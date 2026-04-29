// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "qos: resctrl: " fmt

#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/cbqri.h>
#include <linux/cpu.h>
#include <linux/cpufeature.h>
#include <linux/cpuhotplug.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/numa.h>
#include <linux/resctrl.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "cbqri_internal.h"

static struct cbqri_resctrl_res cbqri_resctrl_resources[RDT_NUM_RESOURCES];

/*
 * cacheinfo populates the cache id <-> cpumask mapping from a
 * device_initcall().  qos_resctrl_setup() runs at late_initcall, which
 * already happens after device_initcall_sync, but follow MPAM's explicit
 * synchronization (mirrors mpam_resctrl.c) so future initcall-order
 * shifts (or a switch to platform-driver style) cannot break us.
 */
static bool cacheinfo_ready;
static DECLARE_WAIT_QUEUE_HEAD(wait_cacheinfo_ready);

static bool exposed_alloc_capable;
static bool exposed_mon_capable;
/* CDP (code data prioritization) on x86 is AT (access type) on RISC-V */
static bool exposed_cdp_l2_capable;
static bool exposed_cdp_l3_capable;
static bool is_cdp_l2_enabled;
static bool is_cdp_l3_enabled;

/* used by resctrl_arch_system_num_rmid_idx(); narrowed by cbqri_probe_controller() */
static u32 max_rmid = U32_MAX;

LIST_HEAD(cbqri_controllers);

static int cbqri_wait_busy_flag(struct cbqri_controller *ctrl, int reg_offset,
				u64 *regp);

/* Set capacity block mask (cc_block_mask) */
static void cbqri_set_cbm(struct cbqri_controller *ctrl, u64 cbm)
{
	iowrite64(cbm, ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
}

static int cbqri_wait_busy_flag(struct cbqri_controller *ctrl, int reg_offset,
				u64 *regp)
{
	u64 reg;
	int ret;

	/*
	 * Sleeping poll: 10us between attempts, 1ms total.  Caller holds
	 * ctrl->lock as a sleeping mutex, so the wait neither pins the
	 * CPU nor disables preemption -- safe under PREEMPT_RT and on
	 * busy multi-CPU systems.
	 */
	ret = readq_poll_timeout(ctrl->base + reg_offset, reg,
				 !FIELD_GET(CBQRI_CONTROL_REGISTERS_BUSY_MASK, reg),
				 10, 1000);
	if (ret) {
		/*
		 * A timeout means the controller did not clear BUSY within
		 * the spec-permitted window.  Mark it faulted so that
		 * subsequent ops fail fast in cbqri_cc_alloc_op() /
		 * cbqri_cc_mon_op() instead of paying the same 1ms each.
		 */
		ctrl->faulted = true;
		return ret;
	}
	/*
	 * Successful poll: clear any prior fault.  Probe-time paths
	 * (cbqri_probe_feature) do not gate on ->faulted, so a transient
	 * early-boot stall (e.g. firmware not yet releasing the controller)
	 * self-heals as soon as the controller next responds.
	 */
	ctrl->faulted = false;
	if (regp)
		*regp = reg;
	return 0;
}

/*
 * Perform capacity allocation control operation on capacity controller.
 * Caller must hold ctrl->lock.
 */
static int cbqri_cc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid,
			     enum resctrl_conf_type type)
{
	int reg_offset = CBQRI_CC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	if (ctrl->faulted)
		return -EIO;

	reg = ioread64(ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout before starting operation\n");
		return -EIO;
	}
	reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_OP_MASK, operation);
	reg &= ~CBQRI_CONTROL_REGISTERS_RCID_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_RCID_MASK, rcid);

	/* Clear AT unconditionally; set it only when CDP is enabled for this level */
	reg &= ~CBQRI_CONTROL_REGISTERS_AT_MASK;

	/* CBQRI capacity AT is only supported on L2 and L3 caches for now */
	if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
	    ((ctrl->cache.cache_level == 2 && is_cdp_l2_enabled) ||
	    (ctrl->cache.cache_level == 3 && is_cdp_l3_enabled))) {
		switch (type) {
		case CDP_CODE:
			reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_AT_MASK,
					  CBQRI_CONTROL_REGISTERS_AT_CODE);
			break;
		case CDP_DATA:
		default:
			reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_AT_MASK,
					  CBQRI_CONTROL_REGISTERS_AT_DATA);
			break;
		}
	}

	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout during operation\n");
		return -EIO;
	}

	status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);
	if (status != CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS) {
		pr_err("operation %d failed: status=%d\n", operation, status);
		return -EIO;
	}

	return 0;
}

/*
 * Write a capacity block mask and verify the hardware accepted it by
 * reading back the value after a CONFIG_LIMIT + READ_LIMIT sequence.
 */
static int cbqri_apply_cache_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				    enum resctrl_conf_type type, struct cbqri_config *cfg)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int err = 0;
	u64 reg;

	mutex_lock(&ctrl->lock);

	/* Set capacity block mask (cc_block_mask) */
	cbqri_set_cbm(ctrl, cfg->cbm);

	/* Capacity config limit operation */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT, closid, type);
	if (err < 0) {
		pr_err("operation failed: err=%d\n", err);
		goto out;
	}

	/* Clear cc_block_mask before read limit to verify op works */
	cbqri_set_cbm(ctrl, 0);

	/* Perform a capacity read limit operation to verify blockmask */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
	if (err < 0) {
		pr_err("operation failed: err=%d\n", err);
		goto out;
	}

	/* Read capacity blockmask to verify it matches the requested config */
	reg = ioread64(ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
	if (reg != cfg->cbm) {
		pr_err("CBM verify mismatch (reg=%llx != cbm=%llx)\n",
		       reg, cfg->cbm);
		err = -EIO;
	}

out:
	mutex_unlock(&ctrl->lock);
	return err;
}

static int cbqri_probe_feature(struct cbqri_controller *ctrl, int reg_offset,
			       int operation, int *status, bool *access_type_supported)
{
	u64 reg, saved_reg;
	int at;

	/* Keep the initial register value to preserve the WPRI fields */
	reg = ioread64(ctrl->base + reg_offset);
	saved_reg = reg;

	/* Execute the requested operation to find if the register is implemented */
	reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_OP_MASK, operation);
	reg &= ~CBQRI_CONTROL_REGISTERS_RCID_MASK;
	iowrite64(reg, ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout during operation\n");
		return -EIO;
	}

	/* Get the operation status */
	*status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);

	/*
	 * Check for the AT support if the register is implemented
	 * (if not, the status value will remain 0)
	 */
	if (*status != 0) {
		/* Set the AT field to a valid value */
		reg = saved_reg;
		reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
		reg &= ~CBQRI_CONTROL_REGISTERS_AT_MASK;
		reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_AT_MASK,
				  CBQRI_CONTROL_REGISTERS_AT_CODE);
		iowrite64(reg, ctrl->base + reg_offset);
		if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
			pr_err("BUSY timeout setting AT field\n");
			return -EIO;
		}

		/*
		 * If the AT field value has been reset to zero,
		 * then the AT support is not present
		 */
		at = FIELD_GET(CBQRI_CONTROL_REGISTERS_AT_MASK, reg);
		if (at == CBQRI_CONTROL_REGISTERS_AT_CODE)
			*access_type_supported = true;
		else
			*access_type_supported = false;
	}

	/* Restore the original register value; clear OP to avoid re-triggering the probe op */
	saved_reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
	iowrite64(saved_reg, ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset, NULL) < 0) {
		pr_err("BUSY timeout restoring register value\n");
		return -EIO;
	}

	return 0;
}

static int cbqri_probe_cc(struct cbqri_controller *ctrl)
{
	bool has_mon_at_code = false;
	int err, status;
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_CC_CAPABILITIES_OFF);
	if (reg == 0)
		return -ENODEV;

	ctrl->ver_minor = FIELD_GET(CBQRI_CC_CAPABILITIES_VER_MINOR_MASK, reg);
	ctrl->ver_major = FIELD_GET(CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK, reg);
	ctrl->cc.ncblks = FIELD_GET(CBQRI_CC_CAPABILITIES_NCBLKS_MASK, reg);

	pr_debug("version=%d.%d ncblks=%d cache_level=%d\n",
		 ctrl->ver_major, ctrl->ver_minor,
		 ctrl->cc.ncblks, ctrl->cache.cache_level);

	/*
	 * NCBLKS == 0 would divide-by-zero in the schemata math while
	 * ctrl->lock is held -- mirror the BC's nbwblks guard.
	 */
	if (!ctrl->cc.ncblks) {
		pr_warn("CC at %pa has 0 capacity blocks, skipping\n",
			&ctrl->addr);
		return -ENODEV;
	}

	/*
	 * resctrl exposes the capacity bit-mask through resctrl_arch_get_config()
	 * as a u32, so a controller advertising more than 32 capacity blocks
	 * cannot be represented without silently truncating the readback CBM.
	 * Reject such hardware at probe rather than misreport state to
	 * userspace.  Real CBQRI hardware to date stays well within this
	 * limit (typical L2/L3 cache way counts), but the spec field is
	 * 16 bits so a defensive ceiling is warranted.
	 */
	if (ctrl->cc.ncblks > 32) {
		pr_warn("CC at %pa has ncblks=%u > 32 (resctrl CBM is u32), skipping\n",
			&ctrl->addr, ctrl->cc.ncblks);
		return -ENODEV;
	}

	/* Probe monitoring features */
	err = cbqri_probe_feature(ctrl, CBQRI_CC_MON_CTL_OFF,
				  CBQRI_CC_MON_CTL_OP_READ_COUNTER, &status,
				  &has_mon_at_code);
	if (err)
		return err;

	if (status == CBQRI_CC_MON_CTL_STATUS_SUCCESS)
		ctrl->mon_capable = true;

	/* Probe allocation features */
	err = cbqri_probe_feature(ctrl, CBQRI_CC_ALLOC_CTL_OFF,
				  CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT,
				  &status, &ctrl->cc.supports_alloc_at_code);
	if (err)
		return err;

	if (status == CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS) {
		ctrl->alloc_capable = true;
		exposed_alloc_capable = true;
	}

	return 0;
}

static int cbqri_probe_controller(struct cbqri_controller *ctrl)
{
	int err;

	pr_debug("controller info: type=%d addr=%pa size=%pa max-rcid=%u max-mcid=%u\n",
		 ctrl->type, &ctrl->addr, &ctrl->size,
		 ctrl->rcid_count, ctrl->mcid_count);

	if (!ctrl->addr) {
		pr_warn("controller has invalid addr=0x0, skipping\n");
		return -EINVAL;
	}

	if (!request_mem_region(ctrl->addr, ctrl->size, "cbqri_controller")) {
		pr_err("request_mem_region failed for %pa\n", &ctrl->addr);
		return -EBUSY;
	}

	ctrl->base = ioremap(ctrl->addr, ctrl->size);
	if (!ctrl->base) {
		pr_err("ioremap failed for %pa\n", &ctrl->addr);
		err = -ENOMEM;
		goto err_release;
	}

	mutex_init(&ctrl->lock);

	switch (ctrl->type) {
	case CBQRI_CONTROLLER_TYPE_CAPACITY:
		err = cbqri_probe_cc(ctrl);
		break;
	default:
		pr_err("unknown controller type %d\n", ctrl->type);
		err = -ENODEV;
		break;
	}

	if (err)
		goto err_iounmap;

	/*
	 * max_rmid is used by resctrl_arch_system_num_rmid_idx()
	 * Find the smallest mcid_count amongst all controllers.
	 */
	max_rmid = min(max_rmid, ctrl->mcid_count);

	return 0;

err_iounmap:
	iounmap(ctrl->base);
	ctrl->base = NULL;
err_release:
	release_mem_region(ctrl->addr, ctrl->size);
	return err;
}

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return exposed_mon_capable;
}

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level rid)
{
	switch (rid) {
	case RDT_RESOURCE_L2:
		return is_cdp_l2_enabled;

	case RDT_RESOURCE_L3:
		return is_cdp_l3_enabled;

	default:
		return false;
	}
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level rid, bool enable)
{
	switch (rid) {
	case RDT_RESOURCE_L2:
		if (!exposed_cdp_l2_capable)
			return -ENODEV;
		is_cdp_l2_enabled = enable;
		break;

	case RDT_RESOURCE_L3:
		if (!exposed_cdp_l3_capable)
			return -ENODEV;
		is_cdp_l3_enabled = enable;
		break;

	default:
		return -ENODEV;
	}

	return 0;
}

struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l)
{
	if (l >= RDT_NUM_RESOURCES)
		return NULL;

	return &cbqri_resctrl_resources[l].resctrl_res;
}

bool resctrl_arch_is_evt_configurable(enum resctrl_event_id evt)
{
	return false;
}

void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r,
				 enum resctrl_event_id evtid)
{
	/* RISC-V can always read an rmid, nothing needs allocating */
	return NULL;
}

void resctrl_arch_mon_ctx_free(struct rdt_resource *r,
			       enum resctrl_event_id evtid, void *arch_mon_ctx)
{
	/* No arch-private monitoring context to free */
}

void resctrl_arch_config_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			      enum resctrl_event_id evtid, u32 rmid, u32 closid,
			      u32 cntr_id, bool assign)
{
	/* MBM counter assignment not supported */
}

int resctrl_arch_cntr_read(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			   u32 unused, u32 rmid, int cntr_id,
			   enum resctrl_event_id eventid, u64 *val)
{
	/* MBM counter assignment not supported */
	return -EOPNOTSUPP;
}

bool resctrl_arch_mbm_cntr_assign_enabled(struct rdt_resource *r)
{
	/* MBM counter assignment not supported */
	return false;
}

int resctrl_arch_mbm_cntr_assign_set(struct rdt_resource *r, bool enable)
{
	/* MBM counter assignment is not supported on CBQRI. */
	return -EOPNOTSUPP;
}

void resctrl_arch_reset_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 unused, u32 rmid, int cntr_id,
			     enum resctrl_event_id eventid)
{
	/* MBM counter assignment not supported */
}

bool resctrl_arch_get_io_alloc_enabled(struct rdt_resource *r)
{
	/* CBQRI does not have I/O-specific allocation */
	return false;
}

int resctrl_arch_io_alloc_enable(struct rdt_resource *r, bool enable)
{
	/* CBQRI does not have I/O-specific allocation */
	return 0;
}

/*
 * Note about terminology between x86 (Intel RDT/AMD QoS) and RISC-V:
 *   CLOSID on x86 is RCID on RISC-V
 *     RMID on x86 is MCID on RISC-V
 */
u32 resctrl_arch_get_num_closid(struct rdt_resource *res)
{
	struct cbqri_resctrl_res *hw_res;

	hw_res = container_of(res, struct cbqri_resctrl_res, resctrl_res);

	/*
	 * fs/resctrl calls this for resctrl-defined rids that CBQRI may not
	 * back (e.g. RDT_RESOURCE_MBA from set_mba_sc() during unmount).
	 * Unpicked rids have ctrl == NULL; report no closids.
	 */
	if (!hw_res->ctrl)
		return 0;

	return hw_res->ctrl->rcid_count;
}

u32 resctrl_arch_system_num_rmid_idx(void)
{
	return max_rmid;
}

u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid)
{
	return rmid;
}

void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid)
{
	*closid = RISCV_RESCTRL_EMPTY_CLOSID;
	*rmid = idx;
}

void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid)
{
	u32 srmcfg = FIELD_PREP(SRMCFG_RCID_MASK, closid) |
		     FIELD_PREP(SRMCFG_MCID_MASK, rmid);

	WRITE_ONCE(per_cpu(cpu_srmcfg_default, cpu), srmcfg);
}

void resctrl_arch_sched_in(struct task_struct *tsk)
{
	__switch_to_srmcfg(tsk);
}

void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 srmcfg = FIELD_PREP(SRMCFG_RCID_MASK, closid) |
		     FIELD_PREP(SRMCFG_MCID_MASK, rmid);

	WRITE_ONCE(tsk->thread.srmcfg, srmcfg);
}

void resctrl_arch_sync_cpu_closid_rmid(void *info)
{
	struct resctrl_cpu_defaults *r = info;

	lockdep_assert_preemption_disabled();

	if (r) {
		resctrl_arch_set_cpu_default_closid_rmid(smp_processor_id(),
							 r->closid, r->rmid);
	}

	resctrl_arch_sched_in(current);
}

bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid)
{
	return FIELD_GET(SRMCFG_RCID_MASK, READ_ONCE(tsk->thread.srmcfg)) == closid;
}

bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	return FIELD_GET(SRMCFG_MCID_MASK, READ_ONCE(tsk->thread.srmcfg)) == rmid;
}

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain_hdr *hdr,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   void *arch_priv, u64 *val, void *arch_mon_ctx)
{
	/* No monitoring events backed in scaffolding; added per-feature later. */
	return -EINVAL;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 closid, u32 rmid, enum resctrl_event_id eventid)
{
	/* No monitoring events backed in scaffolding; added per-feature later. */
}

void resctrl_arch_mon_event_config_read(void *info)
{
	/* Event config not supported */
}

void resctrl_arch_mon_event_config_write(void *info)
{
	/* Event config not supported */
}

void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_l3_mon_domain *d)
{
	/* No monitoring events backed in scaffolding; added per-feature later. */
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	struct cbqri_resctrl_res *hw_res;
	struct rdt_ctrl_domain *d;
	enum resctrl_conf_type t;
	u32 default_ctrl;
	int i;

	lockdep_assert_cpus_held();

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	default_ctrl = resctrl_get_default_ctrl(r);

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
			for (t = 0; t < CDP_NUM_TYPES; t++)
				resctrl_arch_update_one(r, d, i, t,
							default_ctrl);
		}
	}
}

void resctrl_arch_pre_mount(void)
{
	/* All controllers discovered at boot via late_initcall; nothing to do */
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	struct cbqri_resctrl_dom *dom;
	struct cbqri_config cfg;
	int err = 0;

	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	if (!r->alloc_capable)
		return -EINVAL;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		cfg.cbm = cfg_val;
		err = cbqri_apply_cache_config(dom, closid, t, &cfg);
		break;
	default:
		return -EINVAL;
	}

	return err;
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	enum resctrl_conf_type t;
	struct rdt_ctrl_domain *d;
	int err = 0;

	/* Walking r->ctrl_domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &d->staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;
			err = resctrl_arch_update_one(r, d, closid, t, cfg->new_ctrl);
			if (err) {
				pr_err("update failed (err=%d)\n", err);
				return err;
			}
		}
	}
	return err;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	u32 val;
	int err;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	ctrl = hw_dom->hw_ctrl;

	val = resctrl_get_default_ctrl(r);

	if (!r->alloc_capable)
		return val;

	mutex_lock(&ctrl->lock);

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		/* Clear cc_block_mask before read limit operation */
		cbqri_set_cbm(ctrl, 0);

		/* Capacity read limit operation for RCID (closid) */
		err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
		if (err < 0) {
			pr_err("operation failed: err=%d\n", err);
			break;
		}

		/* Read capacity block mask for RCID (closid) */
		val = ioread64(ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
		break;

	default:
		break;
	}

	mutex_unlock(&ctrl->lock);
	return val;
}

static struct rdt_ctrl_domain *qos_new_domain(struct cbqri_controller *ctrl)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct rdt_ctrl_domain *domain;

	hw_dom = kzalloc_obj(*hw_dom, GFP_KERNEL);
	if (!hw_dom)
		return NULL;

	/* associate this cbqri_controller with the domain */
	hw_dom->hw_ctrl = ctrl;

	/* the rdt_domain struct from inside the cbqri_resctrl_dom struct */
	domain = &hw_dom->resctrl_ctrl_dom;

	INIT_LIST_HEAD(&domain->hdr.list);

	return domain;
}

static int qos_init_domain_ctrlval(struct rdt_resource *r, struct rdt_ctrl_domain *d)
{
	struct cbqri_resctrl_res *hw_res;
	int err = 0;
	int i;

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);

	for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
		err = resctrl_arch_update_one(r, d, i, 0,
					      resctrl_get_default_ctrl(r));
		if (err)
			return err;
	}
	return 0;
}

/*
 * Walk cbqri_controllers and pick one capacity controller (CC) per cache
 * level (L2/L3) to back the corresponding RDT_RESOURCE_L*.  When more than
 * one CC sits at the same level (e.g. one per socket), they must agree on
 * rcid_count / ncblks / alloc_capable -- a mismatch is fatal because resctrl
 * exposes a single set of caps per rid.  The first matching controller wins;
 * subsequent matches must be cap-compatible or setup fails.
 *
 * Mirrors mpam_resctrl_pick_caches() in drivers/resctrl/mpam_resctrl.c.
 */
static int cbqri_resctrl_pick_caches(void)
{
	struct cbqri_controller *ctrl;

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		struct cbqri_resctrl_res *cbqri_res;
		enum resctrl_res_level rid;

		if (ctrl->type != CBQRI_CONTROLLER_TYPE_CAPACITY)
			continue;
		/*
		 * Spec allows a CC with mcid_count > 0 and rcid_count == 0
		 * (monitor-only).  Skip alloc-pick for those; their L3
		 * monitoring is still wired up at register time when they
		 * pair with an alloc-capable CC at the same cache_id.
		 */
		if (!ctrl->alloc_capable)
			continue;

		if (ctrl->cache.cache_level == 2) {
			rid = RDT_RESOURCE_L2;
		} else if (ctrl->cache.cache_level == 3) {
			rid = RDT_RESOURCE_L3;
		} else {
			pr_err("unknown cache level %d\n",
			       ctrl->cache.cache_level);
			return -ENODEV;
		}

		cbqri_res = &cbqri_resctrl_resources[rid];
		if (cbqri_res->ctrl) {
			if (cbqri_res->ctrl->rcid_count != ctrl->rcid_count ||
			    cbqri_res->ctrl->cc.ncblks != ctrl->cc.ncblks ||
			    cbqri_res->ctrl->alloc_capable != ctrl->alloc_capable) {
				pr_err("L%d controllers have mismatched capabilities\n",
				       ctrl->cache.cache_level);
				return -EINVAL;
			}
			continue;
		}

		cbqri_res->ctrl = ctrl;
	}

	return 0;
}

/*
 * Fill the rdt_resource fields for one picked rid.  Mirrors
 * mpam_resctrl_control_init() at drivers/resctrl/mpam_resctrl.c.  An rid
 * with no picked controller is left untouched so it stays out of
 * resctrl_arch_get_resource().
 */
static int cbqri_resctrl_control_init(struct cbqri_resctrl_res *cbqri_res)
{
	struct cbqri_controller *ctrl = cbqri_res->ctrl;
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	if (!ctrl)
		return 0;

	res->alloc_capable = ctrl->alloc_capable;

	switch (res->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		res->name = (res->rid == RDT_RESOURCE_L2) ? "L2" : "L3";
		res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
		res->ctrl_scope = (res->rid == RDT_RESOURCE_L2) ?
				    RESCTRL_L2_CACHE : RESCTRL_L3_CACHE;
		res->cache.cbm_len = ctrl->cc.ncblks;
		res->cache.shareable_bits = resctrl_get_default_ctrl(res);
		res->cache.min_cbm_bits = 1;
		break;

	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	return 0;
}

/*
 * Allocate a fresh ctrl_domain, attach it to @ctrl, init its default
 * per-CLOSID values for resource @res, add to res->ctrl_domains, and
 * bring it online. On error, the domain is freed before return.
 */
static int qos_register_ctrl_domain(struct cbqri_controller *ctrl,
				    struct rdt_resource *res,
				    const struct cpumask *cpu_mask, int dom_id,
				    struct rdt_ctrl_domain **out_domain)
{
	struct rdt_ctrl_domain *domain;
	struct list_head *pos = NULL;
	int err;

	domain = qos_new_domain(ctrl);
	if (!domain)
		return -ENOMEM;

	cpumask_copy(&domain->hdr.cpu_mask, cpu_mask);
	domain->hdr.id = dom_id;

	err = qos_init_domain_ctrlval(res, domain);
	if (err)
		goto err_free;

	if (resctrl_find_domain(&res->ctrl_domains, domain->hdr.id, &pos)) {
		pr_err("duplicate domain id %d for resource %s\n",
		       domain->hdr.id, res->name);
		err = -EEXIST;
		goto err_free;
	}
	if (pos)
		list_add_tail(&domain->hdr.list, pos);
	else
		list_add_tail(&domain->hdr.list, &res->ctrl_domains);

	err = resctrl_online_ctrl_domain(res, domain);
	if (err) {
		pr_err("failed to online domain %d\n", domain->hdr.id);
		list_del(&domain->hdr.list);
		goto err_free;
	}

	if (out_domain)
		*out_domain = domain;
	return 0;

err_free:
	kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
	return err;
}

/*
 * Register one rdt_ctrl_domain on the resctrl resource backing @rid for
 * a capacity controller @ctrl.
 */
static int qos_register_cap_controller(struct cbqri_controller *ctrl)
{
	struct cbqri_resctrl_res *cbqri_res;
	struct rdt_resource *res;
	enum resctrl_res_level rid;

	/*
	 * Monitor-only CCs (mcid_count > 0, rcid_count == 0) skip
	 * ctrl_domain registration: the resource was not picked for them
	 * in cbqri_resctrl_pick_caches() so its rdt_resource fields are
	 * not set up, and qos_register_ctrl_domain() would drive
	 * resctrl_arch_update_one() into a !alloc_capable -EINVAL.
	 */
	if (!ctrl->alloc_capable) {
		pr_debug("CC @%pa: monitor-only, skipping register\n",
			 &ctrl->addr);
		return 0;
	}

	switch (ctrl->cache.cache_level) {
	case 2:
		rid = RDT_RESOURCE_L2;
		break;
	case 3:
		rid = RDT_RESOURCE_L3;
		break;
	default:
		pr_err("unknown cache level %d\n", ctrl->cache.cache_level);
		return -ENODEV;
	}

	cbqri_res = &cbqri_resctrl_resources[rid];
	res = &cbqri_res->resctrl_res;

	return qos_register_ctrl_domain(ctrl, res, &ctrl->cache.cpu_mask,
					ctrl->cache.cache_id, NULL);
}

static int qos_resctrl_add_controller_domain(struct cbqri_controller *ctrl)
{
	switch (ctrl->type) {
	case CBQRI_CONTROLLER_TYPE_CAPACITY:
		return qos_register_cap_controller(ctrl);
	default:
		pr_err("unknown controller type %d\n", ctrl->type);
		return -ENODEV;
	}
}

/* Set after resctrl_init() succeeds; gates resctrl_exit() in teardown. */
static bool qos_resctrl_inited;

/*
 * Free every per-resource ctrl_domain and mon_domain registered through
 * qos_resctrl_setup(), then -- if resctrl_init() was reached -- tear
 * down the resctrl FS state, then unmap the MMIO regions claimed by
 * each cbqri_controller in cbqri_probe_controller().  Safe to call
 * partway through setup: each list walk is empty if its corresponding
 * pass never ran, and a controller without ->base is skipped.  Order
 * matters: resctrl_offline_*_domain() must run before resctrl_exit()
 * so the latter does not WARN about online domains, and ioremaps must
 * stay live until both are done.
 */
void qos_resctrl_teardown(void)
{
	struct rdt_ctrl_domain *domain, *domain_temp;
	struct cbqri_resctrl_res *res;
	struct cbqri_controller *ctrl, *tmp;
	enum resctrl_res_level rid;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		res = &cbqri_resctrl_resources[rid];
		list_for_each_entry_safe(domain, domain_temp, &res->resctrl_res.ctrl_domains,
					 hdr.list) {
			resctrl_offline_ctrl_domain(&res->resctrl_res, domain);
			list_del(&domain->hdr.list);
			kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
		}
	}

	if (qos_resctrl_inited) {
		resctrl_exit();
		qos_resctrl_inited = false;
	}

	list_for_each_entry_safe(ctrl, tmp, &cbqri_controllers, list) {
		if (ctrl->base) {
			iounmap(ctrl->base);
			ctrl->base = NULL;
			release_mem_region(ctrl->addr, ctrl->size);
		}
		list_del(&ctrl->list);
		cbqri_controller_destroy(ctrl);
	}
}

int qos_resctrl_setup(void)
{
	struct cbqri_controller *ctrl;
	struct cbqri_resctrl_res *res;
	enum resctrl_res_level rid;
	int err = 0;

	wait_event(wait_cacheinfo_ready, cacheinfo_ready);

	max_rmid = U32_MAX;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		res = &cbqri_resctrl_resources[rid];
		INIT_LIST_HEAD(&res->resctrl_res.ctrl_domains);
		INIT_LIST_HEAD(&res->resctrl_res.mon_domains);
		res->resctrl_res.rid = rid;
	}

	/*
	 * Phase 1: probe every controller.
	 */
	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		err = cbqri_probe_controller(ctrl);
		if (err) {
			pr_err("probe failed (%d)\n", err);
			goto err_free_controllers_list;
		}
	}

	/*
	 * Clamp the U32_MAX sentinel: if no probed controller narrowed
	 * max_rmid (no controllers, or all have mcid_count == 0), no
	 * monitoring is possible.  Leaving the sentinel in place would let
	 * resctrl_arch_system_num_rmid_idx() return ~0 and any later
	 * kcalloc(idx_limit, ...) overflow.
	 */
	if (max_rmid == U32_MAX)
		max_rmid = 0;

	/*
	 * Phase 2: pick which controller backs each rid.  Mismatched caps
	 * across controllers at the same rid are a fatal configuration
	 * error -- resctrl exposes one set of caps per rid.
	 */
	err = cbqri_resctrl_pick_caches();
	if (err)
		goto err_free_controllers_list;

	/*
	 * Phase 3: init each picked rid as an rdt_resource.  An rid with no
	 * picked controller is left in its zero-init state and skipped.
	 */
	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		res = &cbqri_resctrl_resources[rid];
		err = cbqri_resctrl_control_init(res);
		if (err) {
			pr_err("control_init failed for rid %d (%d)\n", rid, err);
			goto err_free_controllers_list;
		}
	}

	/*
	 * Phase 4: register one rdt_ctrl_domain per controller.  Domain
	 * registration runs on the rdt_resource whose fields were populated
	 * in phase 3.
	 */
	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		err = qos_resctrl_add_controller_domain(ctrl);
		if (err) {
			pr_err("failed to add controller domain (%d)\n", err);
			goto err_free_controllers_list;
		}

		/*
		 * CDP (code data prioritization) on x86 is similar to
		 * the AT (access type) field in CBQRI. CDP only supports
		 * caches so this must be a CBQRI capacity controller.
		 */
		if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
		    ctrl->cc.supports_alloc_at_code) {
			if (ctrl->cache.cache_level == 2)
				exposed_cdp_l2_capable = true;
			else
				exposed_cdp_l3_capable = true;
		}
	}
	pr_debug("alloc=%d cdp_l2=%d cdp_l3=%d\n",
		 exposed_alloc_capable,
		 exposed_cdp_l2_capable, exposed_cdp_l3_capable);

	err = resctrl_init();
	if (err)
		goto err_free_controllers_list;
	qos_resctrl_inited = true;

	return 0;

err_free_controllers_list:
	qos_resctrl_teardown();
	return err;
}

/* Protects domain->hdr.cpu_mask mutations (mirrors x86 domain_list_lock). */
static DEFINE_MUTEX(qos_domain_list_lock);

/*
 * Update domain->hdr.cpu_mask to reflect the online subset of the
 * controller's PPTT/RQSC mask (mirrors x86 domain_add/remove_cpu).
 * Empty domains are not unregistered (matches MPAM).
 * Caller must hold qos_domain_list_lock.
 */
static void qos_domain_update_cpu(unsigned int cpu, bool online)
{
	struct cbqri_resctrl_res *cr;
	struct cbqri_resctrl_dom *hw_dom;
	struct rdt_ctrl_domain *cdom;
	enum resctrl_res_level rid;

	lockdep_assert_held(&qos_domain_list_lock);

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		cr = &cbqri_resctrl_resources[rid];
		list_for_each_entry(cdom, &cr->resctrl_res.ctrl_domains, hdr.list) {
			const struct cpumask *src;

			hw_dom = container_of(cdom, struct cbqri_resctrl_dom,
					      resctrl_ctrl_dom);
			if (!hw_dom->hw_ctrl)
				continue;
			if (hw_dom->hw_ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY)
				src = &hw_dom->hw_ctrl->cache.cpu_mask;
			else
				src = &hw_dom->hw_ctrl->mem.cpu_mask;
			if (!cpumask_test_cpu(cpu, src))
				continue;
			if (online)
				cpumask_set_cpu(cpu, &cdom->hdr.cpu_mask);
			else
				cpumask_clear_cpu(cpu, &cdom->hdr.cpu_mask);
		}
	}
}

int qos_resctrl_online_cpu(unsigned int cpu)
{
	/*
	 * Hardware resets CSR_SRMCFG to 0 when a CPU is offlined/re-onlined.
	 * Zero the cached value so the next context switch always re-programs
	 * the CSR rather than skipping it as "unchanged".
	 */
	per_cpu(cpu_srmcfg, cpu) = 0;
	mutex_lock(&qos_domain_list_lock);
	qos_domain_update_cpu(cpu, true);
	mutex_unlock(&qos_domain_list_lock);
	resctrl_online_cpu(cpu);
	return 0;
}

int qos_resctrl_offline_cpu(unsigned int cpu)
{
	/*
	 * Clear the departing CPU from each domain's cpu_mask BEFORE
	 * resctrl_offline_cpu() runs.  resctrl_offline_cpu() calls
	 * get_mon_domain_from_cpu() and mbm_setup_overflow_handler()
	 * to migrate pending MBM work off the leaving CPU; if the bit
	 * is still set, those helpers may pick the very CPU being torn
	 * down to host the next overflow tick.  This also makes the
	 * online/offline ordering symmetric with qos_resctrl_online_cpu(),
	 * which sets the bit before the resctrl call.
	 */
	mutex_lock(&qos_domain_list_lock);
	qos_domain_update_cpu(cpu, false);
	mutex_unlock(&qos_domain_list_lock);
	resctrl_offline_cpu(cpu);
	return 0;
}

static int __init __cacheinfo_ready(void)
{
	cacheinfo_ready = true;
	wake_up(&wait_cacheinfo_ready);
	return 0;
}
device_initcall_sync(__cacheinfo_ready);

void cbqri_controller_destroy(struct cbqri_controller *ctrl)
{
	kfree(ctrl);
}

/*
 * Allocate, populate, and add to cbqri_controllers a fresh controller
 * descriptor based on @info supplied by a discovery layer (ACPI RQSC,
 * future DT).  Resolves the cpumask via PPTT (capacity) or NUMA proximity
 * domain (bandwidth) so callers don't need to know about cacheinfo / NUMA
 * topology.
 */
int riscv_cbqri_register_controller(const struct cbqri_controller_info *info)
{
	struct cbqri_controller *ctrl;

	if (!info->addr) {
		pr_warn("skipping controller with invalid addr=0x0\n");
		return -EINVAL;
	}

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	ctrl->addr = info->addr;
	ctrl->size = info->size;
	ctrl->type = info->type;
	ctrl->rcid_count = info->rcid_count;
	ctrl->mcid_count = info->mcid_count;

	switch (info->type) {
	case CBQRI_CONTROLLER_TYPE_CAPACITY: {
		int err;

		ctrl->cache.cache_id = info->cache_id;
		ctrl->cache.cache_level =
			find_acpi_cache_level_from_id(info->cache_id);

		if (acpi_pptt_get_cache_size_from_id(info->cache_id,
						     &ctrl->cache.cache_size)) {
			pr_warn("failed to determine size for cache id 0x%x\n",
				info->cache_id);
			ctrl->cache.cache_size = 0;
		}

		err = acpi_pptt_get_cpumask_from_cache_id(info->cache_id,
							  &ctrl->cache.cpu_mask);
		if (err) {
			pr_warn("Failed to get cpumask for cache id 0x%x (%d), skipping\n",
				info->cache_id, err);
			cbqri_controller_destroy(ctrl);
			return err;
		}
		break;
	}
	case CBQRI_CONTROLLER_TYPE_BANDWIDTH: {
		int node_id;

		ctrl->mem.prox_dom = info->prox_dom;
		node_id = pxm_to_node(info->prox_dom);
		if (node_id == NUMA_NO_NODE) {
			pr_warn("controller at %pa: proximity domain %u has no NUMA node, skipping\n",
				&ctrl->addr, info->prox_dom);
			cbqri_controller_destroy(ctrl);
			return -ENODEV;
		}
		cpumask_copy(&ctrl->mem.cpu_mask, cpumask_of_node(node_id));
		break;
	}
	default:
		pr_warn("controller at %pa: unknown type %u, skipping\n",
			&ctrl->addr, info->type);
		cbqri_controller_destroy(ctrl);
		return -EINVAL;
	}

	list_add_tail(&ctrl->list, &cbqri_controllers);
	return 0;
}

/* Saved cpuhp slot from cpuhp_setup_state() for symmetric removal. */
static enum cpuhp_state qos_cpuhp_state;

static int __init qos_arch_late_init(void)
{
	int err;

	if (!riscv_isa_extension_available(NULL, SSQOSID))
		return -ENODEV;

	/*
	 * qos_resctrl_setup() is responsible for its own cleanup on any
	 * failure path -- including the resctrl_init() that happens
	 * inside it -- via qos_resctrl_teardown().  Don't call
	 * resctrl_exit() here: it might run before resctrl_init() did.
	 */
	err = qos_resctrl_setup();
	if (err)
		return err;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "qos:online",
				qos_resctrl_online_cpu,
				qos_resctrl_offline_cpu);
	if (err < 0) {
		qos_resctrl_teardown();
		return err;
	}
	qos_cpuhp_state = err;

	return 0;
}
late_initcall(qos_arch_late_init);
