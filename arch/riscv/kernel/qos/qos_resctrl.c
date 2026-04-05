// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "qos: resctrl: " fmt

#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/resctrl.h>
#include <linux/riscv_qos.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/csr.h>
#include <asm/qos.h>
#include "internal.h"

static struct cbqri_resctrl_res cbqri_resctrl_resources[RDT_NUM_RESOURCES];

static bool exposed_alloc_capable;
static bool exposed_mon_capable;
/* CDP (code data prioritization) on x86 is AT (access type) on RISC-V */
static bool exposed_cdp_l2_capable;
static bool exposed_cdp_l3_capable;
static bool is_cdp_l2_enabled;
static bool is_cdp_l3_enabled;

/* used by resctrl_arch_system_num_rmid_idx() */
static u32 max_rmid;

LIST_HEAD(cbqri_controllers);

static int cbqri_wait_busy_flag(struct cbqri_controller *ctrl, int reg_offset);

/* Set capacity block mask (cc_block_mask) */
static void cbqri_set_cbm(struct cbqri_controller *ctrl, u64 cbm)
{
	int reg_offset;

	reg_offset = CBQRI_CC_BLOCK_MASK_OFF;
	iowrite64(cbm, ctrl->base + reg_offset);
}

/* Set the Rbwb (reserved bandwidth blocks) field in bc_bw_alloc */
static void cbqri_set_rbwb(struct cbqri_controller *ctrl, u64 rbwb)
{
	int reg_offset;
	u64 reg;

	reg_offset = CBQRI_BC_BW_ALLOC_OFF;
	reg = ioread64(ctrl->base + reg_offset);
	reg &= ~CBQRI_CONTROL_REGISTERS_RBWB_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_RBWB_MASK, rbwb);
	iowrite64(reg, ctrl->base + reg_offset);
}

/* Get the Rbwb (reserved bandwidth blocks) field in bc_bw_alloc */
static u64 cbqri_get_rbwb(struct cbqri_controller *ctrl)
{
	int reg_offset;
	u64 reg;

	reg_offset = CBQRI_BC_BW_ALLOC_OFF;
	reg = ioread64(ctrl->base + reg_offset);
	return FIELD_GET(CBQRI_CONTROL_REGISTERS_RBWB_MASK, reg);
}

static int cbqri_wait_busy_flag(struct cbqri_controller *ctrl, int reg_offset)
{
	u64 reg;
	int ret;

	ret = readq_poll_timeout_atomic(ctrl->base + reg_offset, reg,
					!FIELD_GET(CBQRI_CONTROL_REGISTERS_BUSY_MASK, reg),
					0, 1000);
	if (ret)
		pr_err("%s(): busy timeout\n", __func__);

	return ret;
}

/* Perform capacity allocation control operation on capacity controller */
static int cbqri_cc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid,
			     enum resctrl_conf_type type)
{
	int reg_offset = CBQRI_CC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	reg = ioread64(ctrl->base + reg_offset);
	reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_OP_MASK, operation);
	reg &= ~CBQRI_CONTROL_REGISTERS_RCID_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_RCID_MASK, rcid);

	/* CBQRI capacity AT is only supported on L2 and L3 caches for now */
	if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
	    ((ctrl->cache.cache_level == 2 && is_cdp_l2_enabled) ||
	    (ctrl->cache.cache_level == 3 && is_cdp_l3_enabled))) {
		reg &= ~CBQRI_CONTROL_REGISTERS_AT_MASK;
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

	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation", __func__);
		return -EIO;
	}

	reg = ioread64(ctrl->base + reg_offset);
	status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);
	if (status != CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS) {
		pr_err("%s(): operation %d failed: status=%d", __func__, operation, status);
		return -EIO;
	}

	return 0;
}

static int cbqri_apply_cache_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				    enum resctrl_conf_type type, struct cbqri_config *cfg)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int reg_offset;
	int err = 0;
	u64 reg;

	spin_lock(&ctrl->lock);

	/* Set capacity block mask (cc_block_mask) */
	cbqri_set_cbm(ctrl, cfg->cbm);

	/* Capacity config limit operation */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT, closid, type);
	if (err < 0) {
		pr_err("%s(): operation failed: err = %d", __func__, err);
		goto out;
	}

	/* Clear cc_block_mask before read limit to verify op works */
	cbqri_set_cbm(ctrl, 0);

	/* Perform a capacity read limit operation to verify blockmask */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
	if (err < 0) {
		pr_err("%s(): operation failed: err = %d", __func__, err);
		goto out;
	}

	/* Read capacity blockmask to verify it matches the requested config */
	reg_offset = CBQRI_CC_BLOCK_MASK_OFF;
	reg = ioread64(ctrl->base + reg_offset);
	if (reg != cfg->cbm) {
		pr_err("%s(): failed to verify allocation (reg:%llx != cbm:%llx)",
			__func__, reg, cfg->cbm);
		err = -EIO;
	}

out:
	spin_unlock(&ctrl->lock);
	return err;
}

/* Perform bandwidth allocation control operation on bandwidth controller */
static int cbqri_bc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid)
{
	int reg_offset = CBQRI_BC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	reg = ioread64(ctrl->base + reg_offset);
	reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_OP_MASK, operation);
	reg &= ~CBQRI_CONTROL_REGISTERS_RCID_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_RCID_MASK, rcid);
	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation", __func__);
		return -EIO;
	}

	reg = ioread64(ctrl->base + reg_offset);
	status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);
	if (status != CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS) {
		pr_err("%s(): operation %d failed with status = %d",
		       __func__, operation, status);
		return -EIO;
	}

	return 0;
}

static int cbqri_apply_bw_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				 enum resctrl_conf_type type, struct cbqri_config *cfg)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int ret = 0;
	u64 reg;

	spin_lock(&ctrl->lock);

	/* Set reserved bandwidth blocks */
	cbqri_set_rbwb(ctrl, cfg->rbwb);

	/* Bandwidth config limit operation */
	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_CONFIG_LIMIT, closid);
	if (ret < 0) {
		pr_err("%s(): operation failed: ret = %d", __func__, ret);
		goto out;
	}

	/* Clear rbwb before read limit to verify op works */
	cbqri_set_rbwb(ctrl, 0);

	/* Bandwidth allocation read limit operation to verify */
	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
	if (ret < 0)
		goto out;

	/* Read bandwidth allocation to verify it matches the requested config */
	reg = cbqri_get_rbwb(ctrl);
	if (reg != cfg->rbwb) {
		pr_err("%s(): failed to verify allocation (reg:%llx != rbwb:%llu)",
			__func__, reg, cfg->rbwb);
		ret = -EIO;
	}

out:
	spin_unlock(&ctrl->lock);
	return ret;
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
	iowrite64(reg, ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation", __func__);
		return -EIO;
	}

	/* Get the operation status */
	reg = ioread64(ctrl->base + reg_offset);
	*status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);

	/*
	 * Check for the AT support if the register is implemented
	 * (if not, the status value will remain 0)
	 */
	if (*status != 0) {
		/* Set the AT field to a valid value */
		reg = saved_reg;
		reg &= ~CBQRI_CONTROL_REGISTERS_AT_MASK;
		reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_AT_MASK,
				  CBQRI_CONTROL_REGISTERS_AT_CODE);
		iowrite64(reg, ctrl->base + reg_offset);
		if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
			pr_err("%s(): BUSY timeout when setting AT field", __func__);
			return -EIO;
		}

		/*
		 * If the AT field value has been reset to zero,
		 * then the AT support is not present
		 */
		reg = ioread64(ctrl->base + reg_offset);
		at = FIELD_GET(CBQRI_CONTROL_REGISTERS_AT_MASK, reg);
		if (at == CBQRI_CONTROL_REGISTERS_AT_CODE)
			*access_type_supported = true;
		else
			*access_type_supported = false;
	}

	/* Restore the original register value */
	iowrite64(saved_reg, ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when restoring the original register value", __func__);
		return -EIO;
	}

	return 0;
}

static int cbqri_probe_cc(struct cbqri_controller *ctrl)
{
	int err, status;
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_CC_CAPABILITIES_OFF);
	if (reg == 0)
		return -ENODEV;

	ctrl->ver_minor = FIELD_GET(CBQRI_CC_CAPABILITIES_VER_MINOR_MASK, reg);
	ctrl->ver_major = FIELD_GET(CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK, reg);
	ctrl->cc.supports_alloc_op_flush_rcid =
		FIELD_GET(CBQRI_CC_CAPABILITIES_FRCID_MASK, reg);
	ctrl->cc.ncblks = FIELD_GET(CBQRI_CC_CAPABILITIES_NCBLKS_MASK, reg);
	ctrl->cc.blk_size = ctrl->cache.cache_size / ctrl->cc.ncblks;

	pr_debug("version=%d.%d ncblks=%d blk_size=%d cache_level=%d",
		ctrl->ver_major, ctrl->ver_minor,
		ctrl->cc.ncblks, ctrl->cc.blk_size, ctrl->cache.cache_level);

	/* Probe monitoring features */
	err = cbqri_probe_feature(ctrl, CBQRI_CC_MON_CTL_OFF,
				  CBQRI_CC_MON_CTL_OP_READ_COUNTER, &status,
				  &ctrl->cc.supports_mon_at_code);
	if (err)
		return err;

	if (status == CBQRI_CC_MON_CTL_STATUS_SUCCESS) {
		ctrl->cc.supports_mon_op_config_event = true;
		ctrl->cc.supports_mon_op_read_counter = true;
		ctrl->mon_capable = true;
		exposed_mon_capable = true;
	}

	/*
	 * AT data is "always" supported as it has the same value
	 * as when the AT field is not supported.
	 */
	ctrl->cc.supports_mon_at_data = true;

	/* Probe allocation features */
	err = cbqri_probe_feature(ctrl, CBQRI_CC_ALLOC_CTL_OFF,
				  CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT,
				  &status, &ctrl->cc.supports_alloc_at_code);
	if (err)
		return err;

	if (status == CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS) {
		ctrl->cc.supports_alloc_op_config_limit = true;
		ctrl->cc.supports_alloc_op_read_limit = true;
		ctrl->alloc_capable = true;
		exposed_alloc_capable = true;
	}

	/*
	 * AT data is "always" supported as it has the same value
	 * as when the AT field is not supported.
	 */
	ctrl->cc.supports_alloc_at_data = true;

	return 0;
}

static int cbqri_probe_bc(struct cbqri_controller *ctrl)
{
	int err, status;
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_BC_CAPABILITIES_OFF);
	if (reg == 0)
		return -ENODEV;

	ctrl->ver_minor = FIELD_GET(CBQRI_BC_CAPABILITIES_VER_MINOR_MASK, reg);
	ctrl->ver_major = FIELD_GET(CBQRI_BC_CAPABILITIES_VER_MAJOR_MASK, reg);
	ctrl->bc.nbwblks = FIELD_GET(CBQRI_BC_CAPABILITIES_NBWBLKS_MASK, reg);
	ctrl->bc.mrbwb = FIELD_GET(CBQRI_BC_CAPABILITIES_MRBWB_MASK, reg);

	pr_debug("version=%d.%d nbwblks=%d mrbwb=%d",
		ctrl->ver_major, ctrl->ver_minor,
		ctrl->bc.nbwblks, ctrl->bc.mrbwb);

	/* Probe monitoring features */
	err = cbqri_probe_feature(ctrl, CBQRI_BC_MON_CTL_OFF,
				  CBQRI_BC_MON_CTL_OP_READ_COUNTER,
				  &status, &ctrl->bc.supports_mon_at_code);
	if (err)
		return err;

	if (status == CBQRI_BC_MON_CTL_STATUS_SUCCESS) {
		ctrl->bc.supports_mon_op_config_event = true;
		ctrl->bc.supports_mon_op_read_counter = true;
		ctrl->mon_capable = true;
		exposed_mon_capable = true;
	}

	/*
	 * AT data is "always" supported as it has the same value
	 * as when the AT field is not supported.
	 */
	ctrl->bc.supports_mon_at_data = true;

	/* Probe allocation features */
	err = cbqri_probe_feature(ctrl, CBQRI_BC_ALLOC_CTL_OFF,
				  CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT,
				  &status, &ctrl->bc.supports_alloc_at_code);
	if (err)
		return err;

	if (status == CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS) {
		ctrl->bc.supports_alloc_op_config_limit = true;
		ctrl->bc.supports_alloc_op_read_limit = true;
		ctrl->alloc_capable = true;
		exposed_alloc_capable = true;
	}

	/*
	 * AT data is "always" supported as it has the same value
	 * as when the AT field is not supported.
	 */
	ctrl->bc.supports_alloc_at_data = true;

	return 0;
}

static int cbqri_probe_controller(struct cbqri_controller *ctrl)
{
	int err;

	pr_debug("controller info: type=%d addr=%pa size=%pa max-rcid=%u max-mcid=%u",
		ctrl->type, &ctrl->addr, &ctrl->size,
		ctrl->rcid_count, ctrl->mcid_count);

	/*
	 * max_rmid is used by resctrl_arch_system_num_rmid_idx()
	 * Find the smallest mcid_count amongst all controllers.
	 */
	if (max_rmid == 0)
		max_rmid = ctrl->mcid_count;
	else if (ctrl->mcid_count < max_rmid)
		max_rmid = ctrl->mcid_count;

	if (!ctrl->addr) {
		pr_err("%s(): controller has invalid addr=0x0, skipping\n", __func__);
		return -EINVAL;
	}

	if (!request_mem_region(ctrl->addr, ctrl->size, "cbqri_controller")) {
		pr_err("%s(): request_mem_region failed for %pa\n",
			__func__, &ctrl->addr);
		return -EBUSY;
	}

	ctrl->base = ioremap(ctrl->addr, ctrl->size);
	if (!ctrl->base) {
		pr_err("%s(): ioremap failed for %pa\n", __func__, &ctrl->addr);
		err = -ENOMEM;
		goto err_release;
	}

	spin_lock_init(&ctrl->lock);

	switch (ctrl->type) {
	case CBQRI_CONTROLLER_TYPE_CAPACITY:
		err = cbqri_probe_cc(ctrl);
		break;
	case CBQRI_CONTROLLER_TYPE_BANDWIDTH:
		err = cbqri_probe_bc(ctrl);
		break;
	default:
		pr_err("unknown controller type %d\n", ctrl->type);
		err = -ENODEV;
		break;
	}

	if (err)
		goto err_iounmap;

	return 0;

err_iounmap:
	iounmap(ctrl->base);
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
	/* not implemented for the RISC-V resctrl interface */
}

void resctrl_arch_config_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			      enum resctrl_event_id evtid, u32 rmid, u32 closid,
			      u32 cntr_id, bool assign)
{
	/* not implemented for the RISC-V resctrl implementation */
}

int resctrl_arch_cntr_read(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			   u32 unused, u32 rmid, int cntr_id,
			   enum resctrl_event_id eventid, u64 *val)
{
	/* not implemented for the RISC-V resctrl implementation */
	return 0;
}

bool resctrl_arch_mbm_cntr_assign_enabled(struct rdt_resource *r)
{
	/* not implemented for the RISC-V resctrl implementation */
	return false;
}

int resctrl_arch_mbm_cntr_assign_set(struct rdt_resource *r, bool enable)
{
	/* not implemented for the RISC-V resctrl implementation */
	return 0;
}

void resctrl_arch_reset_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 unused, u32 rmid, int cntr_id,
			     enum resctrl_event_id eventid)
{
	/* not implemented for the RISC-V resctrl implementation */
}

bool resctrl_arch_get_io_alloc_enabled(struct rdt_resource *r)
{
	/* not implemented for the RISC-V resctrl implementation */
	return false;
}

int resctrl_arch_io_alloc_enable(struct rdt_resource *r, bool enable)
{
	/* not implemented for the RISC-V resctrl implementation */
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

	return hw_res->max_rcid;
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
	u32 srmcfg;

	srmcfg = rmid << SRMCFG_MCID_SHIFT;
	srmcfg |= closid;
	WRITE_ONCE(per_cpu(cpu_srmcfg_default, cpu), srmcfg);
}

void resctrl_arch_sched_in(struct task_struct *tsk)
{
	__switch_to_srmcfg(tsk);
}

void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 srmcfg;

	WARN_ON_ONCE((closid & SRMCFG_RCID_MASK) != closid);
	WARN_ON_ONCE((rmid & SRMCFG_MCID_MASK) != rmid);

	srmcfg = rmid << SRMCFG_MCID_SHIFT;
	srmcfg |= closid;
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
	u32 srmcfg;
	bool match;

	srmcfg = READ_ONCE(tsk->thread.srmcfg);
	match = (srmcfg & SRMCFG_RCID_MASK) == closid;
	return match;
}

bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 tsk_rmid;

	tsk_rmid = READ_ONCE(tsk->thread.srmcfg);
	tsk_rmid >>= SRMCFG_MCID_SHIFT;
	tsk_rmid &= SRMCFG_MCID_MASK;

	return tsk_rmid == rmid;
}

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain_hdr *hdr,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   void *arch_priv, u64 *val, void *arch_mon_ctx)
{
	/*
	 * Cache occupancy and bandwidth monitoring are not yet implemented
	 * for RISC-V CBQRI. This will be added in a future series once the
	 * resctrl framework supports monitoring domains at non-L3 scopes.
	 */
	return 0;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 closid, u32 rmid, enum resctrl_event_id eventid)
{
	/* not implemented for the RISC-V resctrl interface */
}

void resctrl_arch_mon_event_config_read(void *info)
{
	/* not implemented for the RISC-V resctrl interface */
}

void resctrl_arch_mon_event_config_write(void *info)
{
	/* not implemented for the RISC-V resctrl interface */
}

void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_l3_mon_domain *d)
{
	/* not implemented for the RISC-V resctrl implementation */
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	/* not implemented for the RISC-V resctrl implementation */
}

void resctrl_arch_pre_mount(void)
{
	/* not implemented for the RISC-V resctrl implementation */
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	struct cbqri_controller *ctrl;
	struct cbqri_resctrl_dom *dom;
	struct cbqri_config cfg;
	int err = 0;

	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	ctrl = dom->hw_ctrl;

	if (!r->alloc_capable)
		return -EINVAL;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		cfg.cbm = cfg_val;
		err = cbqri_apply_cache_config(dom, closid, t, &cfg);
		break;
	case RDT_RESOURCE_MBA:
		/* convert from percentage to bandwidth blocks */
		cfg.rbwb = cfg_val * ctrl->bc.nbwblks / 100;
		err = cbqri_apply_bw_config(dom, closid, t, &cfg);
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

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &d->staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;
			err = resctrl_arch_update_one(r, d, closid, t, cfg->new_ctrl);
			if (err) {
				pr_err("%s(): update failed (err=%d)", __func__, err);
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
	int reg_offset;
	u32 percent;
	u32 rbwb;
	u64 reg;
	int err;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	ctrl = hw_dom->hw_ctrl;

	if (!r->alloc_capable)
		return resctrl_get_default_ctrl(r);

	val = resctrl_get_default_ctrl(r);

	spin_lock(&ctrl->lock);

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		/* Clear cc_block_mask before read limit operation */
		cbqri_set_cbm(ctrl, 0);

		/* Capacity read limit operation for RCID (closid) */
		err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d", __func__, err);
			break;
		}

		/* Read capacity block mask for RCID (closid) */
		reg_offset = CBQRI_CC_BLOCK_MASK_OFF;
		reg = ioread64(ctrl->base + reg_offset);
		val = reg;
		break;

	case RDT_RESOURCE_MBA:
		/* Bandwidth read limit operation for RCID (closid) */
		err = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d", __func__, err);
			break;
		}

		rbwb = cbqri_get_rbwb(ctrl);
		rbwb *= 100;
		percent = rbwb / ctrl->bc.nbwblks;
		if (rbwb % ctrl->bc.nbwblks)
			percent++;
		val = percent;
		break;

	default:
		break;
	}

	spin_unlock(&ctrl->lock);
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

	for (i = 0; i < hw_res->max_rcid; i++) {
		err = resctrl_arch_update_one(r, d, i, 0, resctrl_get_default_ctrl(r));
		if (err)
			return err;
	}
	return 0;
}

static void qos_init_cache_resource(struct cbqri_controller *ctrl,
				    struct cbqri_resctrl_res *cbqri_res,
				    enum resctrl_res_level rid, char *name,
				    enum resctrl_scope scope)
{
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	cbqri_res->max_rcid = ctrl->rcid_count;
	cbqri_res->max_mcid = ctrl->mcid_count;
	res->mon.num_rmid = ctrl->mcid_count;
	res->rid = rid;
	res->name = name;
	res->alloc_capable = ctrl->alloc_capable;
	res->mon_capable = ctrl->mon_capable;
	res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
	res->ctrl_scope = scope;
	res->cache.cbm_len = ctrl->cc.ncblks;
	res->cache.shareable_bits = resctrl_get_default_ctrl(res);
	res->cache.min_cbm_bits = 1;
}

static void qos_init_membw_resource(struct cbqri_controller *ctrl,
				     struct cbqri_resctrl_res *cbqri_res)
{
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	cbqri_res->max_rcid = ctrl->rcid_count;
	cbqri_res->max_mcid = ctrl->mcid_count;
	res->mon.num_rmid = ctrl->mcid_count;
	res->rid = RDT_RESOURCE_MBA;
	res->name = "MB";
	res->alloc_capable = ctrl->alloc_capable;
	res->schema_fmt = RESCTRL_SCHEMA_RANGE;
	res->ctrl_scope = RESCTRL_L3_CACHE;
	res->membw.delay_linear = true;
	res->membw.arch_needs_linear = true;
	res->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
	res->membw.min_bw = 1;
	res->membw.max_bw = 80;
	res->membw.bw_gran = 1;
}

static int qos_resctrl_add_controller_domain(struct cbqri_controller *ctrl)
{
	struct rdt_ctrl_domain *domain;
	struct cbqri_resctrl_res *cbqri_res = NULL;
	struct rdt_resource *res = NULL;
	struct list_head *pos = NULL;
	int err;

	domain = qos_new_domain(ctrl);
	if (!domain)
		return -ENOSPC;

	switch (ctrl->type) {
	case CBQRI_CONTROLLER_TYPE_CAPACITY:
		cpumask_copy(&domain->hdr.cpu_mask, &ctrl->cache.cpu_mask);
		domain->hdr.id = ctrl->cache.cache_id;

		if (ctrl->cache.cache_level == 2) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_L2];
			qos_init_cache_resource(ctrl, cbqri_res, RDT_RESOURCE_L2,
						"L2", RESCTRL_L2_CACHE);
		} else if (ctrl->cache.cache_level == 3) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_L3];
			qos_init_cache_resource(ctrl, cbqri_res, RDT_RESOURCE_L3,
						"L3", RESCTRL_L3_CACHE);
		} else {
			pr_err("unknown cache level %d\n", ctrl->cache.cache_level);
			err = -ENODEV;
			goto err_free_domain;
		}
		res = &cbqri_res->resctrl_res;
		break;

	case CBQRI_CONTROLLER_TYPE_BANDWIDTH:
		domain->hdr.id = ctrl->mem.prox_dom;
		if (ctrl->alloc_capable) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_MBA];
			qos_init_membw_resource(ctrl, cbqri_res);
			res = &cbqri_res->resctrl_res;
		}
		break;

	default:
		pr_err("unknown controller type %d\n", ctrl->type);
		err = -ENODEV;
		goto err_free_domain;
	}

	if (!res)
		goto out;

	err = qos_init_domain_ctrlval(res, domain);
	if (err)
		goto err_free_domain;

	resctrl_find_domain(&res->ctrl_domains, domain->hdr.id, &pos);
	if (pos)
		list_add_tail(&domain->hdr.list, pos);
	else
		list_add_tail(&domain->hdr.list, &res->ctrl_domains);

	err = resctrl_online_ctrl_domain(res, domain);
	if (err) {
		pr_err("failed to online domain %d\n", domain->hdr.id);
		goto err_free_domain;
	}

out:
	return 0;

err_free_domain:
	kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
	return err;
}

int qos_resctrl_setup(void)
{
	struct rdt_ctrl_domain *domain, *domain_temp;
	struct cbqri_controller *ctrl;
	struct cbqri_resctrl_res *res;
	int err = 0;
	int i = 0;

	max_rmid = 0;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &cbqri_resctrl_resources[i];
		INIT_LIST_HEAD(&res->resctrl_res.ctrl_domains);
		INIT_LIST_HEAD(&res->resctrl_res.mon_domains);
		res->resctrl_res.rid = i;
	}

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		err = cbqri_probe_controller(ctrl);
		if (err) {
			pr_err("%s(): failed (%d)", __func__, err);
			goto err_unmap_controllers;
		}

		err = qos_resctrl_add_controller_domain(ctrl);
		if (err) {
			pr_err("%s(): failed to add controller domain (%d)", __func__, err);
			goto err_free_controllers_list;
		}

		/*
		 * CDP (code data prioritization) on x86 is similar to
		 * the AT (access type) field in CBQRI. CDP only supports
		 * caches so this must be a CBQRI capacity controller.
		 */
		if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
		    ctrl->cc.supports_alloc_at_code &&
		    ctrl->cc.supports_alloc_at_data) {
			if (ctrl->cache.cache_level == 2)
				exposed_cdp_l2_capable = true;
			else
				exposed_cdp_l3_capable = true;
		}
	}
	pr_debug("alloc=%d mon=%d cdp_l2=%d cdp_l3=%d",
		 exposed_alloc_capable, exposed_mon_capable,
		 exposed_cdp_l2_capable, exposed_cdp_l3_capable);

	return resctrl_init();

err_free_controllers_list:
	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &cbqri_resctrl_resources[i];
		list_for_each_entry_safe(domain, domain_temp, &res->resctrl_res.ctrl_domains,
					 hdr.list) {
			kfree(domain);
		}
	}

err_unmap_controllers:
	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		if (!ctrl->base)
			break;
		iounmap(ctrl->base);
		ctrl->base = NULL;
		release_mem_region(ctrl->addr, ctrl->size);
	}

	return err;
}

int qos_resctrl_online_cpu(unsigned int cpu)
{
	resctrl_online_cpu(cpu);
	return 0;
}

int qos_resctrl_offline_cpu(unsigned int cpu)
{
	resctrl_offline_cpu(cpu);
	return 0;
}
