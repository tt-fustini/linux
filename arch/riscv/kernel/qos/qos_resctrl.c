// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "qos: resctrl: " fmt

#include <linux/slab.h>
#include <linux/err.h>
#include <linux/riscv_qos.h>
#include <linux/resctrl.h>
#include <linux/types.h>
#include <asm/csr.h>
#include <asm/qos.h>
#include "internal.h"

#define MAX_CONTROLLERS 6
static struct cbqri_controller controllers[MAX_CONTROLLERS];
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

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return exposed_mon_capable;
}

bool resctrl_arch_is_llc_occupancy_enabled(void)
{
	return true;
}

bool resctrl_arch_is_mbm_local_enabled(void)
{
	return false;
}

bool resctrl_arch_is_mbm_total_enabled(void)
{
	return false;
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

struct rdt_domain_hdr *resctrl_arch_find_domain(struct list_head *domain_list, int id)
{
	struct rdt_domain_hdr *hdr;

	lockdep_assert_cpus_held();

	list_for_each_entry(hdr, domain_list, list) {
		if (hdr->id == id)
			return hdr;
	}

	return NULL;
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

void resctrl_arch_reset_resources(void)
{
	/* not implemented for the RISC-V resctrl implementation */
}

void resctrl_arch_config_cntr(struct rdt_resource *r, struct rdt_mon_domain *d,
			      enum resctrl_event_id evtid, u32 rmid, u32 closid,
			      u32 cntr_id, bool assign)
{
	/* not implemented for the RISC-V resctrl implementation */
}

int resctrl_arch_cntr_read(struct rdt_resource *r, struct rdt_mon_domain *d,
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

void resctrl_arch_reset_cntr(struct rdt_resource *r, struct rdt_mon_domain *d,
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
	*closid = ((u32)~0); /* refer to X86_RESCTRL_BAD_CLOSID */
	*rmid = idx;
}

/* RISC-V resctrl interface does not maintain a default srmcfg value for a given CPU */
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid) { }

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

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_mon_domain *d,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   u64 *val, void *arch_mon_ctx)
{
	/*
	 * The current Qemu implementation of CBQRI capacity and bandwidth
	 * controllers do not emulate the utilization of resources over
	 * time. Therefore, Qemu currently sets the invalid bit in
	 * cc_mon_ctr_val and bc_mon_ctr_val, and there is no meaningful
	 * value other than 0 to return for reading an RMID (e.g. MCID in
	 * CBQRI terminology)
	 */

	return 0;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_mon_domain *d,
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

void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_mon_domain *d)
{
	/* not implemented for the RISC-V resctrl implementation */
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	/* not implemented for the RISC-V resctrl implementation */
}

/* Set capacity block mask (cc_block_mask) */
static void cbqri_set_cbm(struct cbqri_controller *ctrl, u64 cbm)
{
		int reg_offset;
		u64 reg;

		reg_offset = CBQRI_CC_BLOCK_MASK_OFF;
		reg = ioread64(ctrl->base + reg_offset);

		reg = cbm;
		iowrite64(reg, ctrl->base + reg_offset);
}

/* Set the Rbwb (reserved bandwidth blocks) field in bc_bw_alloc */
static void cbqri_set_rbwb(struct cbqri_controller *ctrl, u64 rbwb)
{
		int reg_offset;
		u64 reg;

		reg_offset = CBQRI_BC_BW_ALLOC_OFF;
		reg = ioread64(ctrl->base + reg_offset);
		reg &= ~CBQRI_CONTROL_REGISTERS_RBWB_MASK;
		rbwb &= CBQRI_CONTROL_REGISTERS_RBWB_MASK;
		reg |= rbwb;
		iowrite64(reg, ctrl->base + reg_offset);
}

/* Get the Rbwb (reserved bandwidth blocks) field in bc_bw_alloc */
static u64 cbqri_get_rbwb(struct cbqri_controller *ctrl)
{
		int reg_offset;
		u64 reg;

		reg_offset = CBQRI_BC_BW_ALLOC_OFF;
		reg = ioread64(ctrl->base + reg_offset);
		reg &= CBQRI_CONTROL_REGISTERS_RBWB_MASK;
		return reg;
}

static int cbqri_wait_busy_flag(struct cbqri_controller *ctrl, int reg_offset)
{
	unsigned long timeout = jiffies + (HZ / 10); /* Timeout after 100ms */
	int busy;
	u64 reg;

	while (time_before(jiffies, timeout)) {
		reg = ioread64(ctrl->base + reg_offset);
		busy = (reg >> CBQRI_CONTROL_REGISTERS_BUSY_SHIFT) &
			CBQRI_CONTROL_REGISTERS_BUSY_MASK;
		if (!busy)
			return 0;
	}

	pr_warn("%s(): busy timeout", __func__);
	return -EIO;
}

/* Perform capacity allocation control operation on capacity controller */
static int cbqri_cc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid,
			     enum resctrl_conf_type type)
{
	int reg_offset = CBQRI_CC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	reg = ioread64(ctrl->base + reg_offset);
	reg &= ~(CBQRI_CONTROL_REGISTERS_OP_MASK << CBQRI_CONTROL_REGISTERS_OP_SHIFT);
	reg |= (operation & CBQRI_CONTROL_REGISTERS_OP_MASK) <<
		CBQRI_CONTROL_REGISTERS_OP_SHIFT;
	reg &= ~(CBQRI_CONTROL_REGISTERS_RCID_MASK <<
		 CBQRI_CONTROL_REGISTERS_RCID_SHIFT);
	reg |= (rcid & CBQRI_CONTROL_REGISTERS_RCID_MASK) <<
		CBQRI_CONTROL_REGISTERS_RCID_SHIFT;

	/* CBQRI capacity AT is only supported on L2 and L3 caches for now */
	if (ctrl->ctrl_info->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
	    ((ctrl->ctrl_info->cache.cache_level == 2 && is_cdp_l2_enabled) ||
	    (ctrl->ctrl_info->cache.cache_level == 3 && is_cdp_l3_enabled))) {
		reg &= ~(CBQRI_CONTROL_REGISTERS_AT_MASK <<
			 CBQRI_CONTROL_REGISTERS_AT_SHIFT);
		switch (type) {
		case CDP_CODE:
			reg |= (CBQRI_CONTROL_REGISTERS_AT_CODE &
				CBQRI_CONTROL_REGISTERS_AT_MASK) <<
				CBQRI_CONTROL_REGISTERS_AT_SHIFT;
			break;
		case CDP_DATA:
		default:
			reg |= (CBQRI_CONTROL_REGISTERS_AT_DATA &
				CBQRI_CONTROL_REGISTERS_AT_MASK) <<
				CBQRI_CONTROL_REGISTERS_AT_SHIFT;
			break;
		}
	}

	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation", __func__);
		return -EIO;
	}

	reg = ioread64(ctrl->base + reg_offset);
	status = (reg >> CBQRI_CONTROL_REGISTERS_STATUS_SHIFT) &
		  CBQRI_CONTROL_REGISTERS_STATUS_MASK;
	if (status != 1) {
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

	if (cfg->cbm != hw_dom->ctrl_val[closid]) {
		/* Store the new cbm in the ctrl_val array for this closid in this domain */
		hw_dom->ctrl_val[closid] = cfg->cbm;

		/* Set capacity block mask (cc_block_mask) */
		cbqri_set_cbm(ctrl, cfg->cbm);

		/* Capacity config limit operation */
		err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT, closid, type);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d", __func__, err);
			return err;
		}

		/* Clear cc_block_mask before read limit to verify op works*/
		cbqri_set_cbm(ctrl, 0);

		/* Performa capacity read limit operation to verify blockmask */
		err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d", __func__, err);
			return err;
		}

		/* Read capacity blockmask to verify it matches the requested config */
		reg_offset = CBQRI_CC_BLOCK_MASK_OFF;
		reg = ioread64(ctrl->base + reg_offset);
		if (reg != cfg->cbm) {
			pr_warn("%s(): failed to verify allocation (reg:%llx != cbm:%llx)",
				__func__, reg, cfg->cbm);
			return -EIO;
		}
	}

	return err;
}

/* Perform bandwidth allocation control operation on bandwidth controller */
static int cbqri_bc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid)
{
	int reg_offset = CBQRI_BC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	reg = ioread64(ctrl->base + reg_offset);
	reg &= ~(CBQRI_CONTROL_REGISTERS_OP_MASK << CBQRI_CONTROL_REGISTERS_OP_SHIFT);
	reg |=  (operation & CBQRI_CONTROL_REGISTERS_OP_MASK) <<
		 CBQRI_CONTROL_REGISTERS_OP_SHIFT;
	reg &= ~(CBQRI_CONTROL_REGISTERS_RCID_MASK << CBQRI_CONTROL_REGISTERS_RCID_SHIFT);
	reg |=  (rcid & CBQRI_CONTROL_REGISTERS_RCID_MASK) <<
		 CBQRI_CONTROL_REGISTERS_RCID_SHIFT;
	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation", __func__);
		return -EIO;
	}

	reg = ioread64(ctrl->base + reg_offset);
	status = (reg >> CBQRI_CONTROL_REGISTERS_STATUS_SHIFT) &
		  CBQRI_CONTROL_REGISTERS_STATUS_MASK;
	if (status != 1) {
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

	if (cfg->rbwb != hw_dom->ctrl_val[closid]) {
		/* Store the new rbwb in the ctrl_val array for this closid in this domain */
		hw_dom->ctrl_val[closid] = cfg->rbwb;

		/* Set reserved bandwidth blocks */
		cbqri_set_rbwb(ctrl, cfg->rbwb);

		/* Bandwidth config limit operation */
		ret = cbqri_bc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT, closid);
		if (ret < 0) {
			pr_err("%s(): operation failed: ret = %d", __func__, ret);
			return ret;
		}

		/* Clear rbwb before read limit to verify op works*/
		cbqri_set_rbwb(ctrl, 0);

		/* Bandwidth allocation read limit operation to verify */
		ret = cbqri_bc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (ret < 0) {
			pr_err("%s(): operation failed: ret = %d", __func__, ret);
			return ret;
		}

		/* Read bandwidth allocation to verify it matches the requested config */
		reg = cbqri_get_rbwb(ctrl);
		if (reg != cfg->rbwb) {
			pr_warn("%s(): failed to verify allocation (reg:%llx != rbwb:%llu)",
				__func__, reg, cfg->rbwb);
			return -EIO;
		}
	}

	return ret;
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
		/* covert from percentage to bandwidth blocks */
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
				pr_warn("%s(): update failed (err=%d)", __func__, err);
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
	int reg_offset;
	u32 percent;
	u32 rbwb;
	u64 reg;
	int err;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	ctrl = hw_dom->hw_ctrl;

	if (!r->alloc_capable)
		return -EINVAL;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		/* Clear cc_block_mask before read limit operation */
		cbqri_set_cbm(ctrl, 0);

		/* Capacity read limit operation for RCID (closid) */
		err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, type, closid);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d", __func__, err);
			return -EIO;
		}

		/* Read capacity block mask for RCID (closid) */
		reg_offset = CBQRI_CC_BLOCK_MASK_OFF;
		reg = ioread64(ctrl->base + reg_offset);

		/* Update the config value for the closid in this domain */
		hw_dom->ctrl_val[closid] = reg;
		return hw_dom->ctrl_val[closid];

	case RDT_RESOURCE_MBA:
		/* Capacity read limit operation for RCID (closid) */
		err = cbqri_bc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d", __func__, err);
			return -EIO;
		}

		hw_dom->ctrl_val[closid] = cbqri_get_rbwb(ctrl);

		/* Convert from bandwidth blocks to percent */
		rbwb = hw_dom->ctrl_val[closid];
		rbwb *= 100;
		percent = rbwb / ctrl->bc.nbwblks;
		if (rbwb % ctrl->bc.nbwblks)
			percent++;
		return percent;

	default:
		return -EINVAL;
	}
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
	reg &= ~(CBQRI_CONTROL_REGISTERS_OP_MASK << CBQRI_CONTROL_REGISTERS_OP_SHIFT);
	reg |= (operation & CBQRI_CONTROL_REGISTERS_OP_MASK) << CBQRI_CONTROL_REGISTERS_OP_SHIFT;
	iowrite64(reg, ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation", __func__);
		return -EIO;
	}

	/* Get the operation status */
	reg = ioread64(ctrl->base + reg_offset);
	*status = (reg >> CBQRI_CONTROL_REGISTERS_STATUS_SHIFT) &
		   CBQRI_CONTROL_REGISTERS_STATUS_MASK;

	/*
	 * Check for the AT support if the register is implemented
	 * (if not, the status value will remain 0)
	 */
	if (*status != 0) {
		/* Set the AT field to a valid value */
		reg = saved_reg;
		reg &= ~(CBQRI_CONTROL_REGISTERS_AT_MASK << CBQRI_CONTROL_REGISTERS_AT_SHIFT);
		reg |= CBQRI_CONTROL_REGISTERS_AT_CODE << CBQRI_CONTROL_REGISTERS_AT_SHIFT;
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
		at = (reg >> CBQRI_CONTROL_REGISTERS_AT_SHIFT) & CBQRI_CONTROL_REGISTERS_AT_MASK;
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

/*
 * Note: for the purposes of the CBQRI proof-of-concept, debug logging
 * has been left in this function that detects the properties of CBQRI
 * capable controllers in the system. pr_info calls would be removed
 * before submitting non-RFC patches.
 */
static int cbqri_probe_controller(struct cbqri_controller_info *ctrl_info,
				  struct cbqri_controller *ctrl)
{
	int err = 0, status;
	u64 reg;

	pr_info("controller info: type=%d addr=0x%lx size=%lu max-rcid=%u max-mcid=%u",
		ctrl_info->type, ctrl_info->addr, ctrl_info->size,
		ctrl_info->rcid_count, ctrl_info->mcid_count);

	/* max_rmid is used by resctrl_arch_system_num_rmid_idx() */
	max_rmid = ctrl_info->mcid_count;

	ctrl->ctrl_info = ctrl_info;

	/* Try to access the memory-mapped CBQRI registers */
	if (!request_mem_region(ctrl_info->addr, ctrl_info->size, "cbqri_controller")) {
		pr_warn("%s(): return %d", __func__, err);
		return err;
	}
	ctrl->base = ioremap(ctrl_info->addr, ctrl_info->size);
	if (!ctrl->base) {
		pr_warn("%s(): goto err_release_mem_region", __func__);
		goto err_release_mem_region;
	}

	ctrl->alloc_capable = false;
	ctrl->mon_capable = false;

	/* Probe capacity allocation and monitoring features */
	if (ctrl_info->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
		pr_info("probe capacity controller");

		/* Make sure the register is implemented */
		reg = ioread64(ctrl->base + CBQRI_CC_CAPABILITIES_OFF);
		if (reg == 0) {
			err = -ENODEV;
			goto err_iounmap;
		}

		ctrl->ver_minor = reg & CBQRI_CC_CAPABILITIES_VER_MINOR_MASK;
		ctrl->ver_major = reg & CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK;

		ctrl->cc.supports_alloc_op_flush_rcid = (reg >> CBQRI_CC_CAPABILITIES_FRCID_SHIFT)
			& CBQRI_CC_CAPABILITIES_FRCID_MASK;

		ctrl->cc.ncblks = (reg >> CBQRI_CC_CAPABILITIES_NCBLKS_SHIFT) &
				   CBQRI_CC_CAPABILITIES_NCBLKS_MASK;

		/* Calculate size of capacity block in bytes */
		ctrl->cc.blk_size = ctrl_info->cache.cache_size / ctrl->cc.ncblks;
		ctrl->cc.cache_level = ctrl_info->cache.cache_level;

		pr_info("version=%d.%d ncblks=%d blk_size=%d cache_level=%d",
			ctrl->ver_major, ctrl->ver_minor,
			ctrl->cc.ncblks, ctrl->cc.blk_size, ctrl->cc.cache_level);

		/* Probe monitoring features */
		err = cbqri_probe_feature(ctrl, CBQRI_CC_MON_CTL_OFF,
					  CBQRI_CC_MON_CTL_OP_READ_COUNTER, &status,
					  &ctrl->cc.supports_mon_at_code);
		if (err) {
			pr_warn("%s() failed to probe cc_mon_ctl feature", __func__);
			goto err_iounmap;
		}

		if (status == CBQRI_CC_MON_CTL_STATUS_SUCCESS) {
			pr_info("cc_mon_ctl is supported");
			ctrl->cc.supports_mon_op_config_event = true;
			ctrl->cc.supports_mon_op_read_counter = true;
			ctrl->mon_capable = true;
		} else {
			pr_info("cc_mon_ctl is NOT supported");
			ctrl->cc.supports_mon_op_config_event = false;
			ctrl->cc.supports_mon_op_read_counter = false;
			ctrl->mon_capable = false;
		}
		/*
		 * AT data is "always" supported as it has the same value
		 * than when AT field is not supported.
		 */
		ctrl->cc.supports_mon_at_data = true;
		pr_info("supports_mon_at_data: %d, supports_mon_at_code: %d",
			ctrl->cc.supports_mon_at_data, ctrl->cc.supports_mon_at_code);

		/* Probe allocation features */
		err = cbqri_probe_feature(ctrl, CBQRI_CC_ALLOC_CTL_OFF,
					  CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT,
					  &status, &ctrl->cc.supports_alloc_at_code);
		if (err) {
			pr_warn("%s() failed to probe cc_alloc_ctl feature", __func__);
			goto err_iounmap;
		}

		if (status == CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS) {
			pr_info("cc_alloc_ctl is supported");
			ctrl->cc.supports_alloc_op_config_limit = true;
			ctrl->cc.supports_alloc_op_read_limit = true;
			ctrl->alloc_capable = true;
			exposed_alloc_capable = true;
		} else {
			pr_info("cc_alloc_ctl is NOT supported");
			ctrl->cc.supports_alloc_op_config_limit = false;
			ctrl->cc.supports_alloc_op_read_limit = false;
			ctrl->alloc_capable = false;
		}
		/*
		 * AT data is "always" supported as it has the same value
		 * than when AT field is not supported
		 */
		ctrl->cc.supports_alloc_at_data = true;
		pr_info("supports_alloc_at_data: %d, supports_alloc_at_code: %d",
			ctrl->cc.supports_alloc_at_data,
			ctrl->cc.supports_alloc_at_code);
	} else if (ctrl_info->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
		pr_info("probe bandwidth controller");

		/* Make sure the register is implemented */
		reg = ioread64(ctrl->base + CBQRI_BC_CAPABILITIES_OFF);
		if (reg == 0) {
			err = -ENODEV;
			goto err_iounmap;
		}

		ctrl->ver_minor = reg & CBQRI_BC_CAPABILITIES_VER_MINOR_MASK;
		ctrl->ver_major = reg & CBQRI_BC_CAPABILITIES_VER_MAJOR_MASK;

		ctrl->bc.nbwblks = (reg >> CBQRI_BC_CAPABILITIES_NBWBLKS_SHIFT) &
				    CBQRI_BC_CAPABILITIES_NBWBLKS_MASK;
		ctrl->bc.mrbwb = (reg >> CBQRI_BC_CAPABILITIES_MRBWB_SHIFT) &
				  CBQRI_BC_CAPABILITIES_MRBWB_MASK;

		pr_info("version=%d.%d nbwblks=%d mrbwb=%d",
			ctrl->ver_major, ctrl->ver_minor,
			ctrl->bc.nbwblks, ctrl->bc.mrbwb);

		/* Probe monitoring features */
		err = cbqri_probe_feature(ctrl, CBQRI_BC_MON_CTL_OFF,
					  CBQRI_BC_MON_CTL_OP_READ_COUNTER,
					  &status, &ctrl->bc.supports_mon_at_code);
		if (err) {
			pr_warn("%s() failed to probe bc_mon_ctl feature", __func__);
			goto err_iounmap;
		}

		if (status == CBQRI_BC_MON_CTL_STATUS_SUCCESS) {
			pr_info("bc_mon_ctl is supported");
			ctrl->bc.supports_mon_op_config_event = true;
			ctrl->bc.supports_mon_op_read_counter = true;
			ctrl->mon_capable = true;
			exposed_mon_capable = true;
		} else {
			pr_info("bc_mon_ctl is NOT supported");
			ctrl->bc.supports_mon_op_config_event = false;
			ctrl->bc.supports_mon_op_read_counter = false;
			ctrl->mon_capable = false;
		}
		/*
		 * AT data is "always" supported as it has the same value
		 * than when AT field is not supported
		 */
		ctrl->bc.supports_mon_at_data = true;
		pr_info("supports_mon_at_data: %d, supports_mon_at_code: %d",
			ctrl->bc.supports_mon_at_data, ctrl->bc.supports_mon_at_code);

		/* Probe allocation features */
		err = cbqri_probe_feature(ctrl, CBQRI_BC_ALLOC_CTL_OFF,
					  CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT,
					  &status, &ctrl->bc.supports_alloc_at_code);
		if (err) {
			pr_warn("%s() failed to probe bc_alloc_ctl feature", __func__);
			goto err_iounmap;
		}

		if (status == CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS) {
			pr_warn("bc_alloc_ctl is supported");
			ctrl->bc.supports_alloc_op_config_limit = true;
			ctrl->bc.supports_alloc_op_read_limit = true;
			ctrl->alloc_capable = true;
			exposed_alloc_capable = true;
		} else {
			pr_warn("bc_alloc_ctl is NOT supported");
			ctrl->bc.supports_alloc_op_config_limit = false;
			ctrl->bc.supports_alloc_op_read_limit = false;
			ctrl->alloc_capable = false;
		}

		/*
		 * AT data is "always" supported as it has the same value
		 * than when AT field is not supported
		 */
		ctrl->bc.supports_alloc_at_data = true;
		pr_warn("supports_alloc_at_data: %d, supports_alloc_at_code: %d",
			ctrl->bc.supports_alloc_at_data, ctrl->bc.supports_alloc_at_code);
	} else {
		pr_warn("controller type is UNKNOWN");
		err = -ENODEV;
		goto err_release_mem_region;
	}

	return 0;

err_iounmap:
	pr_warn("%s(): err_iounmap", __func__);
	iounmap(ctrl->base);

err_release_mem_region:
	pr_warn("%s(): err_release_mem_region", __func__);
	release_mem_region(ctrl_info->addr, ctrl_info->size);

	return err;
}

static struct rdt_ctrl_domain *qos_new_domain(struct cbqri_controller *ctrl)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct rdt_ctrl_domain *domain;

	hw_dom = kzalloc(sizeof(*hw_dom), GFP_KERNEL);
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
	struct cbqri_resctrl_dom *hw_dom;
	u64 *dc;
	int err = 0;
	int i;

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	if (!hw_res)
		return -ENOMEM;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	if (!hw_dom)
		return -ENOMEM;

	dc = kmalloc_array(hw_res->max_rcid, sizeof(*hw_dom->ctrl_val),
			   GFP_KERNEL);
	if (!dc)
		return -ENOMEM;

	hw_dom->ctrl_val = dc;

	for (i = 0; i < hw_res->max_rcid; i++, dc++) {
		err = resctrl_arch_update_one(r, d, i, 0, resctrl_get_default_ctrl(r));
		if (err)
			return 0;
		*dc = resctrl_get_default_ctrl(r);
	}
	return 0;
}

static int qos_resctrl_add_controller_domain(struct cbqri_controller *ctrl, int *id)
{
	struct rdt_ctrl_domain *domain = NULL;
	struct cbqri_resctrl_res *cbqri_res = NULL;
	struct rdt_resource *res = NULL;
	int internal_id = *id;
	int err = 0;

	domain = qos_new_domain(ctrl);
	if (!domain)
		return -ENOSPC;
	if (ctrl->ctrl_info->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
		cpumask_copy(&domain->hdr.cpu_mask, &ctrl->ctrl_info->cache.cpu_mask);
		if (ctrl->ctrl_info->cache.cache_level == 2) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_L2];
			cbqri_res->max_rcid = ctrl->ctrl_info->rcid_count;
			cbqri_res->max_mcid = ctrl->ctrl_info->mcid_count;
			res = &cbqri_res->resctrl_res;
			res->mon.num_rmid = ctrl->ctrl_info->mcid_count;
			res->rid = RDT_RESOURCE_L2;
			res->name = "L2";
			res->alloc_capable = ctrl->alloc_capable;
			res->mon_capable = ctrl->mon_capable;
			res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
			res->ctrl_scope = RESCTRL_L2_CACHE;
			res->cache.arch_has_sparse_bitmasks = false;
			res->cache.arch_has_per_cpu_cfg = false;
			res->cache.cbm_len = ctrl->cc.ncblks;
			res->cache.shareable_bits = resctrl_get_default_ctrl(res);
			res->cache.min_cbm_bits = 1;
		} else if (ctrl->ctrl_info->cache.cache_level == 3) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_L3];
			cbqri_res->max_rcid = ctrl->ctrl_info->rcid_count;
			cbqri_res->max_mcid = ctrl->ctrl_info->mcid_count;
			res = &cbqri_res->resctrl_res;
			res->mon.num_rmid = ctrl->ctrl_info->mcid_count;
			res->rid = RDT_RESOURCE_L3;
			res->name = "L3";
			res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
			res->ctrl_scope = RESCTRL_L3_CACHE;
			res->alloc_capable = ctrl->alloc_capable;
			res->mon_capable = ctrl->mon_capable;
			res->cache.arch_has_sparse_bitmasks = false;
			res->cache.arch_has_per_cpu_cfg = false;
			res->cache.cbm_len = ctrl->cc.ncblks;
			res->cache.shareable_bits = resctrl_get_default_ctrl(res);
			res->cache.min_cbm_bits = 1;
		} else {
			pr_warn("%s(): unknown cache level %d", __func__,
				ctrl->ctrl_info->cache.cache_level);
			err = -ENODEV;
			goto err_free_domain;
		}
	} else if (ctrl->ctrl_info->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
		if (ctrl->alloc_capable) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_MBA];
			cbqri_res->max_rcid = ctrl->ctrl_info->rcid_count;
			cbqri_res->max_mcid = ctrl->ctrl_info->mcid_count;
			res = &cbqri_res->resctrl_res;
			res->mon.num_rmid = ctrl->ctrl_info->mcid_count;
			res->rid = RDT_RESOURCE_MBA;
			res->name = "MB";
			res->schema_fmt = RESCTRL_SCHEMA_RANGE;
			res->ctrl_scope = RESCTRL_L3_CACHE;
			res->alloc_capable = ctrl->alloc_capable;
			res->mon_capable = false;
			res->membw.delay_linear = true;
			res->membw.arch_needs_linear = true;
			res->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
			// The minimum percentage allowed by the CBQRI spec
			res->membw.min_bw = 1;
			// The maximum percentage allowed by the CBQRI spec
			res->membw.max_bw = 80;
			res->membw.bw_gran = 1;
		}
	} else {
		pr_warn("%s(): unknown resource %d", __func__, ctrl->ctrl_info->type);
		err = -ENODEV;
		goto err_free_domain;
	}

	domain->hdr.id = internal_id;
	err = qos_init_domain_ctrlval(res, domain);
	if (err)
		goto err_free_domain;

	if (cbqri_res) {
		list_add_tail(&domain->hdr.list, &cbqri_res->resctrl_res.ctrl_domains);
		*id = internal_id;
		err = resctrl_online_ctrl_domain(res, domain);
		if (err) {
			pr_warn("%s(): failed to online cbqri_res domain", __func__);
			goto err_free_domain;
		}
	}

	return 0;

err_free_domain:
	pr_warn("%s(): err_free_domain", __func__);
	kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));

	return err;
}

int qos_resctrl_setup(void)
{
	struct rdt_ctrl_domain *domain, *domain_temp;
	struct cbqri_controller_info *ctrl_info;
	struct cbqri_controller *ctrl;
	struct cbqri_resctrl_res *res;
	static int found_controllers;
	int err = 0;
	int id = 0;
	int i;

	list_for_each_entry(ctrl_info, &cbqri_controllers, list) {
		err = cbqri_probe_controller(ctrl_info, &controllers[found_controllers]);
		if (err) {
			pr_warn("%s(): failed (%d)", __func__, err);
			goto err_unmap_controllers;
		}

		found_controllers++;
		if (found_controllers > MAX_CONTROLLERS) {
			pr_warn("%s(): increase MAX_CONTROLLERS value", __func__);
			break;
		}
	}

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &cbqri_resctrl_resources[i];
		INIT_LIST_HEAD(&res->resctrl_res.ctrl_domains);
		INIT_LIST_HEAD(&res->resctrl_res.mon_domains);
		res->resctrl_res.rid = i;
	}

	for (i = 0; i < found_controllers; i++) {
		ctrl = &controllers[i];
		err = qos_resctrl_add_controller_domain(ctrl, &id);
		if (err) {
			pr_warn("%s(): failed to add controller domain (%d)", __func__, err);
			goto err_free_controllers_list;
		}
		id++;

		/*
		 * CDP (code data prioritization) on x86 is similar to
		 * the AT (access type) field in CBQRI. CDP only supports
		 * caches so this must be a CBQRI capacity controller.
		 */
		if (ctrl->ctrl_info->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
		    ctrl->cc.supports_alloc_at_code &&
		    ctrl->cc.supports_alloc_at_data) {
			if (ctrl->ctrl_info->cache.cache_level == 2)
				exposed_cdp_l2_capable = true;
			else
				exposed_cdp_l3_capable = true;
		}
	}

	pr_info("exposed_alloc_capable = %d", exposed_alloc_capable);
	pr_info("exposed_mon_capable = %d", exposed_mon_capable);
	pr_info("exposed_cdp_l2_capable = %d", exposed_cdp_l2_capable);
	pr_info("exposed_cdp_l3_capable = %d", exposed_cdp_l3_capable);

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
	for (i = 0; i < found_controllers; i++) {
		iounmap(controllers[i].base);
		release_mem_region(controllers[i].ctrl_info->addr, controllers[i].ctrl_info->size);
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

