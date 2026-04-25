// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "qos: resctrl: " fmt

#include <linux/cpu.h>
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

void cbqri_controller_destroy(struct cbqri_controller *ctrl)
{
	kfree(ctrl);
}

static int cbqri_wait_busy_flag(struct cbqri_controller *ctrl, int reg_offset,
				u64 *regp);

/* Set capacity block mask (cc_block_mask) */
static void cbqri_set_cbm(struct cbqri_controller *ctrl, u64 cbm)
{
	iowrite64(cbm, ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
}

/* Set the Rbwb (reserved bandwidth blocks) field in bc_bw_alloc */
static void cbqri_set_rbwb(struct cbqri_controller *ctrl, u64 rbwb)
{
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_BC_BW_ALLOC_OFF);
	reg &= ~CBQRI_CONTROL_REGISTERS_RBWB_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_RBWB_MASK, rbwb);
	iowrite64(reg, ctrl->base + CBQRI_BC_BW_ALLOC_OFF);
}

/* Get the Rbwb (reserved bandwidth blocks) field in bc_bw_alloc */
static u64 cbqri_get_rbwb(struct cbqri_controller *ctrl)
{
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_BC_BW_ALLOC_OFF);
	return FIELD_GET(CBQRI_CONTROL_REGISTERS_RBWB_MASK, reg);
}

/* Set the Mweight (opportunistic weight) field in bc_bw_alloc */
static void cbqri_set_mweight(struct cbqri_controller *ctrl, u64 mweight)
{
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_BC_BW_ALLOC_OFF);
	reg &= ~CBQRI_CONTROL_REGISTERS_MWEIGHT_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_MWEIGHT_MASK, mweight);
	iowrite64(reg, ctrl->base + CBQRI_BC_BW_ALLOC_OFF);
}

/* Get the Mweight (opportunistic weight) field in bc_bw_alloc */
static u64 cbqri_get_mweight(struct cbqri_controller *ctrl)
{
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_BC_BW_ALLOC_OFF);
	return FIELD_GET(CBQRI_CONTROL_REGISTERS_MWEIGHT_MASK, reg);
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
		pr_err("%s(): BUSY timeout before starting operation\n", __func__);
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
		pr_err("%s(): BUSY timeout when executing the operation\n", __func__);
		return -EIO;
	}

	status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);
	if (status != CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS) {
		pr_err("%s(): operation %d failed: status=%d\n", __func__, operation, status);
		return -EIO;
	}

	return 0;
}

/*
 * Perform capacity usage monitoring operation on capacity controller.
 * Caller must hold ctrl->lock.
 */
static int cbqri_cc_mon_op(struct cbqri_controller *ctrl, int operation,
			   int mcid, int evt_id, u64 *out_reg)
{
	u64 reg;

	if (ctrl->faulted)
		return -EIO;

	reg = FIELD_PREP(CBQRI_MON_CTL_OP_MASK, operation) |
	      FIELD_PREP(CBQRI_MON_CTL_MCID_MASK, mcid) |
	      FIELD_PREP(CBQRI_MON_CTL_EVT_ID_MASK, evt_id);
	iowrite64(reg, ctrl->base + CBQRI_CC_MON_CTL_OFF);

	if (cbqri_wait_busy_flag(ctrl, CBQRI_CC_MON_CTL_OFF, &reg) < 0) {
		pr_err("%s(): BUSY timeout\n", __func__);
		return -EIO;
	}

	if (FIELD_GET(CBQRI_MON_CTL_STATUS_MASK, reg) !=
	    CBQRI_CC_MON_CTL_STATUS_SUCCESS)
		return -EIO;

	if (out_reg)
		*out_reg = reg;

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
		pr_err("%s(): operation failed: err = %d\n", __func__, err);
		goto out;
	}

	/* Clear cc_block_mask before read limit to verify op works */
	cbqri_set_cbm(ctrl, 0);

	/* Perform a capacity read limit operation to verify blockmask */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
	if (err < 0) {
		pr_err("%s(): operation failed: err = %d\n", __func__, err);
		goto out;
	}

	/* Read capacity blockmask to verify it matches the requested config */
	reg = ioread64(ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
	if (reg != cfg->cbm) {
		pr_err("%s(): failed to verify allocation (reg:%llx != cbm:%llx)\n",
		       __func__, reg, cfg->cbm);
		err = -EIO;
	}

out:
	mutex_unlock(&ctrl->lock);
	return err;
}

/*
 * Perform bandwidth usage monitoring operation on bandwidth controller.
 * Caller must hold ctrl->lock.
 */
static int cbqri_bc_mon_op(struct cbqri_controller *ctrl, int operation,
			   int mcid, int evt_id, u64 *out_reg)
{
	u64 reg;

	if (ctrl->faulted)
		return -EIO;

	reg = FIELD_PREP(CBQRI_MON_CTL_OP_MASK, operation) |
	      FIELD_PREP(CBQRI_MON_CTL_MCID_MASK, mcid) |
	      FIELD_PREP(CBQRI_MON_CTL_EVT_ID_MASK, evt_id);
	iowrite64(reg, ctrl->base + CBQRI_BC_MON_CTL_OFF);

	if (cbqri_wait_busy_flag(ctrl, CBQRI_BC_MON_CTL_OFF, &reg) < 0) {
		pr_err("%s(): BUSY timeout\n", __func__);
		return -EIO;
	}

	if (FIELD_GET(CBQRI_MON_CTL_STATUS_MASK, reg) !=
	    CBQRI_BC_MON_CTL_STATUS_SUCCESS)
		return -EIO;

	if (out_reg)
		*out_reg = reg;

	return 0;
}

/* Perform bandwidth allocation control operation on bandwidth controller */
/* Caller must hold ctrl->lock. */
static int cbqri_bc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid)
{
	int reg_offset = CBQRI_BC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	if (ctrl->faulted)
		return -EIO;

	reg = ioread64(ctrl->base + reg_offset);
	reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_OP_MASK, operation);
	reg &= ~CBQRI_CONTROL_REGISTERS_RCID_MASK;
	reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_RCID_MASK, rcid);
	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation\n", __func__);
		return -EIO;
	}

	status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);
	if (status != CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS) {
		pr_err("%s(): operation %d failed with status = %d\n",
		       __func__, operation, status);
		return -EIO;
	}

	return 0;
}

/*
 * Write one field (Rbwb or Mweight) of the bc_bw_alloc staging register for
 * @closid and verify hardware accepted it. bc_bw_alloc packs both fields, so
 * READ_LIMIT first loads the RCID's current state to preserve the unmodified
 * field across the subsequent CONFIG_LIMIT.
 *
 * Caller must hold ctrl->lock.
 */
static int cbqri_apply_bc_field(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				void (*set)(struct cbqri_controller *, u64),
				u64 (*get)(struct cbqri_controller *),
				u64 val)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int ret;
	u64 reg;

	/* Load current RCID state so the unmodified field is preserved */
	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
	if (ret < 0)
		return ret;

	set(ctrl, val);

	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_CONFIG_LIMIT, closid);
	if (ret < 0)
		return ret;

	/* Clear field before read-back so a silent READ_LIMIT failure is caught */
	set(ctrl, 0);

	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
	if (ret < 0)
		return ret;

	reg = get(ctrl);
	if (reg != val) {
		pr_err("%s(): verify mismatch (reg=0x%llx != val=%llu)\n",
		       __func__, reg, val);
		return -EIO;
	}

	return 0;
}

/*
 * Apply an Rbwb update for @closid.  The CBQRI §4.5 invariant
 * sum(Rbwb across all RCIDs) <= MRBWB must hold after the write, so
 * sum, validate, and apply all happen under one mutex acquisition --
 * dropping the lock between sum and apply would let a concurrent
 * resctrl writer change another RCID's Rbwb in the gap and silently
 * over-allocate.
 */
static int cbqri_apply_bw_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				 enum resctrl_conf_type type, struct cbqri_config *cfg)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	u64 sum = 0;
	int ret = 0;
	u32 i;

	mutex_lock(&ctrl->lock);

	if (cfg->rbwb > 0) {
		for (i = 0; i < ctrl->rcid_count; i++) {
			if (i == closid)
				continue;
			if (cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, i))
				continue;
			sum += cbqri_get_rbwb(ctrl);
		}
		if (sum + cfg->rbwb > ctrl->bc.mrbwb) {
			pr_err("%s(): RBWB sum %llu exceeds MRBWB %u\n",
			       __func__, sum + cfg->rbwb, ctrl->bc.mrbwb);
			ret = -ENOSPC;
			goto out;
		}
	}

	ret = cbqri_apply_bc_field(hw_dom, closid,
				   cbqri_set_rbwb, cbqri_get_rbwb, cfg->rbwb);
out:
	mutex_unlock(&ctrl->lock);
	return ret;
}

static int cbqri_apply_mweight_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				      struct cbqri_config *cfg)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int ret;

	mutex_lock(&ctrl->lock);
	ret = cbqri_apply_bc_field(hw_dom, closid,
				   cbqri_set_mweight, cbqri_get_mweight,
				   cfg->mweight);
	mutex_unlock(&ctrl->lock);
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
	reg &= ~CBQRI_CONTROL_REGISTERS_RCID_MASK;
	iowrite64(reg, ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("%s(): BUSY timeout when executing the operation\n", __func__);
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
		reg &= ~CBQRI_CONTROL_REGISTERS_AT_MASK;
		reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_AT_MASK,
				  CBQRI_CONTROL_REGISTERS_AT_CODE);
		iowrite64(reg, ctrl->base + reg_offset);
		if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
			pr_err("%s(): BUSY timeout when setting AT field\n", __func__);
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
		pr_err("%s(): BUSY timeout when restoring the original register value\n", __func__);
		return -EIO;
	}

	return 0;
}

static int cbqri_probe_cc(struct cbqri_controller *ctrl)
{
	bool has_mon_at_code;
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

static int cbqri_probe_bc(struct cbqri_controller *ctrl)
{
	bool has_mon_at_code;
	int err, status;
	u64 reg;

	reg = ioread64(ctrl->base + CBQRI_BC_CAPABILITIES_OFF);
	if (reg == 0)
		return -ENODEV;

	ctrl->ver_minor = FIELD_GET(CBQRI_BC_CAPABILITIES_VER_MINOR_MASK, reg);
	ctrl->ver_major = FIELD_GET(CBQRI_BC_CAPABILITIES_VER_MAJOR_MASK, reg);
	ctrl->bc.nbwblks = FIELD_GET(CBQRI_BC_CAPABILITIES_NBWBLKS_MASK, reg);
	ctrl->bc.mrbwb = FIELD_GET(CBQRI_BC_CAPABILITIES_MRBWB_MASK, reg);

	if (!ctrl->bc.nbwblks) {
		pr_err("bandwidth controller has nbwblks=0\n");
		return -EINVAL;
	}

	pr_debug("version=%d.%d nbwblks=%d mrbwb=%d\n",
		 ctrl->ver_major, ctrl->ver_minor,
		 ctrl->bc.nbwblks, ctrl->bc.mrbwb);

	/* Probe monitoring features */
	err = cbqri_probe_feature(ctrl, CBQRI_BC_MON_CTL_OFF,
				  CBQRI_BC_MON_CTL_OP_READ_COUNTER, &status,
				  &has_mon_at_code);
	if (err)
		return err;

	if (status == CBQRI_BC_MON_CTL_STATUS_SUCCESS)
		ctrl->mon_capable = true;

	/* Probe allocation features */
	err = cbqri_probe_feature(ctrl, CBQRI_BC_ALLOC_CTL_OFF,
				  CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT,
				  &status, &ctrl->bc.supports_alloc_at_code);
	if (err)
		return err;

	if (status == CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS) {
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
		pr_warn("%s(): controller has invalid addr=0x0, skipping\n", __func__);
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

	mutex_init(&ctrl->lock);

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

	return hw_res->max_rcid;
}

void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid)
{
	u32 srmcfg;

	if (WARN_ON_ONCE((closid & SRMCFG_RCID_MASK) != closid) ||
	    WARN_ON_ONCE((rmid & SRMCFG_MCID_MASK) != rmid))
		return;

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

	if (WARN_ON_ONCE((closid & SRMCFG_RCID_MASK) != closid) ||
	    WARN_ON_ONCE((rmid & SRMCFG_MCID_MASK) != rmid))
		return;

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
	return (READ_ONCE(tsk->thread.srmcfg) & SRMCFG_RCID_MASK) == closid;
}

bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u32 tsk_rmid;

	tsk_rmid = READ_ONCE(tsk->thread.srmcfg);
	tsk_rmid >>= SRMCFG_MCID_SHIFT;
	tsk_rmid &= SRMCFG_MCID_MASK;

	return tsk_rmid == rmid;
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	struct cbqri_resctrl_res *hw_res;
	struct cbqri_resctrl_dom *dom;
	struct rdt_ctrl_domain *d;
	enum resctrl_conf_type t;
	struct cbqri_config cfg;
	u32 default_ctrl;
	int i;

	lockdep_assert_cpus_held();

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	default_ctrl = resctrl_get_default_ctrl(r);

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		dom = container_of(d, struct cbqri_resctrl_dom,
				   resctrl_ctrl_dom);
		switch (r->rid) {
		case RDT_RESOURCE_RBWB:
			/*
			 * CBQRI §4.5: Rbwb >= 1, sum(Rbwb) <= MRBWB.
			 * Give RCID 0 the remaining budget after
			 * reserving 1 block for every other RCID.
			 */
			for (i = 0; i < hw_res->max_rcid; i++) {
				cfg.rbwb = i == 0 ?
					dom->hw_ctrl->bc.mrbwb - (hw_res->max_rcid - 1) : 1;
				cbqri_apply_bw_config(dom, i, 0, &cfg);
			}
			break;
		case RDT_RESOURCE_MWEIGHT:
			/* Default Mweight = 1 for work-conserving behavior */
			for (i = 0; i < hw_res->max_rcid; i++) {
				cfg.mweight = 1;
				cbqri_apply_mweight_config(dom, i, &cfg);
			}
			break;
		default:
			for (i = 0; i < hw_res->max_rcid; i++) {
				for (t = 0; t < CDP_NUM_TYPES; t++)
					resctrl_arch_update_one(r, d, i, t,
								default_ctrl);
			}
			break;
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
	struct cbqri_resctrl_res *hw_res;
	struct cbqri_controller *ctrl;
	struct cbqri_resctrl_dom *dom;
	struct cbqri_config cfg;
	u64 sum_other;
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
	case RDT_RESOURCE_RBWB:
		hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
		sum_other = cbqri_sum_other_rbwb(ctrl, closid, hw_res->max_rcid);
		if (sum_other + cfg_val > ctrl->bc.mrbwb) {
			pr_err("%s(): RBWB sum %llu exceeds MRBWB %u\n",
			       __func__, sum_other + cfg_val, ctrl->bc.mrbwb);
			return -ENOSPC;
		}
		cfg.rbwb = cfg_val;
		err = cbqri_apply_bw_config(dom, closid, t, &cfg);
		break;
	case RDT_RESOURCE_MWEIGHT:
		cfg.mweight = cfg_val;
		err = cbqri_apply_mweight_config(dom, closid, &cfg);
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
				pr_err("%s(): update failed (err=%d)\n", __func__, err);
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
			pr_err("%s(): operation failed: err = %d\n", __func__, err);
			break;
		}

		/* Read capacity block mask for RCID (closid) */
		val = ioread64(ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
		break;

	case RDT_RESOURCE_RBWB:
		err = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d\n", __func__, err);
			break;
		}
		val = cbqri_get_rbwb(ctrl);
		break;

	case RDT_RESOURCE_MWEIGHT:
		err = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (err < 0) {
			pr_err("%s(): operation failed: err = %d\n", __func__, err);
			break;
		}
		val = cbqri_get_mweight(ctrl);
		break;

	default:
		break;
	}

	mutex_unlock(&ctrl->lock);
	return val;
}
