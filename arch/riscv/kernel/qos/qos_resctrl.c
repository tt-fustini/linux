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

/* used by resctrl_arch_system_num_rmid_idx(); narrowed by cbqri_probe_controller() */
static u32 max_rmid = U32_MAX;

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

/*
 * Apply an Rbwb value without the cross-RCID sum validation.  Init and
 * reset paths walk every RCID in a coordinated order; intermediate
 * sums during the walk may transiently exceed MRBWB while later RCIDs
 * still hold pre-walk values (e.g. firmware preconfiguration after
 * kexec, or the previous RCID 0 budget while RCIDs 1..N are still
 * being lowered).  Only the final state, set when all RCIDs have been
 * written, is guaranteed to satisfy the invariant -- and the caller
 * holds responsibility for that.
 */
static int cbqri_apply_rbwb_unchecked(struct cbqri_resctrl_dom *hw_dom,
				      u32 closid, u64 rbwb)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int ret;

	mutex_lock(&ctrl->lock);
	ret = cbqri_apply_bc_field(hw_dom, closid,
				   cbqri_set_rbwb, cbqri_get_rbwb, rbwb);
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

/*
 * Pair every L3 with the single mon-capable bandwidth controller in the
 * system, mirroring MPAM's strict "one MSC, one L3" mapping.  CBQRI BCs
 * live at memory-controller scope, which resctrl does not represent;
 * the only honest way to surface BC counters as MBM_TOTAL at L3 scope
 * is to require that there is exactly one BC, so all memory traffic
 * observed at the LLC necessarily flows through it.  If the platform
 * exposes zero or more than one mon-capable BC, no L3 gets a paired
 * BC and MBM_TOTAL is not advertised.
 */
static struct cbqri_controller *cbqri_find_only_mon_bc(void)
{
	struct cbqri_controller *ctrl, *only_bc = NULL;

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		if (ctrl->type != CBQRI_CONTROLLER_TYPE_BANDWIDTH)
			continue;
		if (!ctrl->mon_capable)
			continue;
		if (only_bc)
			return NULL;
		only_bc = ctrl;
	}
	return only_bc;
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
	/*
	 * MBM counter assignment is not supported on CBQRI.  Returning 0
	 * for enable=true would let the resctrl core believe the feature
	 * was activated even though no hardware change occurred; only
	 * accept the no-op disable path.
	 */
	if (enable)
		return -EOPNOTSUPP;
	return 0;
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

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain_hdr *hdr,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   void *arch_priv, u64 *val, void *arch_mon_ctx)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	struct rdt_ctrl_domain *d;
	u64 ctr_val;
	int err;

	if (eventid != QOS_L3_OCCUP_EVENT_ID)
		return -EINVAL;

	/*
	 * The monitoring domain shares the same id as the control domain.
	 * Find the control domain to get the hw_ctrl pointer.
	 */
	d = (struct rdt_ctrl_domain *)resctrl_find_domain(&r->ctrl_domains,
							  hdr->id, NULL);
	if (!d)
		return -ENOENT;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	ctrl = hw_dom->hw_ctrl;

	mutex_lock(&ctrl->lock);

	/*
	 * All MCIDs are configured with the Occupancy event at init time
	 * (qos_init_mon_counters). Just snapshot the current value.
	 */
	err = cbqri_cc_mon_op(ctrl, CBQRI_CC_MON_CTL_OP_READ_COUNTER,
			      rmid, 0, NULL);
	if (err)
		goto out;

	ctr_val = ioread64(ctrl->base + CBQRI_CC_MON_CTL_VAL_OFF);

	/* Convert from capacity blocks to bytes */
	*val = ctr_val * (ctrl->cache.cache_size / ctrl->cc.ncblks);

out:
	mutex_unlock(&ctrl->lock);
	return err;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 closid, u32 rmid, enum resctrl_event_id eventid)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	struct rdt_ctrl_domain *cd;

	if (eventid != QOS_L3_OCCUP_EVENT_ID)
		return;

	cd = (struct rdt_ctrl_domain *)resctrl_find_domain(&r->ctrl_domains,
							   d->hdr.id, NULL);
	if (!cd)
		return;

	hw_dom = container_of(cd, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	ctrl = hw_dom->hw_ctrl;

	mutex_lock(&ctrl->lock);
	/* CONFIG_EVENT with EVT_ID=None stops counting and resets counter */
	cbqri_cc_mon_op(ctrl, CBQRI_CC_MON_CTL_OP_CONFIG_EVENT,
			rmid, CBQRI_CC_EVT_ID_NONE, NULL);
	mutex_unlock(&ctrl->lock);
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
	int i;

	/*
	 * resctrl tracks the system-wide minimum mcid_count via max_rmid;
	 * MCIDs >= max_rmid are not visible to userspace.  Bound the loop
	 * to that subset so reset_rmid_all matches the index range that
	 * resctrl_arch_system_num_rmid_idx() advertises.
	 */
	for (i = 0; i < max_rmid; i++)
		resctrl_arch_reset_rmid(r, d, 0, i, QOS_L3_OCCUP_EVENT_ID);
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
			 *
			 * Walk RCIDs 1..N-1 down to 1 first, then RCID 0
			 * last, using the unchecked helper.  The sum check
			 * cannot be honoured during the walk: RCIDs not yet
			 * visited still hold their previous values, so the
			 * intermediate sum may exceed MRBWB even though the
			 * final state is MRBWB exactly.
			 */
			for (i = 0; i < hw_res->max_rcid; i++) {
				u32 rcid = (i + 1) % hw_res->max_rcid;
				int rerr;

				cfg.rbwb = rcid == 0 ?
					dom->hw_ctrl->bc.mrbwb - (hw_res->max_rcid - 1) : 1;
				rerr = cbqri_apply_rbwb_unchecked(dom, rcid,
								  cfg.rbwb);
				if (rerr)
					pr_err_ratelimited("RBWB reset RCID %u failed (%d)\n",
							   rcid, rerr);
			}
			break;
		case RDT_RESOURCE_MWEIGHT:
			/*
			 * Use the same default as new groups get at mkdir
			 * (resctrl_get_default_ctrl() -> max_bw since Mweight
			 * has no sum constraint). All RCIDs start at max
			 * weight, giving equal work-conserving shares; users
			 * restrict groups by writing a smaller value.
			 */
			for (i = 0; i < hw_res->max_rcid; i++) {
				cfg.mweight = default_ctrl;
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
	case RDT_RESOURCE_RBWB:
		/*
		 * sum(Rbwb) <= MRBWB validation now lives inside
		 * cbqri_apply_bw_config() so that sum, validate, and apply
		 * happen under one mutex acquisition; otherwise a concurrent
		 * resctrl writer could change another RCID's Rbwb between
		 * the sum and the apply, silently over-allocating.
		 */
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
	struct cbqri_resctrl_dom *dom;
	struct cbqri_config cfg;
	int err = 0;
	int i;

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	for (i = 0; i < hw_res->max_rcid; i++) {
		/*
		 * RBWB walks RCIDs 1..N-1 first, then RCID 0 last, so the
		 * sum is always trending toward (rather than past) MRBWB
		 * once every RCID has been written.  Other resources do
		 * not need the reorder, so they fall through.
		 */
		u32 rcid = (r->rid == RDT_RESOURCE_RBWB) ?
				((i + 1) % hw_res->max_rcid) : i;

		switch (r->rid) {
		case RDT_RESOURCE_RBWB:
			/*
			 * CBQRI §4.5: Rbwb >= 1, sum(Rbwb) <= MRBWB.
			 * RCID 0 gets the remaining budget so the final sum
			 * equals MRBWB exactly.  Use the unchecked helper:
			 * during the walk, RCIDs not yet visited may still
			 * hold stale firmware values that would make the
			 * intermediate sum check spuriously fail.
			 */
			if (rcid == 0)
				cfg.rbwb = dom->hw_ctrl->bc.mrbwb -
					   (hw_res->max_rcid - 1);
			else
				cfg.rbwb = 1;
			err = cbqri_apply_rbwb_unchecked(dom, rcid, cfg.rbwb);
			break;
		case RDT_RESOURCE_MWEIGHT:
			/*
			 * Match the new-group default from
			 * resctrl_get_default_ctrl(): max_bw, giving equal
			 * work-conserving shares across all RCIDs.
			 */
			cfg.mweight = resctrl_get_default_ctrl(r);
			err = cbqri_apply_mweight_config(dom, i, &cfg);
			break;
		default:
			err = resctrl_arch_update_one(r, d, i, 0,
						      resctrl_get_default_ctrl(r));
			break;
		}
		if (err)
			return err;
	}
	return 0;
}

static int qos_init_cache_resource(struct cbqri_controller *ctrl,
				   struct cbqri_resctrl_res *cbqri_res,
				   enum resctrl_res_level rid, char *name,
				   enum resctrl_scope scope)
{
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	/* Already initialized by a previous controller at this cache level */
	if (res->name) {
		if (cbqri_res->max_rcid != ctrl->rcid_count ||
		    res->cache.cbm_len != ctrl->cc.ncblks ||
		    res->alloc_capable != ctrl->alloc_capable) {
			pr_err("%s controllers have mismatched capabilities\n",
			       name);
			return -EINVAL;
		}
		return 0;
	}

	cbqri_res->max_rcid = ctrl->rcid_count;
	cbqri_res->max_mcid = ctrl->mcid_count;
	res->rid = rid;
	res->name = name;
	res->alloc_capable = ctrl->alloc_capable;
	res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
	res->ctrl_scope = scope;
	res->cache.cbm_len = ctrl->cc.ncblks;
	res->cache.shareable_bits = resctrl_get_default_ctrl(res);
	res->cache.min_cbm_bits = 1;

	if (ctrl->mon_capable && scope == RESCTRL_L3_CACHE) {
		res->mon_capable = true;
		res->mon_scope = RESCTRL_L3_CACHE;
		res->mon.num_rmid = ctrl->mcid_count;
		resctrl_enable_mon_event(QOS_L3_OCCUP_EVENT_ID, false, 0, NULL);
	}

	return 0;
}

static int qos_init_rbwb_resource(struct cbqri_controller *ctrl,
				  struct cbqri_resctrl_res *cbqri_res)
{
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	if (res->name) {
		if (cbqri_res->max_rcid != ctrl->rcid_count ||
		    res->membw.max_bw != ctrl->bc.mrbwb) {
			pr_err("RBWB controllers have mismatched capabilities\n");
			return -EINVAL;
		}
		return 0;
	}

	cbqri_res->max_rcid = ctrl->rcid_count;
	cbqri_res->max_mcid = ctrl->mcid_count;
	res->rid = RDT_RESOURCE_RBWB;
	res->name = "RBWB";
	res->alloc_capable = ctrl->alloc_capable;
	res->schema_fmt = RESCTRL_SCHEMA_RANGE;
	/*
	 * resctrl requires a cache scope for MBA-style domains. Use L3 as
	 * a proxy until the framework supports non-cache scopes for
	 * bandwidth resources.
	 */
	res->ctrl_scope = RESCTRL_L3_CACHE;
	/*
	 * CBQRI Rbwb is an integer block count, not a percentage with a
	 * linear-delay mapping. delay_linear/arch_needs_linear are the
	 * MBA concept and do not apply; leave them at their zero-init
	 * values so bw_validate() does not reject writes.
	 */
	res->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
	res->membw.min_bw = 1;
	res->membw.max_bw = ctrl->bc.mrbwb;
	res->membw.bw_gran = 1;
	/*
	 * CBQRI §4.5 caps sum(Rbwb across all RCIDs) at MRBWB. Enforcement
	 * lives in resctrl_arch_update_one() (returns -ENOSPC on overflow).
	 * Default new groups to min_bw so mkdir does not overflow the sum;
	 * max_bw remains the per-group upper bound enforced by bw_validate().
	 */
	res->membw.default_ctrl = res->membw.min_bw;
	return 0;
}

static int qos_init_mweight_resource(struct cbqri_controller *ctrl,
				     struct cbqri_resctrl_res *cbqri_res)
{
	struct rdt_resource *res = &cbqri_res->resctrl_res;

	if (res->name) {
		if (cbqri_res->max_rcid != ctrl->rcid_count) {
			pr_err("MWEIGHT controllers have mismatched capabilities\n");
			return -EINVAL;
		}
		return 0;
	}

	cbqri_res->max_rcid = ctrl->rcid_count;
	cbqri_res->max_mcid = ctrl->mcid_count;
	res->rid = RDT_RESOURCE_MWEIGHT;
	res->name = "MWEIGHT";
	res->alloc_capable = ctrl->alloc_capable;
	res->schema_fmt = RESCTRL_SCHEMA_RANGE;
	res->ctrl_scope = RESCTRL_L3_CACHE;
	/* Mweight is a dimensionless ratio; no delay/linear concept. */
	res->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
	/*
	 * CBQRI §4.5: Mweight is 0-255; 0 disables work-conserving, so
	 * the group gets only its Rbwb reservation with no opportunistic
	 * access to unreserved or unused bandwidth. Weights have no sum
	 * constraint (they are ratios, not a budget).
	 */
	res->membw.min_bw = 0;
	res->membw.max_bw = 255;
	res->membw.bw_gran = 1;
	return 0;
}

static int qos_init_mon_counters(struct cbqri_controller *ctrl)
{
	int i, err;

	for (i = 0; i < ctrl->mcid_count; i++) {
		mutex_lock(&ctrl->lock);
		err = cbqri_cc_mon_op(ctrl, CBQRI_CC_MON_CTL_OP_CONFIG_EVENT,
				      i, CBQRI_CC_EVT_ID_OCCUPANCY, NULL);
		mutex_unlock(&ctrl->lock);
		if (err)
			return err;
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
		return -ENOSPC;

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

static void qos_unregister_ctrl_domain(struct rdt_resource *res,
				       struct rdt_ctrl_domain *domain)
{
	resctrl_offline_ctrl_domain(res, domain);
	list_del(&domain->hdr.list);
	kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
}

static int qos_resctrl_add_controller_domain(struct cbqri_controller *ctrl)
{
	struct rdt_ctrl_domain *domain = NULL;
	struct cbqri_resctrl_res *cbqri_res = NULL;
	struct cbqri_resctrl_res *mw_cbqri_res = NULL;
	struct rdt_resource *res = NULL;
	struct rdt_resource *mw_res = NULL;
	struct rdt_ctrl_domain *mw_domain = NULL;
	int err;

	switch (ctrl->type) {
	case CBQRI_CONTROLLER_TYPE_CAPACITY:
		/*
		 * Spec allows a capacity controller with mcid_count>0 and
		 * rcid_count==0 (monitor-only).  Skip the whole
		 * resource+domain register path for those: qos_init_cache_resource()
		 * would record alloc_capable=false on the resource, and a
		 * later alloc-capable CC at the same level would then trip the
		 * mismatch check; qos_register_ctrl_domain() would also drive
		 * resctrl_arch_update_one() into a !alloc_capable -EINVAL.
		 *
		 * TODO: refactor to register an L3 mon_domain independently
		 * of the ctrl_domain so monitor-only CCs can still surface
		 * MBM/llc_occupancy.
		 */
		if (!ctrl->alloc_capable) {
			pr_debug("CC @%pa: monitor-only, skipping register\n",
				 &ctrl->addr);
			return 0;
		}

		if (ctrl->cache.cache_level == 2) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_L2];
			err = qos_init_cache_resource(ctrl, cbqri_res,
						      RDT_RESOURCE_L2, "L2",
						      RESCTRL_L2_CACHE);
		} else if (ctrl->cache.cache_level == 3) {
			cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_L3];
			err = qos_init_cache_resource(ctrl, cbqri_res,
						      RDT_RESOURCE_L3, "L3",
						      RESCTRL_L3_CACHE);
		} else {
			pr_err("unknown cache level %d\n", ctrl->cache.cache_level);
			return -ENODEV;
		}
		if (err)
			return err;
		res = &cbqri_res->resctrl_res;

		err = qos_register_ctrl_domain(ctrl, res, &ctrl->cache.cpu_mask,
					       ctrl->cache.cache_id, &domain);
		if (err)
			return err;
		break;

	case CBQRI_CONTROLLER_TYPE_BANDWIDTH:
		if (!ctrl->alloc_capable)
			return 0;

		/* Register RBWB resource + domain */
		cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_RBWB];
		err = qos_init_rbwb_resource(ctrl, cbqri_res);
		if (err)
			return err;
		res = &cbqri_res->resctrl_res;
		err = qos_register_ctrl_domain(ctrl, res, &ctrl->mem.cpu_mask,
					       ctrl->mem.prox_dom, &domain);
		if (err)
			return err;

		/* Register MWEIGHT resource + domain (parallel to RBWB) */
		mw_cbqri_res = &cbqri_resctrl_resources[RDT_RESOURCE_MWEIGHT];
		err = qos_init_mweight_resource(ctrl, mw_cbqri_res);
		if (err)
			goto err_rbwb;
		mw_res = &mw_cbqri_res->resctrl_res;
		err = qos_register_ctrl_domain(ctrl, mw_res, &ctrl->mem.cpu_mask,
					       ctrl->mem.prox_dom, &mw_domain);
		if (err)
			goto err_rbwb;
		break;

	default:
		pr_err("unknown controller type %d\n", ctrl->type);
		return -ENODEV;
	}

	/* Create monitoring domain for L3 capacity controllers */
	if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
	    ctrl->mon_capable && ctrl->cache.cache_level == 3) {
		struct rdt_l3_mon_domain *mon_dom;
		struct list_head *mon_pos = NULL;

		mon_dom = kzalloc_obj(*mon_dom, GFP_KERNEL);
		if (!mon_dom) {
			err = -ENOMEM;
			goto err_ctrl;
		}

		mon_dom->hdr.id = domain->hdr.id;
		mon_dom->hdr.type = RESCTRL_MON_DOMAIN;
		mon_dom->hdr.rid = RDT_RESOURCE_L3;
		cpumask_copy(&mon_dom->hdr.cpu_mask, &ctrl->cache.cpu_mask);
		INIT_LIST_HEAD(&mon_dom->hdr.list);

		/*
		 * Reject duplicate domain ids: two L3 capacity controllers
		 * sharing a cache_id would otherwise leave two entries on
		 * res->mon_domains with the same id, causing
		 * resctrl_offline_mon_domain() to be called twice during
		 * teardown.  Mirrors the ctrl_domain check in
		 * qos_register_ctrl_domain().
		 */
		if (resctrl_find_domain(&res->mon_domains, mon_dom->hdr.id,
					&mon_pos)) {
			pr_err("duplicate L3 mon domain id %d\n",
			       mon_dom->hdr.id);
			kfree(mon_dom);
			err = -EEXIST;
			goto err_ctrl;
		}
		if (mon_pos)
			list_add_tail(&mon_dom->hdr.list, mon_pos);
		else
			list_add_tail(&mon_dom->hdr.list, &res->mon_domains);

		err = resctrl_online_mon_domain(res, &mon_dom->hdr);
		if (err) {
			list_del(&mon_dom->hdr.list);
			kfree(mon_dom);
			goto err_ctrl;
		}

		err = qos_init_mon_counters(ctrl);
		if (err) {
			resctrl_offline_mon_domain(res, &mon_dom->hdr);
			list_del(&mon_dom->hdr.list);
			kfree(mon_dom);
			goto err_ctrl;
		}
	}

	return 0;

err_rbwb:
	if (domain)
		qos_unregister_ctrl_domain(res, domain);
	return err;

err_ctrl:
	if (mw_domain)
		qos_unregister_ctrl_domain(mw_res, mw_domain);
	if (domain)
		qos_unregister_ctrl_domain(res, domain);
	return err;
}

/*
 * Free every per-resource ctrl_domain and mon_domain registered through
 * qos_resctrl_setup(), then unmap the MMIO regions claimed by each
 * cbqri_controller in cbqri_probe_controller().  Safe to call partway
 * through setup: each list walk is empty if its corresponding pass
 * never ran, and a controller without ->base is skipped.
 */
void qos_resctrl_teardown(void)
{
	struct rdt_ctrl_domain *domain, *domain_temp;
	struct cbqri_resctrl_res *res;
	struct cbqri_controller *ctrl;
	int i;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		struct rdt_l3_mon_domain *mon_d, *mon_tmp;

		res = &cbqri_resctrl_resources[i];
		list_for_each_entry_safe(mon_d, mon_tmp,
					 &res->resctrl_res.mon_domains, hdr.list) {
			resctrl_offline_mon_domain(&res->resctrl_res, &mon_d->hdr);
			list_del(&mon_d->hdr.list);
			kfree(mon_d);
		}
		list_for_each_entry_safe(domain, domain_temp, &res->resctrl_res.ctrl_domains,
					 hdr.list) {
			resctrl_offline_ctrl_domain(&res->resctrl_res, domain);
			list_del(&domain->hdr.list);
			kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
		}
	}

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		kfree(ctrl->mbm_total_states);
		ctrl->mbm_total_states = NULL;
		if (!ctrl->base)
			continue;
		iounmap(ctrl->base);
		ctrl->base = NULL;
		release_mem_region(ctrl->addr, ctrl->size);
	}
}

int qos_resctrl_setup(void)
{
	struct cbqri_controller *ctrl;
	struct cbqri_resctrl_res *res;
	int err = 0;
	int i = 0;

	max_rmid = U32_MAX;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &cbqri_resctrl_resources[i];
		INIT_LIST_HEAD(&res->resctrl_res.ctrl_domains);
		INIT_LIST_HEAD(&res->resctrl_res.mon_domains);
		res->resctrl_res.rid = i;
	}

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		err = cbqri_probe_controller(ctrl);
		if (err) {
			pr_err("%s(): failed (%d)\n", __func__, err);
			goto err_free_controllers_list;
		}

		err = qos_resctrl_add_controller_domain(ctrl);
		if (err) {
			pr_err("%s(): failed to add controller domain (%d)\n", __func__, err);
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

		if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
		    ctrl->mon_capable && ctrl->cache.cache_level == 3)
			exposed_mon_capable = true;
	}
	pr_debug("alloc=%d mon=%d cdp_l2=%d cdp_l3=%d\n",
		 exposed_alloc_capable, exposed_mon_capable,
		 exposed_cdp_l2_capable, exposed_cdp_l3_capable);

	err = resctrl_init();
	if (err)
		goto err_free_controllers_list;

	return 0;

err_free_controllers_list:
	qos_resctrl_teardown();
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
