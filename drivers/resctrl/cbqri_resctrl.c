// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "qos: resctrl: " fmt

#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/cacheinfo.h>
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
 * Per-event monitor table.  cbqri_resctrl_pick_counters() populates one
 * slot per advertised event; cbqri_resctrl_control_init() reads it when
 * filling rdt_resource caps.  The hot path (resctrl_arch_rmid_read) keeps
 * its per-domain cbqri_resctrl_dom::paired_bc cache because the lookup
 * key there is (domain, event), not just event.  Sized to mirror MPAM
 * (drivers/resctrl/mpam_resctrl.c): only events CBQRI can actually back
 * occupy a slot, so Intel PMT events do not bloat the array.
 */
struct cbqri_resctrl_mon {
	struct cbqri_controller *ctrl;
};

#define CBQRI_MAX_EVENT QOS_L3_MBM_TOTAL_EVENT_ID
static struct cbqri_resctrl_mon cbqri_resctrl_counters[CBQRI_MAX_EVENT + 1];

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
	 * CPU nor disables preemption - safe under PREEMPT_RT and on
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

	lockdep_assert_held(&ctrl->lock);

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

	/*
	 * CBQRI Table 1 encodes AT field as 0=Data, 1=Code (the rest are
	 * Reserved or Custom).  Always program the AT field on controllers
	 * that report supports_alloc_at_code, mapping the caller's
	 * resctrl_conf_type to the matching encoding; the wrapper
	 * cbqri_apply_cache_config() decides whether one or two
	 * CONFIG_LIMIT operations are needed when resctrl has CDP
	 * disabled but the controller supports AT differentiation.
	 *
	 * On controllers that do NOT report supports_alloc_at_code the
	 * AT field is reserved-as-zero and the operation acts on both
	 * halves; leave the bits clear in that case.  See
	 * cbqri_resctrl_pick_caches() for the pick-time mismatch check
	 * that prevents resctrl from advertising CDP on a CC pool whose
	 * members disagree on AT support.
	 */
	reg &= ~CBQRI_CONTROL_REGISTERS_AT_MASK;
	if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY &&
	    ctrl->cc.supports_alloc_at_code) {
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
 * Perform capacity usage monitoring operation on capacity controller.
 * Caller must hold ctrl->lock.
 */
static int cbqri_cc_mon_op(struct cbqri_controller *ctrl, int operation,
			   int mcid, int evt_id, u64 *out_reg)
{
	int reg_offset = CBQRI_CC_MON_CTL_OFF;
	u64 reg;

	lockdep_assert_held(&ctrl->lock);

	if (ctrl->faulted)
		return -EIO;

	/*
	 * Read-modify-write with pre-busy poll, mirroring
	 * cbqri_cc_alloc_op().  Without this, a write issued while the
	 * controller is still BUSY from a firmware op would either be
	 * silently dropped or make the post-write cbqri_wait_busy_flag()
	 * return the firmware op's STATUS instead of ours, which on a
	 * non-SUCCESS firmware result would set ctrl->faulted=true and
	 * permanently disable the controller.  Reading first also
	 * preserves WPRI bit positions that the spec defines with the
	 * same layout as cc_alloc_ctl.
	 */
	reg = ioread64(ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout before starting operation\n");
		return -EIO;
	}
	reg &= ~CBQRI_MON_CTL_OP_MASK;
	reg |= FIELD_PREP(CBQRI_MON_CTL_OP_MASK, operation);
	reg &= ~CBQRI_MON_CTL_MCID_MASK;
	reg |= FIELD_PREP(CBQRI_MON_CTL_MCID_MASK, mcid);
	reg &= ~CBQRI_MON_CTL_EVT_ID_MASK;
	reg |= FIELD_PREP(CBQRI_MON_CTL_EVT_ID_MASK, evt_id);
	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout\n");
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
 *
 * On controllers that support AT differentiation (supports_alloc_at_code)
 * but with resctrl CDP disabled for this cache level, the schemata write
 * carries a single value that must apply to both halves.  CBQRI Table 1
 * encodes AT only as 0=Data and 1=Code (no "all access types" value), so
 * keeping the halves in sync requires a second CONFIG_LIMIT with the
 * other AT.  When CDP is enabled, resctrl issues separate writes per
 * type and a single CONFIG_LIMIT per call is correct.  Controllers that
 * do not support AT (supports_alloc_at_code=false) treat the field as
 * reserved-zero so a single CONFIG_LIMIT covers the whole cache.
 */
static int cbqri_apply_cache_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				    enum resctrl_conf_type type, u64 cbm)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	bool cdp_active;
	int err = 0;
	u64 reg;

	mutex_lock(&ctrl->lock);

	if (ctrl->cache.cache_level == 2)
		cdp_active = cbqri_resctrl_resources[RDT_RESOURCE_L2].cdp_enabled;
	else if (ctrl->cache.cache_level == 3)
		cdp_active = cbqri_resctrl_resources[RDT_RESOURCE_L3].cdp_enabled;
	else
		cdp_active = false;

	/* Set capacity block mask (cc_block_mask) */
	cbqri_set_cbm(ctrl, cbm);

	/* Capacity config limit operation for the AT half implied by @type */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT, closid, type);
	if (err < 0) {
		pr_err("operation failed: err=%d\n", err);
		goto out;
	}

	/*
	 * CDP-off mirror: on AT-capable controllers, also program the
	 * other AT half with the same mask so the two halves stay in sync.
	 */
	if (ctrl->cc.supports_alloc_at_code && !cdp_active) {
		enum resctrl_conf_type other =
			(type == CDP_CODE) ? CDP_DATA : CDP_CODE;

		cbqri_set_cbm(ctrl, cbm);
		err = cbqri_cc_alloc_op(ctrl,
					CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT,
					closid, other);
		if (err < 0) {
			pr_err("operation failed: err=%d\n", err);
			goto out;
		}
	}

	/* Clear cc_block_mask before read limit to verify op works */
	cbqri_set_cbm(ctrl, 0);

	/* Perform a capacity read limit operation to verify blockmask */
	err = cbqri_cc_alloc_op(ctrl, CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT, closid, type);
	if (err < 0) {
		pr_err("operation failed: err=%d\n", err);
		goto out;
	}

	/*
	 * Read capacity blockmask to verify it matches the requested config.
	 *
	 * cc_block_mask is a 64-bit MMIO register but resctrl exposes the
	 * CBM as a u32 and cbqri_probe_cc() rejects ncblks > 32, so @cbm is
	 * always a zero-extended u32 here.  Narrow the readback via
	 * lower_32_bits() (mirroring resctrl_arch_get_config()) so a
	 * non-zero reserved value in bits 32-63 does not spuriously fail
	 * the verify with -EIO.
	 */
	reg = ioread64(ctrl->base + CBQRI_CC_BLOCK_MASK_OFF);
	if (lower_32_bits(reg) != cbm) {
		pr_err("CBM verify mismatch (reg=%llx != cbm=%llx)\n",
		       reg, cbm);
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
	int reg_offset = CBQRI_BC_MON_CTL_OFF;
	u64 reg;

	lockdep_assert_held(&ctrl->lock);

	if (ctrl->faulted)
		return -EIO;

	/* Read-modify-write with pre-busy poll, mirroring cbqri_cc_mon_op(). */
	reg = ioread64(ctrl->base + reg_offset);
	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout before starting operation\n");
		return -EIO;
	}
	reg &= ~CBQRI_MON_CTL_OP_MASK;
	reg |= FIELD_PREP(CBQRI_MON_CTL_OP_MASK, operation);
	reg &= ~CBQRI_MON_CTL_MCID_MASK;
	reg |= FIELD_PREP(CBQRI_MON_CTL_MCID_MASK, mcid);
	reg &= ~CBQRI_MON_CTL_EVT_ID_MASK;
	reg |= FIELD_PREP(CBQRI_MON_CTL_EVT_ID_MASK, evt_id);
	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout\n");
		return -EIO;
	}

	if (FIELD_GET(CBQRI_MON_CTL_STATUS_MASK, reg) !=
	    CBQRI_BC_MON_CTL_STATUS_SUCCESS)
		return -EIO;

	if (out_reg)
		*out_reg = reg;

	return 0;
}

/*
 * 62-bit BC counter delta.  Inputs must be pre-masked to
 * CBQRI_BC_MON_CTR_VAL_CTR_MASK.  The shift promotes the modular
 * subtraction into 64-bit so a single wrap (cur < prev) yields the
 * correct delta rather than a near-2^62 nonsense result.  Multi-wrap
 * is detected by the caller via the hardware OVF bit (CBQRI 4.3):
 * on OVF=1 the read path re-arms and re-anchors, so this function
 * only needs to recover from at most one wrap.  Width hard-coded to
 * the spec maximum (62 bits); narrower implementations trigger OVF
 * more often but the re-anchor branch keeps the accumulator monotonic.
 */
static u64 cbqri_bc_mon_overflow(u64 prev_ctr, u64 cur_ctr)
{
	const unsigned int shift = 64 - 62;
	u64 chunks = (cur_ctr << shift) - (prev_ctr << shift);

	return chunks >> shift;
}

/* Perform bandwidth allocation control operation on bandwidth controller */
/* Caller must hold ctrl->lock. */
static int cbqri_bc_alloc_op(struct cbqri_controller *ctrl, int operation, int rcid)
{
	int reg_offset = CBQRI_BC_ALLOC_CTL_OFF;
	int status;
	u64 reg;

	lockdep_assert_held(&ctrl->lock);

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
	iowrite64(reg, ctrl->base + reg_offset);

	if (cbqri_wait_busy_flag(ctrl, reg_offset, &reg) < 0) {
		pr_err("BUSY timeout during operation\n");
		return -EIO;
	}

	status = FIELD_GET(CBQRI_CONTROL_REGISTERS_STATUS_MASK, reg);
	if (status != CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS) {
		pr_err("BC alloc op %d failed: status=%d\n",
		       operation, status);
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
				u64 val, bool *committed)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int ret;
	u64 reg;

	lockdep_assert_held(&ctrl->lock);

	/* Load current RCID state so the unmodified field is preserved */
	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
	if (ret < 0)
		return ret;

	set(ctrl, val);

	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_CONFIG_LIMIT, closid);
	if (ret < 0)
		return ret;

	/*
	 * CONFIG_LIMIT succeeded - hardware now holds @val.  Tell the
	 * caller so any per-CLOSID software cache it maintains can be
	 * updated regardless of whether the verify below passes.  A
	 * subsequent verify timeout returns -EIO but does not undo the
	 * commit; the caller's cache must reflect what hardware actually
	 * has, not what was asked for.
	 */
	if (committed)
		*committed = true;

	/*
	 * Pre-write a sentinel that cannot equal @val so a silent
	 * READ_LIMIT (status SUCCESS but no staging-register update)
	 * is detectable in the readback.  Using ~val works for any
	 * field width because FIELD_PREP() truncates to the mask, and
	 * for any N-bit field val != (~val mod 2^N) holds (their XOR
	 * is the all-ones value 2^N - 1).  Using a fixed 0 sentinel
	 * collides with val == 0, which is a legal MB_WGHT (Mweight)
	 * value.
	 */
	set(ctrl, ~val);

	ret = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
	if (ret < 0)
		return ret;

	reg = get(ctrl);
	if (reg != val) {
		pr_err("BC field verify mismatch (reg=0x%llx != val=%llu)\n",
		       reg, val);
		return -EIO;
	}

	return 0;
}

/*
 * Apply an Rbwb update for @closid, optionally enforcing the CBQRI section
 * 4.5 invariant sum(Rbwb across all RCIDs) <= MRBWB.  Sum is computed from
 * ctrl->rbwb_cache rather than re-reading hardware, so the whole sequence
 * (sum check + write + verify) needs one mutex acquisition and O(1) MMIO
 * round trips per call regardless of rcid_count.
 *
 * @check_sum=false is used by the coordinated init / reset walks where
 * intermediate sums may transiently exceed MRBWB; the caller guarantees
 * the final state honours the invariant.
 */
static int cbqri_apply_rbwb(struct cbqri_resctrl_dom *hw_dom, u32 closid,
			    u64 rbwb, bool check_sum)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	u32 i;
	int ret;

	if (rbwb > U16_MAX)
		return -EINVAL;

	mutex_lock(&ctrl->lock);

	if (check_sum && rbwb > 0) {
		u64 sum = rbwb;

		for (i = 0; i < ctrl->rcid_count; i++) {
			if (i == closid)
				continue;
			sum += ctrl->rbwb_cache[i];
		}
		if (sum > ctrl->bc.mrbwb) {
			/*
			 * User-reachable rejection on every malformed
			 * schemata write; ratelimit so a userspace loop
			 * cannot fill dmesg.  Reporting via
			 * info/last_cmd_status would be preferable but
			 * rdt_last_cmd_printf() is currently private to
			 * fs/resctrl; exposing it for arch drivers is a
			 * separate fs/resctrl change.
			 */
			pr_err_ratelimited("RBWB sum %llu exceeds MRBWB %u\n",
					   sum, ctrl->bc.mrbwb);
			ret = -EINVAL;
			goto out;
		}
	}

	{
		bool committed = false;

		ret = cbqri_apply_bc_field(hw_dom, closid,
					   cbqri_set_rbwb, cbqri_get_rbwb, rbwb,
					   &committed);
		/*
		 * CONFIG_LIMIT is the operation that commits to hardware;
		 * the subsequent READ_LIMIT verify is defensive.  If commit
		 * succeeded but verify failed (e.g. busy timeout on the
		 * readback), hardware has the new value and the cache must
		 * track it.  Otherwise a future check_sum=true walk would
		 * use the stale (lower) cache entry and let a write that
		 * exceeds MRBWB through.
		 */
		if (committed)
			ctrl->rbwb_cache[closid] = rbwb;
	}
out:
	mutex_unlock(&ctrl->lock);
	return ret;
}

static int cbqri_apply_mweight_config(struct cbqri_resctrl_dom *hw_dom, u32 closid,
				      u64 mweight)
{
	struct cbqri_controller *ctrl = hw_dom->hw_ctrl;
	int ret;

	mutex_lock(&ctrl->lock);
	ret = cbqri_apply_bc_field(hw_dom, closid,
				   cbqri_set_mweight, cbqri_get_mweight,
				   mweight, NULL);
	mutex_unlock(&ctrl->lock);
	return ret;
}

static int cbqri_probe_feature(struct cbqri_controller *ctrl, int reg_offset,
			       int operation, int *status, bool *access_type_supported)
{
	u64 reg, saved_reg;
	int at;

	/*
	 * Default the output to false so the status==0 (feature not
	 * implemented) path returns a deterministic value to the caller
	 * rather than leaving an uninitialised bool.
	 */
	*access_type_supported = false;

	/* Keep the initial register value to preserve the WPRI fields */
	reg = ioread64(ctrl->base + reg_offset);
	saved_reg = reg;

	/*
	 * Wait for any in-flight firmware-issued operation to finish before
	 * issuing our own write.  Mirrors cbqri_cc_alloc_op() / cbqri_bc_alloc_op()
	 * which use the read -> wait-BUSY -> modify -> write -> wait-BUSY
	 * pattern; without this pre-write poll a probe issued while the
	 * controller is still BUSY would either be silently dropped or
	 * make the post-write cbqri_wait_busy_flag() return the firmware
	 * operation's STATUS instead of the probe's.
	 */
	if (cbqri_wait_busy_flag(ctrl, reg_offset, &saved_reg) < 0) {
		pr_err("BUSY timeout before probe operation\n");
		return -EIO;
	}
	reg = saved_reg;

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
		/*
		 * Re-issue @operation with AT=CODE so the controller
		 * actually processes the request and decides whether to
		 * latch AT=CODE (supported) or reset it to 0 (unsupported).
		 * OP=0 here is not a defined CBQRI operation; with OP=0
		 * the write is a no-op on conformant hardware, AT readback
		 * stays 0, and supports_alloc_at_code is permanently false
		 * even on AT-capable controllers - silently disabling CDP.
		 */
		reg = saved_reg;
		reg &= ~CBQRI_CONTROL_REGISTERS_OP_MASK;
		reg |= FIELD_PREP(CBQRI_CONTROL_REGISTERS_OP_MASK, operation);
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
	 * ctrl->lock is held - mirror the BC's nbwblks guard.
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

	/*
	 * Resolve cache_size via cacheinfo before the mon-capable gate.
	 * cbqri_probe_controller() runs from qos_resctrl_setup() at
	 * late_initcall, after wait_event(wait_cacheinfo_ready) returns -
	 * cacheinfo's device_initcall_sync has populated every online CPU's
	 * cache topology by then.  cpus_read_lock keeps that topology stable
	 * across the lookup and satisfies lockdep_assert_cpus_held() inside
	 * get_cpu_cacheinfo_level().  cache.cpu_mask was filled at register
	 * time from PPTT and lists every CPU sharing this cache, so any
	 * online member is fine for the lookup; if every member is offline
	 * (no cacheinfo populated yet), cache_size stays 0 and the gate
	 * below disables mon for this CC.
	 */
	cpus_read_lock();
	if (!ctrl->cache.cache_size) {
		int cpu = cpumask_first_and(&ctrl->cache.cpu_mask, cpu_online_mask);

		if (cpu < nr_cpu_ids) {
			struct cacheinfo *ci;

			ci = get_cpu_cacheinfo_level(cpu, ctrl->cache.cache_level);
			if (ci)
				ctrl->cache.cache_size = ci->size;
		}
	}
	cpus_read_unlock();

	/* Probe monitoring features */
	err = cbqri_probe_feature(ctrl, CBQRI_CC_MON_CTL_OFF,
				  CBQRI_CC_MON_CTL_OP_READ_COUNTER, &status,
				  &has_mon_at_code);
	if (err)
		return err;

	if (status == CBQRI_CC_MON_CTL_STATUS_SUCCESS) {
		/*
		 * Occupancy is reported to userspace in bytes, computed
		 * as cache_size * counter / ncblks (see
		 * resctrl_arch_rmid_read()).  If cacheinfo did not give us
		 * a cache_size, leave mon_capable=false so the file is not
		 * exposed at all rather than silently returning 0.
		 */
		if (!ctrl->cache.cache_size) {
			pr_warn("CC @%pa: cache_size unknown, occupancy monitoring disabled\n",
				&ctrl->addr);
		} else {
			ctrl->mon_capable = true;
		}
	}

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
	bool has_mon_at_code = false;
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

	/*
	 * rcid_count comes from firmware (RQSC).  rcid_count == 0 with
	 * a BC that reports allocation support is malformed: kcalloc(0)
	 * below returns ZERO_SIZE_PTR (~0x10), which passes the NULL
	 * check, and the first cbqri_apply_rbwb() oopses on a write to
	 * that address.  The mrbwb < rcid_count check below also fails
	 * to catch this because both promote to u32 and 0 < 0 is false.
	 */
	if (!ctrl->rcid_count) {
		pr_err("bandwidth controller has rcid_count=0\n");
		return -EINVAL;
	}

	/*
	 * The reset path in resctrl_arch_reset_all_ctrls() seeds RCID 0's
	 * Rbwb with mrbwb - (rcid_count - 1), which underflows when mrbwb
	 * does not cover at least one block per RCID.  Reject such a
	 * controller at probe so resctrl never sees an inconsistent
	 * max_bw < min_bw resource.
	 */
	if (ctrl->bc.mrbwb < ctrl->rcid_count) {
		pr_err("bandwidth controller has mrbwb=%u < rcid_count=%u, rejecting\n",
		       ctrl->bc.mrbwb, ctrl->rcid_count);
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

		/*
		 * Allocate the per-RCID Rbwb cache used by cbqri_apply_rbwb()
		 * to validate sum(Rbwb) <= MRBWB without re-issuing READ_LIMIT
		 * for every RCID.  Initialised to zero (matches MB_MIN's
		 * default of min_bw via @default_to_min); the cache is updated
		 * in lockstep with each successful CONFIG_LIMIT.
		 */
		ctrl->rbwb_cache = kcalloc(ctrl->rcid_count,
					   sizeof(*ctrl->rbwb_cache),
					   GFP_KERNEL);
		if (!ctrl->rbwb_cache)
			return -ENOMEM;
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

	/*
	 * Reject firmware-supplied mappings smaller than the register
	 * span the driver actually touches.  Without this, ioremap()
	 * would succeed and a subsequent ioread64/iowrite64 at e.g.
	 * CBQRI_CC_BLOCK_MASK_OFF (0x20) would walk past the end of
	 * the mapping.
	 */
	if (ctrl->size < CBQRI_CTRL_MIN_REG_SPAN) {
		pr_warn("controller at %pa: size %pa < minimum 0x%x, skipping\n",
			&ctrl->addr, &ctrl->size, CBQRI_CTRL_MIN_REG_SPAN);
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
	 * max_rmid is used by resctrl_arch_system_num_rmid_idx() and
	 * must reflect the smallest MCID space across the controllers
	 * that actually feed the monitoring path.  RQSC supplies an
	 * mcid_count for every controller regardless of its hardware
	 * mon-capability, so a non-mon-capable controller's value
	 * (potentially zero) would otherwise clamp the global minimum
	 * and break monitoring on the controllers that do support it.
	 */
	if (ctrl->mon_capable)
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
 * the only honest way to surface BC counters as mbm_total_bytes at L3 scope
 * is to require that there is exactly one BC, so all memory traffic
 * observed at the LLC necessarily flows through it.  If the platform
 * exposes zero or more than one mon-capable BC, no L3 gets a paired
 * BC and mbm_total_bytes is not advertised.
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
	if (rid != RDT_RESOURCE_L2 && rid != RDT_RESOURCE_L3)
		return false;
	return cbqri_resctrl_resources[rid].cdp_enabled;
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level rid, bool enable)
{
	struct cbqri_resctrl_res *cbqri_res;

	if (rid != RDT_RESOURCE_L2 && rid != RDT_RESOURCE_L3)
		return -ENODEV;

	cbqri_res = &cbqri_resctrl_resources[rid];
	if (!cbqri_res->resctrl_res.cdp_capable)
		return -ENODEV;

	cbqri_res->cdp_enabled = enable;
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
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	struct cbqri_controller *bc;
	struct rdt_ctrl_domain *d;
	u64 ctr_val;
	int err;

	resctrl_arch_rmid_read_context_check();

	/*
	 * Each event-id branch takes a sleeping mutex on the owning
	 * controller (1-ms busy-wait per CBQRI op).  Honour the
	 * resctrl_arch_rmid_read() contract: if irqs are disabled (e.g.
	 * smp_call_function_any() from mon_event_read() on nohz_full)
	 * we cannot sleep, so fail fast and let the caller fall back.
	 */
	if (irqs_disabled())
		return -EIO;

	switch (eventid) {
	case QOS_L3_OCCUP_EVENT_ID:
		/*
		 * The monitoring domain shares the same id as the control
		 * domain.  Find the control domain to get the hw_ctrl pointer.
		 */
		d = (struct rdt_ctrl_domain *)resctrl_find_domain(&r->ctrl_domains,
								  hdr->id, NULL);
		if (!d)
			return -ENOENT;

		hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
		ctrl = hw_dom->hw_ctrl;

		mutex_lock(&ctrl->lock);

		/*
		 * Each MCID is armed with the Occupancy event at init
		 * (qos_init_mon_counters) and re-armed by
		 * resctrl_arch_reset_rmid() on RMID recycle.  Pass
		 * EVT_ID=Occupancy so READ_COUNTER's EVT_ID field matches
		 * the configured event rather than relying on
		 * sticky-last-configured-event semantics that the CBQRI
		 * register definition does not guarantee.
		 */
		err = cbqri_cc_mon_op(ctrl, CBQRI_CC_MON_CTL_OP_READ_COUNTER,
				      rmid, CBQRI_CC_EVT_ID_OCCUPANCY, NULL);
		if (err)
			goto out_cc;

		ctr_val = ioread64(ctrl->base + CBQRI_CC_MON_CTL_VAL_OFF);

		/*
		 * Convert from capacity blocks to bytes.  Multiply before
		 * dividing so a non-power-of-2 ncblks does not truncate the
		 * intermediate result; cache_size and ctr_val both fit in
		 * u64 with room to spare (cache_size <= a few GiB, ctr_val
		 * is bounded by ncblks).
		 */
		*val = (u64)ctrl->cache.cache_size * ctr_val / ctrl->cc.ncblks;
out_cc:
		mutex_unlock(&ctrl->lock);
		return err;

	case QOS_L3_MBM_TOTAL_EVENT_ID:
		/*
		 * The L3 monitoring domain's id is the L3 cache id (see
		 * qos_resctrl_add_controller_domain()).  The matching ctrl
		 * domain's hw_dom->paired_bc was cached at add time so we
		 * don't walk cbqri_controllers on every read.
		 */
		d = (struct rdt_ctrl_domain *)resctrl_find_domain(&r->ctrl_domains,
								  hdr->id, NULL);
		if (!d)
			return -ENOENT;
		hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
		bc = hw_dom->paired_bc;
		if (!bc)
			return -ENOENT;
		if (WARN_ON_ONCE(!bc->mbm_total_states))
			return -EIO;
		if (rmid >= bc->mcid_count)
			return -ERANGE;

		mutex_lock(&bc->lock);
		/*
		 * Each MCID is armed with TOTAL_READ_WRITE at init
		 * (qos_init_bc_mon_counters()) and re-armed by the OVF
		 * recovery path below.  Pass EVT_ID=TOTAL_READ_WRITE so
		 * READ_COUNTER's EVT_ID field matches the configured
		 * event rather than relying on sticky-last-configured-
		 * event semantics that the CBQRI register definition
		 * does not guarantee.  Mirrors the CC READ_COUNTER call
		 * above which passes EVT_ID=OCCUPANCY for the same reason.
		 */
		err = cbqri_bc_mon_op(bc, CBQRI_BC_MON_CTL_OP_READ_COUNTER,
				      rmid, CBQRI_BC_EVT_ID_TOTAL_READ_WRITE,
				      NULL);
		if (err)
			goto out_bc;

		ctr_val = ioread64(bc->base + CBQRI_BC_MON_CTR_VAL_OFF);

		if (ctr_val & CBQRI_BC_MON_CTR_VAL_INVALID) {
			/*
			 * Hardware marked the counter invalid (CBQRI 4.3:
			 * controller could not establish an accurate count).
			 * Return the last good total and leave prev_ctr so
			 * the next valid sample resumes from there.
			 */
			*val = bc->mbm_total_states[rmid].chunks;
		} else if (ctr_val & CBQRI_BC_MON_CTR_VAL_OVF) {
			/*
			 * Hardware overflowed since the previous sample
			 * (CBQRI 4.3: OVF set on unsigned counter wrap; sticky
			 * until the next CONFIG_EVENT).  This shouldn't happen
			 * at the spec's full 62-bit CTR width with any
			 * reasonable userspace polling cadence, but is the
			 * expected steady-state symptom on implementations
			 * that populate fewer CTR bits.  Re-arm the counter
			 * (resets to 0 and clears OVF), accept the loss of
			 * one wrap-period of bytes, and re-anchor prev_ctr
			 * to 0.  Future deltas remain accurate until the
			 * next overflow.  The cbqri_bc_mon_overflow() shift
			 * trick can recover at most one wrap; here we do not
			 * know how many wraps occurred, so re-anchoring is
			 * the only honest behaviour.
			 */
			struct cbqri_bc_mon_state *s = &bc->mbm_total_states[rmid];

			pr_warn_ratelimited("BC@%pa MCID %u: CTR overflow, bandwidth count loses ~one wrap-period; consider a wider CTR or a faster poll cadence\n",
					    &bc->addr, rmid);
			/*
			 * Re-arm the counter (CONFIG_EVENT both resets to 0
			 * and clears OVF).  On failure cbqri_wait_busy_flag()
			 * has set bc->faulted, so every subsequent read on
			 * this controller will fast-fail with -EIO at the
			 * top of cbqri_bc_mon_op().  Surface the error here
			 * rather than returning the previously-successful
			 * READ_COUNTER's err=0: a "success" with stale
			 * prev_ctr would silently desync future deltas, and
			 * userspace that reads /sys/.../mbm_total_bytes
			 * deserves the same monotonic-or-error contract that
			 * a non-OVF read provides.
			 */
			err = cbqri_bc_mon_op(bc, CBQRI_BC_MON_CTL_OP_CONFIG_EVENT,
					      rmid, CBQRI_BC_EVT_ID_TOTAL_READ_WRITE,
					      NULL);
			if (err)
				goto out_bc;

			s->prev_ctr = 0;
			*val = s->chunks;
		} else {
			struct cbqri_bc_mon_state *s = &bc->mbm_total_states[rmid];
			u64 cur = ctr_val & CBQRI_BC_MON_CTR_VAL_CTR_MASK;

			s->chunks  += cbqri_bc_mon_overflow(s->prev_ctr, cur);
			s->prev_ctr = cur;
			*val        = s->chunks;
		}
out_bc:
		mutex_unlock(&bc->lock);
		return err;

	default:
		return -EINVAL;
	}
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 closid, u32 rmid, enum resctrl_event_id eventid)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	struct cbqri_controller *bc;
	struct rdt_ctrl_domain *cd;

	/*
	 * Mirrors the resctrl_arch_rmid_read() guard: this path takes a
	 * sleeping ctrl->lock, but mon_event_count() can dispatch via
	 * smp_call_function_any() from rr->first reads on nohz_full CPUs,
	 * landing here with IRQs disabled.  Bail rather than mutex_lock()
	 * in atomic context.
	 */
	if (irqs_disabled())
		return;

	switch (eventid) {
	case QOS_L3_OCCUP_EVENT_ID:
		cd = (struct rdt_ctrl_domain *)resctrl_find_domain(&r->ctrl_domains,
								   d->hdr.id, NULL);
		if (!cd)
			return;

		hw_dom = container_of(cd, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
		ctrl = hw_dom->hw_ctrl;

		mutex_lock(&ctrl->lock);
		/*
		 * Re-arm CONFIG_EVENT with EVT_ID=OCCUPANCY (rather than
		 * EVT_ID=None) to zero the counter while keeping the MCID
		 * counting.  resctrl invokes this on RMID recycle when the
		 * MCID is reassigned to a new monitoring group; if we cleared
		 * the event configuration, qos_init_mon_counters() (which
		 * runs once at domain online) would not re-arm and the new
		 * group's resctrl_arch_rmid_read() would observe a stuck
		 * zero forever.
		 */
		if (cbqri_cc_mon_op(ctrl, CBQRI_CC_MON_CTL_OP_CONFIG_EVENT,
				    rmid, CBQRI_CC_EVT_ID_OCCUPANCY, NULL))
			pr_warn_ratelimited("CC@%pa MCID %u: occupancy reset failed\n",
					    &ctrl->addr, rmid);
		mutex_unlock(&ctrl->lock);
		return;

	case QOS_L3_MBM_TOTAL_EVENT_ID:
		cd = (struct rdt_ctrl_domain *)resctrl_find_domain(&r->ctrl_domains,
								   d->hdr.id, NULL);
		if (!cd)
			return;
		hw_dom = container_of(cd, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
		bc = hw_dom->paired_bc;
		if (!bc)
			return;
		if (WARN_ON_ONCE(!bc->mbm_total_states))
			return;
		if (rmid >= bc->mcid_count)
			return;

		mutex_lock(&bc->lock);
		/*
		 * CONFIG_EVENT both resets and re-arms.  Skip the accumulator
		 * memset on failure - a stale hardware counter X with
		 * prev_ctr=0 would inject overflow(0, X) on the next read.
		 */
		if (!cbqri_bc_mon_op(bc, CBQRI_BC_MON_CTL_OP_CONFIG_EVENT,
				     rmid, CBQRI_BC_EVT_ID_TOTAL_READ_WRITE,
				     NULL))
			memset(&bc->mbm_total_states[rmid], 0,
			       sizeof(*bc->mbm_total_states));
		mutex_unlock(&bc->lock);
		return;

	default:
		return;
	}
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

	/* Bound by max_rmid (system-wide minimum mcid_count). */
	for (i = 0; i < max_rmid; i++) {
		resctrl_arch_reset_rmid(r, d, 0, i, QOS_L3_OCCUP_EVENT_ID);
		/* mbm_total_bytes reset is a no-op for L3s without a paired BC. */
		resctrl_arch_reset_rmid(r, d, 0, i, QOS_L3_MBM_TOTAL_EVENT_ID);
	}
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	struct cbqri_resctrl_res *hw_res;
	struct cbqri_resctrl_dom *dom;
	struct rdt_ctrl_domain *d;
	enum resctrl_conf_type t;
	u32 default_ctrl;
	int i;

	lockdep_assert_cpus_held();

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	default_ctrl = resctrl_get_default_ctrl(r);

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		dom = container_of(d, struct cbqri_resctrl_dom,
				   resctrl_ctrl_dom);
		switch (r->rid) {
		case RDT_RESOURCE_MB_MIN:
			/*
			 * CBQRI section 4.5: Rbwb >= 1, sum(Rbwb) <= MRBWB.
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
			for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
				u32 rcid = (i + 1) % hw_res->ctrl->rcid_count;
				u64 rbwb = (rcid == 0) ?
					dom->hw_ctrl->bc.mrbwb - (hw_res->ctrl->rcid_count - 1) : 1;
				int rerr;

				rerr = cbqri_apply_rbwb(dom, rcid, rbwb, false);
				if (rerr)
					pr_err_ratelimited("RBWB reset RCID %u failed (%d)\n",
							   rcid, rerr);
			}
			break;
		case RDT_RESOURCE_MB_WGHT:
			/*
			 * Use the same default as new groups get at mkdir
			 * (resctrl_get_default_ctrl() -> max_bw since Mweight
			 * has no sum constraint). All RCIDs start at max
			 * weight, giving equal work-conserving shares; users
			 * restrict groups by writing a smaller value.
			 */
			for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
				int rerr;

				rerr = cbqri_apply_mweight_config(dom, i, default_ctrl);
				if (rerr)
					pr_err_ratelimited("Mweight reset RCID %u failed (%d)\n",
							   i, rerr);
			}
			break;
		default:
			for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
				for (t = 0; t < CDP_NUM_TYPES; t++) {
					int rerr;

					rerr = resctrl_arch_update_one(r, d, i, t,
								       default_ctrl);
					if (rerr)
						pr_err_ratelimited("rid=%d reset RCID %u type %u failed (%d)\n",
								   r->rid, i, t, rerr);
				}
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
	int err = 0;

	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	if (!r->alloc_capable)
		return -EINVAL;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		err = cbqri_apply_cache_config(dom, closid, t, cfg_val);
		break;
	case RDT_RESOURCE_MB_MIN:
		/*
		 * sum(Rbwb) <= MRBWB validation lives inside cbqri_apply_rbwb()
		 * so that sum, validate, and apply happen under one mutex
		 * acquisition; otherwise a concurrent resctrl writer could
		 * change another RCID's Rbwb between the sum and the apply,
		 * silently over-allocating.
		 */
		err = cbqri_apply_rbwb(dom, closid, cfg_val, true);
		break;
	case RDT_RESOURCE_MB_WGHT:
		err = cbqri_apply_mweight_config(dom, closid, cfg_val);
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

		/*
		 * Read capacity block mask for RCID (closid).  cc_block_mask
		 * is a 64-bit MMIO register but resctrl exposes the CBM as a
		 * u32; cbqri_probe_cc() rejects ncblks > 32 so the upper 32
		 * bits are reserved zero by the spec.  Narrow explicitly via
		 * lower_32_bits() rather than implicit u64->u32 truncation
		 * so the assumption is visible at the read site.
		 */
		val = lower_32_bits(ioread64(ctrl->base + CBQRI_CC_BLOCK_MASK_OFF));
		break;

	case RDT_RESOURCE_MB_MIN:
		err = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (err < 0) {
			pr_err("operation failed: err=%d\n", err);
			break;
		}
		val = cbqri_get_rbwb(ctrl);
		break;

	case RDT_RESOURCE_MB_WGHT:
		err = cbqri_bc_alloc_op(ctrl, CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT, closid);
		if (err < 0) {
			pr_err("operation failed: err=%d\n", err);
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
	int err = 0;
	int i;

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
		/*
		 * RBWB walks RCIDs 1..N-1 first, then RCID 0 last, so the
		 * sum is always trending toward (rather than past) MRBWB
		 * once every RCID has been written.  Other resources do
		 * not need the reorder, so rcid stays as i for them.
		 */
		u32 rcid = (r->rid == RDT_RESOURCE_MB_MIN) ?
				((i + 1) % hw_res->ctrl->rcid_count) : i;

		switch (r->rid) {
		case RDT_RESOURCE_MB_MIN: {
			/*
			 * CBQRI section 4.5: Rbwb >= 1, sum(Rbwb) <= MRBWB.
			 * RCID 0 gets the remaining budget so the final sum
			 * equals MRBWB exactly.  Use the unchecked helper:
			 * during the walk, RCIDs not yet visited may still
			 * hold stale firmware values that would make the
			 * intermediate sum check spuriously fail.
			 */
			u64 rbwb = (rcid == 0) ?
				dom->hw_ctrl->bc.mrbwb - (hw_res->ctrl->rcid_count - 1) : 1;

			err = cbqri_apply_rbwb(dom, rcid, rbwb, false);
			break;
		}
		case RDT_RESOURCE_MB_WGHT:
			/*
			 * Match the new-group default from
			 * resctrl_get_default_ctrl(): max_bw, giving equal
			 * work-conserving shares across all RCIDs.
			 */
			err = cbqri_apply_mweight_config(dom, i,
							 resctrl_get_default_ctrl(r));
			break;
		default: {
			enum resctrl_conf_type t;

			/*
			 * Cache resources (L2/L3): seed both the DATA and CODE
			 * staged config slots so a later mount with -o cdp does
			 * not see stale firmware-reset values for the CODE side.
			 * Mirrors resctrl_arch_reset_all_ctrls() for the same
			 * resources.  CDP_NUM_TYPES is 1 on non-CDP-capable
			 * controllers, so this is a single-iteration loop in
			 * the common case.
			 */
			for (t = 0; t < CDP_NUM_TYPES; t++) {
				err = resctrl_arch_update_one(r, d, i, t,
							      resctrl_get_default_ctrl(r));
				if (err)
					break;
			}
			break;
		}
		}
		if (err)
			return err;
	}
	return 0;
}

/*
 * Walk cbqri_controllers and pick one capacity controller (CC) per cache
 * level (L2/L3) to back the corresponding RDT_RESOURCE_L*.  When more than
 * one CC sits at the same level (e.g. one per socket), they must agree on
 * rcid_count / ncblks / alloc_capable - a mismatch is fatal because resctrl
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
			/*
			 * Two CCs at the same cache level must agree on every
			 * cap that resctrl exposes globally.  supports_alloc_at_code
			 * gates AT=CODE writes inside cbqri_cc_alloc_op(), so a
			 * mixed pair (one supports AT, the other does not) would
			 * produce -EIO on schemata write to the non-AT CC after
			 * the user enables CDP.  Reject at pick time so the
			 * inconsistency is visible at boot, not only when the
			 * user mounts -o cdp.
			 */
			if (cbqri_res->ctrl->rcid_count != ctrl->rcid_count ||
			    cbqri_res->ctrl->cc.ncblks != ctrl->cc.ncblks ||
			    cbqri_res->ctrl->cc.supports_alloc_at_code !=
				    ctrl->cc.supports_alloc_at_code ||
			    cbqri_res->ctrl->alloc_capable != ctrl->alloc_capable ||
			    cbqri_res->ctrl->mon_capable != ctrl->mon_capable ||
			    cbqri_res->ctrl->mcid_count != ctrl->mcid_count) {
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
 * Walk cbqri_controllers and pick one bandwidth controller (BC) to back
 * both MB_MIN and MB_WGHT.  These are independent schemata exposed by
 * the same BC; they share a controller pointer and per-controller domain.
 * Multiple BCs (e.g. multi-MC SoC) must agree on rcid_count / mrbwb;
 * mismatch is fatal for the same reason as cbqri_resctrl_pick_caches().
 */
static int cbqri_resctrl_pick_bw_alloc(void)
{
	struct cbqri_resctrl_res *mn = &cbqri_resctrl_resources[RDT_RESOURCE_MB_MIN];
	struct cbqri_resctrl_res *mp = &cbqri_resctrl_resources[RDT_RESOURCE_MB_WGHT];
	struct cbqri_controller *ctrl;

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		if (ctrl->type != CBQRI_CONTROLLER_TYPE_BANDWIDTH)
			continue;
		if (!ctrl->alloc_capable)
			continue;

		if (mn->ctrl) {
			if (mn->ctrl->rcid_count != ctrl->rcid_count ||
			    mn->ctrl->bc.mrbwb != ctrl->bc.mrbwb) {
				pr_err("BW controllers have mismatched capabilities\n");
				return -EINVAL;
			}
			continue;
		}

		mn->ctrl = ctrl;
		mp->ctrl = ctrl;
	}

	return 0;
}

/*
 * Pick one controller per monitoring event.  The per-event mapping
 * in cbqri_resctrl_counters[] lets future events (MBM_LOCAL,
 * READ_ONLY, WRITE_ONLY) extend the table without touching the read
 * hot path.  QOS_L3_OCCUP_EVENT_ID is backed by the picked L3
 * capacity controller if it advertises mon_capable;
 * QOS_L3_MBM_TOTAL_EVENT_ID is backed by the only mon-capable
 * bandwidth controller (single-BC pairing).
 */
static void cbqri_resctrl_pick_counters(void)
{
	struct cbqri_resctrl_res *l3 = &cbqri_resctrl_resources[RDT_RESOURCE_L3];

	if (l3->ctrl && l3->ctrl->mon_capable)
		cbqri_resctrl_counters[QOS_L3_OCCUP_EVENT_ID].ctrl = l3->ctrl;

	cbqri_resctrl_counters[QOS_L3_MBM_TOTAL_EVENT_ID].ctrl =
		cbqri_find_only_mon_bc();
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

	switch (res->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		res->name = (res->rid == RDT_RESOURCE_L2) ? "L2" : "L3";
		res->schema_fmt = RESCTRL_SCHEMA_BITMAP;
		res->ctrl_scope = (res->rid == RDT_RESOURCE_L2) ?
				    RESCTRL_L2_CACHE : RESCTRL_L3_CACHE;
		res->cache.cbm_len = ctrl->cc.ncblks;
		/*
		 * No bits are pre-claimed by external agents on CBQRI: the
		 * full CBM is available for resctrl-managed exclusive
		 * allocation.  Reporting shareable_bits=0 lets the
		 * exclusivity-check helpers in fs/resctrl (and the L3_CAT
		 * selftest's get_mask_no_shareable() which computes
		 * "full_mask & ~shareable_bits") see the entire mask as
		 * available.  Mirrors the x86 convention where
		 * shareable_bits is a subset of cbm_mask covering only
		 * uncore agents (0xc0000 on Intel L3); on CBQRI no such
		 * agents exist.
		 */
		res->cache.shareable_bits = 0;
		res->cache.min_cbm_bits = 1;
		/*
		 * Mirror the controller's AT-CODE capability into the
		 * resctrl resource so the core can size schemata column
		 * widths correctly when the user mounts with -o cdp.
		 * Without this, mounting CDP on AT-capable hardware would
		 * produce malformed schemata output because the core would
		 * not reserve the 4 chars for the :CODE / :DATA suffix.
		 */
		res->cdp_capable = ctrl->cc.supports_alloc_at_code;

		if (ctrl->mon_capable && res->rid == RDT_RESOURCE_L3) {
			res->mon_scope = RESCTRL_L3_CACHE;
			res->mon.num_rmid = ctrl->mcid_count;
			resctrl_enable_mon_event(QOS_L3_OCCUP_EVENT_ID,
						 false, 0, NULL);

			/*
			 * Expose BC bandwidth monitoring as the L3's
			 * mbm_total_bytes event when a BC shares topology with
			 * this L3, mirroring MPAM's "MB on L3" mapping.
			 * The event is global; per-domain availability is
			 * decided in resctrl_arch_rmid_read().  Read the
			 * picked BC from cbqri_resctrl_counters[] rather
			 * than re-running cbqri_find_only_mon_bc().
			 */
			if (cbqri_resctrl_counters[QOS_L3_MBM_TOTAL_EVENT_ID].ctrl)
				resctrl_enable_mon_event(QOS_L3_MBM_TOTAL_EVENT_ID,
							 false, 0, NULL);

			/*
			 * Set mon_capable last so a partial init never leaves
			 * the resource visible to userspace as "ready".
			 */
			res->mon_capable = true;
		}
		break;

	case RDT_RESOURCE_MB_MIN:
		res->name = "MB_MIN";
		res->schema_fmt = RESCTRL_SCHEMA_RANGE;
		/*
		 * resctrl requires a cache scope for MBA-style domains.
		 * Use L3 as a proxy until the framework supports non-cache
		 * scopes for bandwidth resources.
		 */
		res->ctrl_scope = RESCTRL_L3_CACHE;
		/*
		 * CBQRI Rbwb is an integer block count, not a percentage
		 * with a linear-delay mapping.  delay_linear /
		 * arch_needs_linear are the MBA concept and do not apply;
		 * leave them at their zero-init values so bw_validate()
		 * does not reject writes.
		 */
		res->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
		res->membw.min_bw = 1;
		res->membw.max_bw = ctrl->bc.mrbwb;
		res->membw.bw_gran = 1;
		/*
		 * CBQRI section 4.5 caps sum(Rbwb across all RCIDs) at MRBWB.
		 * Enforcement lives in cbqri_apply_rbwb() (returns -EINVAL on
		 * overflow under the per-controller mutex, matching the
		 * existing schemata-write rejection convention).  Default new
		 * groups to min_bw so mkdir does not overflow the sum; max_bw
		 * remains the per-group upper bound enforced by bw_validate().
		 */
		res->membw.default_to_min = true;
		break;

	case RDT_RESOURCE_MB_WGHT:
		res->name = "MB_WGHT";
		res->schema_fmt = RESCTRL_SCHEMA_RANGE;
		res->ctrl_scope = RESCTRL_L3_CACHE;
		/* Mweight is a dimensionless ratio; no delay/linear concept. */
		res->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
		/*
		 * CBQRI section 4.5: Mweight is 0-255; 0 disables
		 * work-conserving, so the group gets only its Rbwb
		 * reservation with no opportunistic access to unreserved
		 * or unused bandwidth.  Weights have no sum constraint
		 * (they are ratios, not a budget).
		 */
		res->membw.min_bw = 0;
		res->membw.max_bw = 255;
		res->membw.bw_gran = 1;
		/*
		 * Equal opportunistic shares across all RCIDs at boot;
		 * userspace narrows individual groups by writing schemata.
		 * Leave @default_to_min false so resctrl_get_default_ctrl()
		 * defaults to @max_bw.
		 */
		break;

	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	/*
	 * Set alloc_capable last so a partial init never leaves the
	 * resource visible to userspace as "ready".
	 */
	res->alloc_capable = ctrl->alloc_capable;

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

/* Pre-arm every MCID with TOTAL_READ_WRITE so reads just snapshot. */
static int qos_init_bc_mon_counters(struct cbqri_controller *bc)
{
	int i, err;

	/*
	 * The single mon-capable BC is reachable from every L3 capacity
	 * controller via cbqri_find_only_mon_bc(), so this initializer is
	 * called once per L3 CC during qos_resctrl_setup().  On multi-L3
	 * single-BC platforms the second and later calls must NOT disturb
	 * accumulator state still in use by the first L3's monitoring; an
	 * unlocked memset of bc->mbm_total_states (or a re-arm via
	 * CONFIG_EVENT, which the spec defines as resetting the counter
	 * to 0) would race resctrl_arch_rmid_read() and silently zero the
	 * already-active byte totals.  Re-entry with state allocated is
	 * benign and would just leak.
	 */
	if (bc->mbm_total_states)
		return 0;

	/*
	 * Per-MCID software accumulator: each entry tracks the previous
	 * 62-bit hardware snapshot and the running 64-bit byte total.
	 * Allocated here rather than at probe so that capacity controllers
	 * and unpaired bandwidth controllers stay at zero footprint.
	 */
	bc->mbm_total_states = kcalloc(bc->mcid_count,
				       sizeof(*bc->mbm_total_states),
				       GFP_KERNEL);
	if (!bc->mbm_total_states)
		return -ENOMEM;

	for (i = 0; i < bc->mcid_count; i++) {
		mutex_lock(&bc->lock);
		err = cbqri_bc_mon_op(bc, CBQRI_BC_MON_CTL_OP_CONFIG_EVENT,
				      i, CBQRI_BC_EVT_ID_TOTAL_READ_WRITE, NULL);
		mutex_unlock(&bc->lock);
		if (err) {
			kfree(bc->mbm_total_states);
			bc->mbm_total_states = NULL;
			return err;
		}
	}
	return 0;
}

/* Protects ctrl_domain / mon_domain list mutations across CPU hotplug. */
static DEFINE_MUTEX(qos_domain_list_lock);

/*
 * Create, list-insert, and online a fresh ctrl_domain backing @ctrl on
 * resource @res, seeded with @cpu and identified by @dom_id.  Caller must
 * hold qos_domain_list_lock and must have already verified that no
 * existing ctrl_domain on @res carries this id.
 */
static struct rdt_ctrl_domain *qos_create_ctrl_domain(struct cbqri_controller *ctrl,
						      struct rdt_resource *res,
						      unsigned int cpu, int dom_id)
{
	struct rdt_ctrl_domain *domain;
	struct list_head *pos = NULL;
	int err;

	domain = qos_new_domain(ctrl);
	if (!domain)
		return ERR_PTR(-ENOMEM);

	cpumask_set_cpu(cpu, &domain->hdr.cpu_mask);
	domain->hdr.id = dom_id;

	err = qos_init_domain_ctrlval(res, domain);
	if (err)
		goto err_free;

	if (resctrl_find_domain(&res->ctrl_domains, dom_id, &pos)) {
		pr_err("duplicate ctrl_domain id %d for resource %s\n",
		       dom_id, res->name);
		err = -EEXIST;
		goto err_free;
	}
	if (pos)
		list_add_tail(&domain->hdr.list, pos);
	else
		list_add_tail(&domain->hdr.list, &res->ctrl_domains);

	err = resctrl_online_ctrl_domain(res, domain);
	if (err) {
		pr_err("failed to online ctrl_domain %d on %s\n",
		       dom_id, res->name);
		list_del(&domain->hdr.list);
		goto err_free;
	}

	return domain;

err_free:
	kfree(container_of(domain, struct cbqri_resctrl_dom, resctrl_ctrl_dom));
	return ERR_PTR(err);
}

/*
 * Add @cpu to the ctrl_domain on @res with id @dom_id, creating the
 * domain (the first-CPU-online case) if it does not yet exist.
 * Returns the resulting ctrl_domain, or ERR_PTR on failure.
 * Caller must hold qos_domain_list_lock.
 */
static struct rdt_ctrl_domain *
qos_attach_cpu_to_ctrl_domain(struct cbqri_controller *ctrl,
			      struct rdt_resource *res,
			      unsigned int cpu, int dom_id)
{
	struct rdt_ctrl_domain *domain;

	lockdep_assert_held(&qos_domain_list_lock);

	domain = (struct rdt_ctrl_domain *)
		resctrl_find_domain(&res->ctrl_domains, dom_id, NULL);
	if (domain) {
		cpumask_set_cpu(cpu, &domain->hdr.cpu_mask);
		return domain;
	}

	return qos_create_ctrl_domain(ctrl, res, cpu, dom_id);
}

/*
 * Add @cpu to the L3 mon_domain backing @ctrl, creating the domain
 * (and arming MCID counters / pairing with the system-wide mon BC) on
 * the first-CPU-online case.  The ctrl_domain for this @ctrl must have
 * already been attached on @res before this is called - the paired_bc
 * pointer is cached on cbqri_resctrl_dom and the mon_domain id matches
 * its ctrl_domain id (cache_id).
 *
 * Caller must hold qos_domain_list_lock.
 */
static int qos_attach_cpu_to_l3_mon(struct cbqri_controller *ctrl,
				    struct rdt_resource *res,
				    unsigned int cpu)
{
	struct rdt_l3_mon_domain *mon_dom;
	struct rdt_ctrl_domain *ctrl_dom;
	struct cbqri_resctrl_dom *hw_dom;
	struct list_head *mon_pos = NULL;
	int dom_id = ctrl->cache.cache_id;
	int err;

	lockdep_assert_held(&qos_domain_list_lock);

	mon_dom = (struct rdt_l3_mon_domain *)
		resctrl_find_domain(&res->mon_domains, dom_id, NULL);
	if (mon_dom) {
		cpumask_set_cpu(cpu, &mon_dom->hdr.cpu_mask);
		return 0;
	}

	ctrl_dom = (struct rdt_ctrl_domain *)
		resctrl_find_domain(&res->ctrl_domains, dom_id, NULL);
	if (!ctrl_dom) {
		pr_err("L3 mon attach for cpu %u: no ctrl_domain id %d\n",
		       cpu, dom_id);
		return -EINVAL;
	}

	mon_dom = kzalloc_obj(*mon_dom, GFP_KERNEL);
	if (!mon_dom)
		return -ENOMEM;

	mon_dom->hdr.id = dom_id;
	mon_dom->hdr.type = RESCTRL_MON_DOMAIN;
	mon_dom->hdr.rid = RDT_RESOURCE_L3;
	cpumask_set_cpu(cpu, &mon_dom->hdr.cpu_mask);
	INIT_LIST_HEAD(&mon_dom->hdr.list);

	if (resctrl_find_domain(&res->mon_domains, dom_id, &mon_pos)) {
		pr_err("duplicate L3 mon_domain id %d\n", dom_id);
		err = -EEXIST;
		goto err_free;
	}
	if (mon_pos)
		list_add_tail(&mon_dom->hdr.list, mon_pos);
	else
		list_add_tail(&mon_dom->hdr.list, &res->mon_domains);

	err = resctrl_online_mon_domain(res, &mon_dom->hdr);
	if (err)
		goto err_listdel;

	err = qos_init_mon_counters(ctrl);
	if (err)
		goto err_offline;

	/*
	 * Pair the sole mon-capable BC with this L3 domain so its combined
	 * read+write counter satisfies mbm_total_bytes reads.  The pairing is
	 * cached on cbqri_resctrl_dom; resctrl_arch_rmid_read() and
	 * resctrl_arch_reset_rmid() consult it on every hit.
	 *
	 * The BC is system-wide (cbqri_find_only_mon_bc() returns one
	 * controller for all L3 domains) and qos_init_bc_mon_counters()
	 * is idempotent, so a failure here is not "this domain doesn't
	 * get mbm_total_bytes" - it is "no domain ever will, and the BC
	 * is now faulted".  cbqri_resctrl_control_init() has already
	 * enabled QOS_L3_MBM_TOTAL_EVENT_ID globally; leaving this attach
	 * to return success would expose mbm_total_bytes to userspace where
	 * every read returns -ENOENT.  Fail the attach so the cpuhp callback
	 * surfaces the error.
	 */
	hw_dom = container_of(ctrl_dom, struct cbqri_resctrl_dom,
			      resctrl_ctrl_dom);
	hw_dom->paired_bc = cbqri_find_only_mon_bc();
	if (hw_dom->paired_bc) {
		err = qos_init_bc_mon_counters(hw_dom->paired_bc);
		if (err) {
			pr_err("BC @%pa: mon init failed (%d), mbm_total_bytes will be unusable\n",
			       &hw_dom->paired_bc->addr, err);
			hw_dom->paired_bc = NULL;
			goto err_offline;
		}
	}

	return 0;

err_offline:
	/*
	 * resctrl_online_mon_domain() above scheduled the mbm_over delayed
	 * work (resctrl_is_mbm_enabled() returns true once
	 * cbqri_resctrl_control_init() enabled QOS_L3_MBM_TOTAL_EVENT_ID).
	 * resctrl_offline_mon_domain() uses cancel_delayed_work() (not _sync)
	 * internally, so a worker already blocked on rdtgroup_mutex would not
	 * be drained before the kfree below frees the domain it dereferences.
	 * Drain explicitly here, mirroring the qos_resctrl_teardown() pattern.
	 * qos_init_bc_mon_counters() can take well over 1s for large
	 * mcid_count, so this race is practically reachable.
	 */
	cancel_delayed_work_sync(&mon_dom->cqm_limbo);
	cancel_delayed_work_sync(&mon_dom->mbm_over);
	resctrl_offline_mon_domain(res, &mon_dom->hdr);
err_listdel:
	list_del(&mon_dom->hdr.list);
err_free:
	kfree(mon_dom);
	return err;
}

/*
 * Bring up every resource-domain ID that @ctrl backs, attaching @cpu.
 * Routes through qos_attach_cpu_to_ctrl_domain() so first-cpu-online
 * lazily creates the rdt_ctrl_domain and subsequent online events just
 * set the cpu in cpu_mask.  Caller must hold qos_domain_list_lock.
 */
static int qos_attach_cpu_to_cap_ctrl(struct cbqri_controller *ctrl,
				      unsigned int cpu)
{
	struct cbqri_resctrl_res *cbqri_res;
	struct rdt_ctrl_domain *ctrl_dom;
	struct rdt_resource *res;
	enum resctrl_res_level rid;

	switch (ctrl->cache.cache_level) {
	case 2:
		rid = RDT_RESOURCE_L2;
		break;
	case 3:
		rid = RDT_RESOURCE_L3;
		break;
	default:
		pr_err("CC @%pa: unknown cache level %d\n",
		       &ctrl->addr, ctrl->cache.cache_level);
		return -ENODEV;
	}

	cbqri_res = &cbqri_resctrl_resources[rid];
	res = &cbqri_res->resctrl_res;

	ctrl_dom = qos_attach_cpu_to_ctrl_domain(ctrl, res, cpu,
						 ctrl->cache.cache_id);
	if (IS_ERR(ctrl_dom))
		return PTR_ERR(ctrl_dom);

	if (ctrl->mon_capable && ctrl->cache.cache_level == 3)
		return qos_attach_cpu_to_l3_mon(ctrl, res, cpu);

	return 0;
}

static int qos_attach_cpu_to_bw_ctrl(struct cbqri_controller *ctrl,
				     unsigned int cpu)
{
	struct rdt_resource *res_min =
		&cbqri_resctrl_resources[RDT_RESOURCE_MB_MIN].resctrl_res;
	struct rdt_resource *res_prop =
		&cbqri_resctrl_resources[RDT_RESOURCE_MB_WGHT].resctrl_res;
	struct rdt_ctrl_domain *dom;

	dom = qos_attach_cpu_to_ctrl_domain(ctrl, res_min, cpu,
					    ctrl->mem.prox_dom);
	if (IS_ERR(dom))
		return PTR_ERR(dom);

	dom = qos_attach_cpu_to_ctrl_domain(ctrl, res_prop, cpu,
					    ctrl->mem.prox_dom);
	if (IS_ERR(dom))
		return PTR_ERR(dom);

	return 0;
}

/*
 * Clear @cpu from every ctrl_domain on @res that lists it.  When the
 * last CPU of a domain leaves, the domain is offlined, list-deleted,
 * and freed.  Caller must hold qos_domain_list_lock.
 */
static void qos_detach_cpu_from_ctrl_domains(struct rdt_resource *res,
					     unsigned int cpu)
{
	struct rdt_ctrl_domain *domain, *tmp;

	lockdep_assert_held(&qos_domain_list_lock);

	list_for_each_entry_safe(domain, tmp, &res->ctrl_domains, hdr.list) {
		if (!cpumask_test_cpu(cpu, &domain->hdr.cpu_mask))
			continue;
		cpumask_clear_cpu(cpu, &domain->hdr.cpu_mask);
		if (!cpumask_empty(&domain->hdr.cpu_mask))
			continue;
		resctrl_offline_ctrl_domain(res, domain);
		list_del(&domain->hdr.list);
		kfree(container_of(domain, struct cbqri_resctrl_dom,
				   resctrl_ctrl_dom));
	}
}

/*
 * Clear @cpu from the L3 mon_domain list on @res.  Last-CPU-leaves
 * triggers cancellation of the per-domain delayed work (cqm_limbo,
 * mbm_over) before resctrl_offline_mon_domain() runs - same reason
 * as the teardown path: cancel_delayed_work() inside
 * resctrl_offline_mon_domain() is not the _sync variant, and a
 * concurrently-running worker can otherwise dereference per-domain
 * state after we kfree() it.
 *
 * Caller must hold qos_domain_list_lock.
 */
static void qos_detach_cpu_from_l3_mon(struct rdt_resource *res,
				       unsigned int cpu)
{
	struct rdt_l3_mon_domain *mon_d, *mon_tmp;

	lockdep_assert_held(&qos_domain_list_lock);

	list_for_each_entry_safe(mon_d, mon_tmp, &res->mon_domains, hdr.list) {
		if (!cpumask_test_cpu(cpu, &mon_d->hdr.cpu_mask))
			continue;
		cpumask_clear_cpu(cpu, &mon_d->hdr.cpu_mask);
		if (!cpumask_empty(&mon_d->hdr.cpu_mask))
			continue;
		cancel_delayed_work_sync(&mon_d->cqm_limbo);
		cancel_delayed_work_sync(&mon_d->mbm_over);
		resctrl_offline_mon_domain(res, &mon_d->hdr);
		list_del(&mon_d->hdr.list);
		kfree(mon_d);
	}
}

/*
 * Walk every probed CBQRI controller and accumulate per-resource and
 * system-wide capability flags into cbqri_resctrl_resources[] and the
 * exposed_* globals.  Run after cbqri_resctrl_pick_*() has filtered
 * heterogeneous-CDP sets at the same cache level, so any one CC that
 * still reports supports_alloc_at_code faithfully implies the picked
 * pool at that level does.
 */
static void qos_resctrl_accumulate_caps(void)
{
	struct cbqri_controller *ctrl;

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		if (ctrl->type != CBQRI_CONTROLLER_TYPE_CAPACITY)
			continue;

		/*
		 * Monitor-only CCs (mcid_count > 0, rcid_count == 0) are
		 * not supported in this revision: the L3 mon_domain attach
		 * path is gated on a paired ctrl_domain because
		 * cbqri_resctrl_pick_caches() does not set up rdt_resource
		 * fields for an unpicked rid.  Surface as a warn_once so
		 * distros notice that monitoring on this controller is
		 * unavailable.  Lifting this requires a fs/resctrl change
		 * to allow an L3 mon_domain to register without a paired
		 * ctrl_domain.
		 */
		if (!ctrl->alloc_capable) {
			pr_warn_once("CC @%pa: monitor-only controller skipped (mon support pending fs/resctrl change)\n",
				     &ctrl->addr);
			continue;
		}

		if (ctrl->mon_capable && ctrl->cache.cache_level == 3)
			exposed_mon_capable = true;
	}
}

/* Set after resctrl_init() succeeds; gates resctrl_exit() in teardown. */
static bool qos_resctrl_inited;

/*
 * Free every per-resource ctrl_domain and mon_domain registered through
 * qos_resctrl_setup(), then - if resctrl_init() was reached - tear
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

	/*
	 * Serialise the per-rid mon/ctrl domain free loop against
	 * cpuhp callbacks (qos_resctrl_offline_cpu / online_cpu walk
	 * the same lists under qos_domain_list_lock).  cpus_read_lock()
	 * additionally blocks new cpuhp transitions for the duration
	 * of teardown.  The userspace-vs-list-walk race that fs/resctrl
	 * mediates with rdtgroup_mutex is a framework-level concern;
	 * driver-side we only need to exclude the cpuhp path.
	 */
	cpus_read_lock();
	mutex_lock(&qos_domain_list_lock);

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct rdt_l3_mon_domain *mon_d, *mon_tmp;

		res = &cbqri_resctrl_resources[rid];
		list_for_each_entry_safe(mon_d, mon_tmp,
					 &res->resctrl_res.mon_domains, hdr.list) {
			/*
			 * Drain mon_d's delayed work before kfree:
			 * resctrl_offline_mon_domain() uses non-_sync
			 * cancel, so a worker that has already taken its
			 * mutex must complete before either fs/resctrl
			 * frees per-domain state or this loop kfrees
			 * mon_d.  Same reasoning as in
			 * qos_attach_cpu_to_l3_mon().
			 */
			cancel_delayed_work_sync(&mon_d->cqm_limbo);
			cancel_delayed_work_sync(&mon_d->mbm_over);

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

	mutex_unlock(&qos_domain_list_lock);
	cpus_read_unlock();

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
	 * error - resctrl exposes one set of caps per rid.
	 */
	err = cbqri_resctrl_pick_caches();
	if (err)
		goto err_free_controllers_list;
	err = cbqri_resctrl_pick_bw_alloc();
	if (err)
		goto err_free_controllers_list;
	cbqri_resctrl_pick_counters();

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
	 * Phase 4: derive per-resource and system-wide capability flags
	 * (cdp_capable, exposed_mon_capable).  rdt_ctrl_domains and the L3
	 * rdt_l3_mon_domain are NOT created here: that responsibility moves
	 * to the cpuhp callbacks (qos_resctrl_online_cpu /
	 * qos_resctrl_offline_cpu) so domain->hdr.cpu_mask only ever
	 * reflects the online subset of each controller's static cache /
	 * memory cpu_mask.  cpuhp_setup_state() in qos_arch_late_init()
	 * replays online events for all already-online CPUs after this
	 * function returns, populating the lists incrementally.
	 */
	qos_resctrl_accumulate_caps();
	pr_debug("alloc=%d mon=%d cdp_l2=%d cdp_l3=%d\n",
		 exposed_alloc_capable, exposed_mon_capable,
		 cbqri_resctrl_resources[RDT_RESOURCE_L2].resctrl_res.cdp_capable,
		 cbqri_resctrl_resources[RDT_RESOURCE_L3].resctrl_res.cdp_capable);

	err = resctrl_init();
	if (err)
		goto err_free_controllers_list;
	qos_resctrl_inited = true;

	return 0;

err_free_controllers_list:
	qos_resctrl_teardown();
	return err;
}

/*
 * Walk every probed controller and, for each whose static cache /
 * memory cpu_mask covers @cpu, route the cpu into the matching
 * resctrl resource's domain via qos_attach_cpu_to_*().  This mirrors
 * x86 domain_add_cpu_ctrl/domain_add_cpu_mon: the rdt_ctrl_domain
 * (and L3 rdt_l3_mon_domain) is created on first-CPU-online and
 * subsequent online events just set the cpu in the existing
 * cpu_mask.  Returns 0 on success or a partial-attach error on the
 * first failure; the cpuhp framework will surface the error and
 * roll the cpu back to its prior state.
 */
int qos_resctrl_online_cpu(unsigned int cpu)
{
	struct cbqri_controller *ctrl;
	int err = 0;

	/*
	 * Hardware resets CSR_SRMCFG to 0 when a CPU is offlined/re-onlined.
	 * Zero the cached value so the next context switch always re-programs
	 * the CSR rather than skipping it as "unchanged".
	 */
	per_cpu(cpu_srmcfg, cpu) = 0;

	mutex_lock(&qos_domain_list_lock);

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		if (!ctrl->alloc_capable)
			continue;

		switch (ctrl->type) {
		case CBQRI_CONTROLLER_TYPE_CAPACITY:
			if (!cpumask_test_cpu(cpu, &ctrl->cache.cpu_mask))
				continue;
			err = qos_attach_cpu_to_cap_ctrl(ctrl, cpu);
			break;
		case CBQRI_CONTROLLER_TYPE_BANDWIDTH:
			if (!cpumask_test_cpu(cpu, &ctrl->mem.cpu_mask))
				continue;
			err = qos_attach_cpu_to_bw_ctrl(ctrl, cpu);
			break;
		default:
			err = -ENODEV;
			break;
		}

		if (err) {
			pr_err("online cpu %u: ctrl @%pa attach failed (%d)\n",
			       cpu, &ctrl->addr, err);
			break;
		}
	}

	mutex_unlock(&qos_domain_list_lock);

	/*
	 * Only enroll the CPU into resctrl's per-CPU bookkeeping if every
	 * controller attach succeeded.  On partial failure the cpuhp framework
	 * will roll back via qos_resctrl_offline_cpu(), so adding this CPU to
	 * rdtgroup_default.cpu_mask now would let userspace observe the CPU
	 * with incomplete domain state for the duration of the rollback.
	 */
	if (!err)
		resctrl_online_cpu(cpu);
	return err;
}

/*
 * Symmetric tear-down of qos_resctrl_online_cpu().  Domain cpu_masks
 * are cleared BEFORE resctrl_offline_cpu() runs: that function calls
 * get_mon_domain_from_cpu() and mbm_setup_overflow_handler() to
 * migrate pending MBM work off the leaving CPU; if the bit is still
 * set, those helpers may pick the very CPU being torn down to host
 * the next overflow tick.  When the last CPU of a domain leaves,
 * resctrl_offline_*_domain() is invoked and the domain is freed.
 */
int qos_resctrl_offline_cpu(unsigned int cpu)
{
	struct rdt_resource *res;
	enum resctrl_res_level rid;

	mutex_lock(&qos_domain_list_lock);

	/*
	 * L3 mon_domains first.  resctrl_offline_mon_domain() inside
	 * qos_detach_cpu_from_l3_mon() drains the per-domain delayed
	 * work; doing this before the ctrl_domain on the same id is
	 * removed keeps the ordering matched to qos_resctrl_teardown().
	 */
	res = &cbqri_resctrl_resources[RDT_RESOURCE_L3].resctrl_res;
	qos_detach_cpu_from_l3_mon(res, cpu);

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		res = &cbqri_resctrl_resources[rid].resctrl_res;
		qos_detach_cpu_from_ctrl_domains(res, cpu);
	}

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
	kfree(ctrl->mbm_total_states);
	kfree(ctrl->rbwb_cache);
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
		int level;
		int err;

		ctrl->cache.cache_id = info->cache_id;

		level = find_acpi_cache_level_from_id(info->cache_id);
		if (level < 0) {
			pr_warn("Failed to resolve cache level for cache id 0x%x (%d), skipping\n",
				info->cache_id, level);
			cbqri_controller_destroy(ctrl);
			return level;
		}
		ctrl->cache.cache_level = level;

		/*
		 * cache_size is resolved lazily on first-cpu-online via
		 * get_cpu_cacheinfo_level() in qos_attach_cpu_to_cap_ctrl().
		 * cacheinfo is not populated yet at this discovery-time call
		 * site (still in acpi_arch_init() before late_initcall), and
		 * a sized lookup that needs cpus_read_lock is the wrong
		 * primitive at this point in boot anyway.  cache_size stays
		 * at 0 (kzalloc default) until the cpuhp callback fills it.
		 */

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
	 * failure path - including the resctrl_init() that happens
	 * inside it - via qos_resctrl_teardown().  Don't call
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
