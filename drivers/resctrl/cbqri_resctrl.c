// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/bitfield.h>
#include <linux/cacheinfo.h>
#include <linux/riscv_cbqri.h>
#include <linux/cpu.h>
#include <linux/cpufeature.h>
#include <linux/cpuhotplug.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/resctrl.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "cbqri_internal.h"

/* Cache resources carry a single DEF control. */
#define CBQRI_MAX_CTRLS_PER_RES	1

/*
 * struct cbqri_hw_ctrl - arch private wrapper around a resctrl control
 * @r_ctrl:	control properties exposed to fs/resctrl
 * @hw:		backing CBQRI controller (the backing CC backs a cache
 *		resource's single control)
 */
struct cbqri_hw_ctrl {
	struct resctrl_ctrl	r_ctrl;
	struct cbqri_controller	*hw;
};

struct cbqri_resctrl_res {
	struct cbqri_controller *ctrl;
	struct rdt_resource     resctrl_res;
	bool                    cdp_enabled;
	struct cbqri_hw_ctrl    ctrls[CBQRI_MAX_CTRLS_PER_RES];
	int                     nr_ctrls;
};

struct cbqri_resctrl_dom {
	struct rdt_ctrl_domain  resctrl_ctrl_dom;
	struct cbqri_controller *hw_ctrl;
};

static struct cbqri_resctrl_res cbqri_resctrl_resources[RDT_NUM_RESOURCES];

static bool exposed_alloc_capable;
static bool exposed_mon_capable;

/* Used by resctrl_arch_system_num_rmid_idx(). Narrowed by accumulate_caps. */
static u32 max_rmid = U32_MAX;

/* Protects ctrl_domain list mutations across CPU hotplug. */
static DEFINE_MUTEX(cbqri_domain_list_lock);

static struct rdt_ctrl_domain *
cbqri_find_ctrl_domain(struct list_head *h, int id)
{
	struct rdt_domain_hdr *hdr = resctrl_find_domain(h, id, NULL);

	return hdr ? container_of(hdr, struct rdt_ctrl_domain, hdr) : NULL;
}

/*
 * Return the first control of a resource. Cache resources carry exactly one
 * (the DEF control), whose domains the attach paths consult to reach the
 * backing controller. NULL if the resource has no control.
 */
static struct resctrl_ctrl *cbqri_first_ctrl(struct rdt_resource *r)
{
	return list_first_entry_or_null(&r->controls, struct resctrl_ctrl,
					entry);
}

static struct rdt_l3_mon_domain *
cbqri_find_l3_mon_domain(struct list_head *h, int id)
{
	struct rdt_domain_hdr *hdr = resctrl_find_domain(h, id, NULL);

	return hdr ? container_of(hdr, struct rdt_l3_mon_domain, hdr) : NULL;
}

static int cbqri_apply_cache_config_dom(struct cbqri_resctrl_dom *hw_dom,
					struct rdt_resource *r,
					u32 closid, enum resctrl_conf_type t,
					u64 cbm)
{
	struct cbqri_resctrl_res *hw_res =
		container_of(r, struct cbqri_resctrl_res, resctrl_res);
	struct cbqri_cc_config cfg = {
		.cbm = cbm,
		.at = (t == CDP_CODE) ? CBQRI_AT_CODE : CBQRI_AT_DATA,
		.cdp_enabled = hw_res->cdp_enabled,
	};

	return cbqri_apply_cache_config(hw_dom->hw_ctrl, closid, &cfg);
}

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return exposed_mon_capable;
}

bool resctrl_arch_get_cdp_enabled(struct rdt_resource *r)
{
	if (r->rid != RDT_RESOURCE_L2 && r->rid != RDT_RESOURCE_L3)
		return false;
	return cbqri_resctrl_resources[r->rid].cdp_enabled;
}

int resctrl_arch_set_cdp_enabled(struct rdt_resource *r,
				 struct resctrl_ctrl *ctrl, bool enable)
{
	struct cbqri_resctrl_res *cbqri_res;

	if (r->rid != RDT_RESOURCE_L2 && r->rid != RDT_RESOURCE_L3)
		return -ENODEV;

	cbqri_res = &cbqri_resctrl_resources[r->rid];
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

/*
 * fs/resctrl unconditionally references the symbols below before checking
 * mon_capable. They are stubs for features CBQRI does not yet support.
 */
bool resctrl_arch_is_evt_configurable(enum resctrl_event_id evt)
{
	return false;
}

void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r,
				 enum resctrl_event_id evtid)
{
	return NULL;
}

void resctrl_arch_mon_ctx_free(struct rdt_resource *r,
			       enum resctrl_event_id evtid, void *arch_mon_ctx)
{
}

void resctrl_arch_config_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			      enum resctrl_event_id evtid, u32 rmid, u32 closid,
			      u32 cntr_id, bool assign)
{
}

int resctrl_arch_cntr_read(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			   u32 unused, u32 rmid, int cntr_id,
			   enum resctrl_event_id eventid, u64 *val)
{
	return -EOPNOTSUPP;
}

bool resctrl_arch_mbm_cntr_assign_enabled(struct rdt_resource *r)
{
	return false;
}

int resctrl_arch_mbm_cntr_assign_set(struct rdt_resource *r, bool enable)
{
	return -EOPNOTSUPP;
}

void resctrl_arch_reset_cntr(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 unused, u32 rmid, int cntr_id,
			     enum resctrl_event_id eventid)
{
}

bool resctrl_arch_get_io_alloc_enabled(struct rdt_resource *r)
{
	return false;
}

int resctrl_arch_io_alloc_enable(struct rdt_resource *r,
				 struct resctrl_ctrl *ctrl, bool enable)
{
	return -EOPNOTSUPP;
}

void resctrl_arch_mon_event_config_read(void *info)
{
}

void resctrl_arch_mon_event_config_write(void *info)
{
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_l3_mon_domain *d,
			     u32 unused, u32 rmid, enum resctrl_event_id eventid)
{
}

void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_l3_mon_domain *d)
{
}

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain_hdr *hdr,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   void *arch_priv, u64 *val, void *arch_mon_ctx)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *ctrl;
	struct resctrl_ctrl *res_ctrl;
	struct rdt_ctrl_domain *d;
	u64 ctr_val;
	int err = 0;

	resctrl_arch_rmid_read_context_check();

	/*
	 * cbqri_mon_op() takes ctrl->lock sleeping mutex and polls
	 * BUSY for up to 1 ms, neither of which is safe under
	 * irqs_disabled().
	 */
	if (irqs_disabled())
		return -EIO;

	/*
	 * cbqri_domain_list_lock serialises the list walk against
	 * cbqri_detach_cpu_from_ctrl_domains().
	 */
	mutex_lock(&cbqri_domain_list_lock);

	res_ctrl = cbqri_first_ctrl(r);
	if (!res_ctrl) {
		mutex_unlock(&cbqri_domain_list_lock);
		return -ENOENT;
	}

	switch (eventid) {
	case QOS_L3_OCCUP_EVENT_ID:
		d = cbqri_find_ctrl_domain(&res_ctrl->domains, hdr->id);
		if (!d) {
			err = -ENOENT;
			break;
		}

		hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
		ctrl = hw_dom->hw_ctrl;

		mutex_lock(&ctrl->lock);

		/*
		 * MCIDs are armed with Occupancy once at init and free run.
		 * Pass EVT_ID explicitly as the CBQRI spec does not guarantee
		 * sticky-last-configured-event for READ_COUNTER.
		 */
		err = cbqri_mon_op(ctrl, CBQRI_CC_MON_CTL_OFF,
				   CBQRI_CC_MON_CTL_OP_READ_COUNTER,
				   rmid, CBQRI_CC_EVT_ID_OCCUPANCY, NULL);
		if (!err) {
			ctr_val = ioread64(ctrl->base + CBQRI_CC_MON_CTL_VAL_OFF);

			/*
			 * Capacity blocks to bytes. Multiply before divide
			 * so a non-power-of-2 ncblks doesn't truncate.
			 */
			*val = (u64)ctrl->cache.cache_size * ctr_val /
			       ctrl->cc.ncblks;
		}
		mutex_unlock(&ctrl->lock);
		break;

	default:
		err = -EINVAL;
		break;
	}

	mutex_unlock(&cbqri_domain_list_lock);
	return err;
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

void resctrl_arch_pre_mount(void)
{
	/* All controllers discovered at boot via late_initcall. Nothing to do. */
}

int resctrl_arch_update_one(struct rdt_resource *r, struct resctrl_ctrl *ctrl,
			    struct rdt_ctrl_domain *d, u32 closid,
			    enum resctrl_conf_type t, u32 cfg_val)
{
	struct cbqri_resctrl_dom *dom;

	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);

	if (!r->alloc_capable)
		return -EINVAL;

	if (ctrl->type == RESCTRL_CTRL_BITMAP)
		return cbqri_apply_cache_config_dom(dom, r, closid, t, cfg_val);

	switch (ctrl->name) {
	case RESCTRL_CTRL_NAME_MIN:
		/* sum(Rbwb) <= MRBWB validation runs inside cbqri_apply_rbwb(). */
		return cbqri_apply_rbwb(dom->hw_ctrl, closid, cfg_val, true);
	default:
		return -EINVAL;
	}
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	enum resctrl_conf_type t;
	struct rdt_ctrl_domain *d;
	struct resctrl_ctrl *ctrl;
	int err = 0;

	/* Walking ctrl->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	for_each_resource_ctrl(ctrl, r) {
		list_for_each_entry(d, &ctrl->domains, hdr.list) {
			for (t = 0; t < CDP_NUM_TYPES; t++) {
				cfg = &d->staged_config[t];
				if (!cfg->have_new_ctrl)
					continue;
				err = resctrl_arch_update_one(r, ctrl, d, closid,
							      t, cfg->new_ctrl);
				if (err)
					return err;
			}
		}
	}
	return err;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct resctrl_ctrl *ctrl,
			    struct rdt_ctrl_domain *d, u32 closid,
			    enum resctrl_conf_type type)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct cbqri_controller *hw;
	enum cbqri_at at;
	u32 val;
	int err;

	hw_dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	hw = hw_dom->hw_ctrl;
	val = resctrl_get_default_ctrlval(ctrl);

	if (!r->alloc_capable)
		return val;

	if (ctrl->type == RESCTRL_CTRL_BITMAP) {
		at = (type == CDP_CODE) ? CBQRI_AT_CODE : CBQRI_AT_DATA;
		err = cbqri_read_cache_config(hw, closid, at, &val);
		if (err < 0)
			val = resctrl_get_default_ctrlval(ctrl);
		return val;
	}

	switch (ctrl->name) {
	case RESCTRL_CTRL_NAME_MIN: {
		u64 rbwb;

		err = cbqri_read_rbwb(hw, closid, &rbwb);
		if (err == 0)
			val = (u32)rbwb;
		break;
	}
	default:
		break;
	}

	return val;
}

/*
 * RCID 0 carries the remaining MRBWB after every other RCID is seeded with
 * the minimum Rbwb of 1. cbqri_probe_bc() rejects a bandwidth controller
 * with mrbwb < rcid_count, so this subtraction cannot underflow.
 */
static u64 cbqri_rcid0_rbwb(struct cbqri_controller *ctrl)
{
	if (WARN_ON_ONCE(ctrl->bc.mrbwb < ctrl->rcid_count))
		return 1;
	return ctrl->bc.mrbwb - (ctrl->rcid_count - 1);
}

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	struct cbqri_resctrl_res *hw_res;
	struct cbqri_resctrl_dom *dom;
	struct rdt_ctrl_domain *d;
	struct resctrl_ctrl *ctrl;
	enum resctrl_conf_type t;
	u32 default_ctrl;
	int i;

	lockdep_assert_cpus_held();

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);

	if (!hw_res->ctrl)
		return;

	for_each_resource_ctrl(ctrl, r) {
		default_ctrl = resctrl_get_default_ctrlval(ctrl);

		list_for_each_entry(d, &ctrl->domains, hdr.list) {
			dom = container_of(d, struct cbqri_resctrl_dom,
					   resctrl_ctrl_dom);

			if (ctrl->type == RESCTRL_CTRL_BITMAP) {
				for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
					for (t = 0; t < CDP_NUM_TYPES; t++) {
						int rerr;

						rerr = resctrl_arch_update_one(r, ctrl, d, i, t,
									       default_ctrl);
						if (rerr)
							pr_err_ratelimited("rid=%d reset RCID %u type %u failed (%d)\n",
									   r->rid, i, t, rerr);
					}
				}
				continue;
			}

			switch (ctrl->name) {
			case RESCTRL_CTRL_NAME_MIN:
				/*
				 * CBQRI section 4.5: Rbwb >= 1, sum(Rbwb) <= MRBWB.
				 * Walk N-1..1 first so RCID 0 lands last with the
				 * remaining budget.
				 */
				for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
					u32 rcid = (i + 1) % hw_res->ctrl->rcid_count;
					u64 rbwb = (rcid == 0) ?
						cbqri_rcid0_rbwb(dom->hw_ctrl) : 1;
					int rerr;

					rerr = cbqri_apply_rbwb(dom->hw_ctrl, rcid, rbwb, false);
					if (rerr)
						pr_err_ratelimited("RBWB reset RCID %u failed (%d)\n",
								   rcid, rerr);
				}
				break;
			default:
				break;
			}
		}
	}
}

static struct rdt_ctrl_domain *cbqri_new_domain(struct cbqri_controller *ctrl)
{
	struct cbqri_resctrl_dom *hw_dom;
	struct rdt_ctrl_domain *domain;

	hw_dom = kzalloc_obj(*hw_dom, GFP_KERNEL);
	if (!hw_dom)
		return NULL;

	hw_dom->hw_ctrl = ctrl;
	domain = &hw_dom->resctrl_ctrl_dom;

	INIT_LIST_HEAD(&domain->hdr.list);

	return domain;
}

static int cbqri_init_domain_ctrlval(struct rdt_resource *r,
				     struct resctrl_ctrl *ctrl,
				     struct rdt_ctrl_domain *d)
{
	struct cbqri_resctrl_res *hw_res;
	struct cbqri_resctrl_dom *dom;
	u32 default_ctrl;
	enum resctrl_conf_type t;
	int err = 0;
	u64 rbwb;
	int i;

	hw_res = container_of(r, struct cbqri_resctrl_res, resctrl_res);
	dom = container_of(d, struct cbqri_resctrl_dom, resctrl_ctrl_dom);
	default_ctrl = resctrl_get_default_ctrlval(ctrl);

	for (i = 0; i < hw_res->ctrl->rcid_count; i++) {
		if (ctrl->type == RESCTRL_CTRL_BITMAP) {
			/*
			 * Seed both DATA and CODE staged slots so a later
			 * mount with -o cdp does not see stale CODE values.
			 * On non-AT controllers cbqri_cc_alloc_op() masks
			 * AT to 0, so all three iterations land on the same
			 * hardware state. The redundant writes are harmless.
			 */
			for (t = 0; t < CDP_NUM_TYPES; t++) {
				err = resctrl_arch_update_one(r, ctrl, d, i, t,
							      default_ctrl);
				if (err)
					return err;
			}
			continue;
		}

		switch (ctrl->name) {
		case RESCTRL_CTRL_NAME_MIN: {
			/*
			 * CBQRI section 4.5: Rbwb >= 1, sum(Rbwb) <= MRBWB.
			 * Walk RCIDs 1..N-1 then RCID 0 last so the sum doesn't
			 * exceed MRBWB during the walk. RCID 0 takes the
			 * remaining budget.
			 */
			u32 rcid = (i + 1) % hw_res->ctrl->rcid_count;

			rbwb = (rcid == 0) ? cbqri_rcid0_rbwb(dom->hw_ctrl) : 1;
			err = cbqri_apply_rbwb(dom->hw_ctrl, rcid, rbwb, false);
			break;
		}
		default:
			err = -EINVAL;
			break;
		}
		if (err)
			return err;
	}
	return 0;
}

/*
 * Walk cbqri_controllers and pick one capacity controller (CC) per cache
 * level (L2/L3) to back the corresponding RDT_RESOURCE_L*. When more than
 * one CC sits at the same level (e.g. one per socket), they must agree on
 * rcid_count / ncblks / CDP support. A mismatch is fatal because resctrl
 * exposes a single set of caps per rid. The first matching controller wins.
 */
static int cbqri_resctrl_pick_caches(void)
{
	struct cbqri_controller *ctrl;

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		struct cbqri_resctrl_res *cbqri_res;
		enum resctrl_res_level rid;

		if (ctrl->type != CBQRI_CONTROLLER_TYPE_CAPACITY)
			continue;
		if (!ctrl->alloc_capable) {
			if (ctrl->mon_capable)
				pr_warn_once("CC @%pa: monitor-only controllers aren't supported\n",
					     &ctrl->addr);
			continue;
		}

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
			 * CCs at the same cache level must agree on every cap
			 * resctrl exposes globally. Reject mismatches at pick
			 * time so the inconsistency is visible at boot.
			 */
			if (cbqri_res->ctrl->rcid_count != ctrl->rcid_count ||
			    cbqri_res->ctrl->cc.ncblks != ctrl->cc.ncblks ||
			    cbqri_res->ctrl->cc.supports_alloc_at_code !=
				    ctrl->cc.supports_alloc_at_code) {
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
 * Append one arch control wrapper to a resource's control list. Each control
 * carries its own scope and domain list. The backing CBQRI controller hw is
 * the same CC for a cache resource's single control.
 */
static struct resctrl_ctrl *
cbqri_add_ctrl(struct cbqri_resctrl_res *cbqri_res, enum resctrl_scope scope,
	       enum resctrl_ctrl_type type, enum resctrl_ctrl_name name)
{
	struct rdt_resource *res = &cbqri_res->resctrl_res;
	struct cbqri_hw_ctrl *hw_ctrl;

	if (WARN_ON_ONCE(cbqri_res->nr_ctrls >= CBQRI_MAX_CTRLS_PER_RES))
		return NULL;

	hw_ctrl = &cbqri_res->ctrls[cbqri_res->nr_ctrls++];
	hw_ctrl->hw = cbqri_res->ctrl;
	hw_ctrl->r_ctrl.scope = scope;
	hw_ctrl->r_ctrl.type = type;
	hw_ctrl->r_ctrl.name = name;
	INIT_LIST_HEAD(&hw_ctrl->r_ctrl.domains);
	list_add_tail(&hw_ctrl->r_ctrl.entry, &res->controls);

	return &hw_ctrl->r_ctrl;
}

/*
 * Fill the rdt_resource fields and build the control list for one picked rid.
 * An rid with no picked controller is left untouched so it stays out of
 * resctrl_arch_get_resource().
 */
static int cbqri_resctrl_control_init(struct cbqri_resctrl_res *cbqri_res)
{
	struct cbqri_controller *ctrl = cbqri_res->ctrl;
	struct rdt_resource *res = &cbqri_res->resctrl_res;
	struct resctrl_ctrl *r_ctrl;

	if (!ctrl)
		return 0;

	switch (res->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		res->name = (res->rid == RDT_RESOURCE_L2) ? "L2" : "L3";
		res->cdp_capable = ctrl->cc.supports_alloc_at_code;
		res->alloc_capable = ctrl->alloc_capable;
		INIT_LIST_HEAD(&res->mon_domains);

		/* One default control of type BITMAP holds the cache caps. */
		r_ctrl = cbqri_add_ctrl(cbqri_res,
					res->rid == RDT_RESOURCE_L2 ?
						RESCTRL_L2_CACHE : RESCTRL_L3_CACHE,
					RESCTRL_CTRL_BITMAP,
					RESCTRL_CTRL_NAME_DEF);
		if (!r_ctrl)
			return -EINVAL;
		r_ctrl->cache.cbm_len = ctrl->cc.ncblks;
		r_ctrl->cache.shareable_bits = 0;
		r_ctrl->cache.min_cbm_bits = 1;
		r_ctrl->cache.arch_has_sparse_bitmasks = false;

		if (ctrl->mon_capable && res->rid == RDT_RESOURCE_L3) {
			res->mon_scope = RESCTRL_L3_CACHE;
			/*
			 * any_cpu: the occupancy counter is read over MMIO,
			 * which is valid from any CPU. Letting the core read
			 * in process context avoids an IPI that would land in
			 * resctrl_arch_rmid_read() with IRQs disabled (where
			 * the BUSY poll is unsafe) on nohz_full domains.
			 */
			resctrl_enable_mon_event(QOS_L3_OCCUP_EVENT_ID,
						 true, 0, NULL);
			res->mon_capable = true;
		}
		break;

	case RDT_RESOURCE_MBA:
		res->name = "MB";
		res->alloc_capable = ctrl->alloc_capable;
		/* CBQRI is not throttle based, so neither field applies. */
		res->bw_throttle_mode = THREAD_THROTTLE_UNDEFINED;
		INIT_LIST_HEAD(&res->mon_domains);

		/*
		 * MIN control: CBQRI Rbwb (reserved minimum bandwidth blocks).
		 * resctrl requires a cache scope for MBA-style domains, so use
		 * L3 as a proxy until non-cache scopes are supported for
		 * bandwidth.
		 */
		r_ctrl = cbqri_add_ctrl(cbqri_res, RESCTRL_L3_CACHE,
					RESCTRL_CTRL_SCALAR,
					RESCTRL_CTRL_NAME_MIN);
		if (!r_ctrl)
			return -EINVAL;
		/*
		 * CBQRI section 4.5 caps sum(Rbwb) <= MRBWB. A MIN control
		 * resets new groups to min_bw, so 1 (one reserved block) keeps
		 * mkdir from overflowing that sum.
		 */
		r_ctrl->membw.min_bw = 1;
		/*
		 * cbqri_apply_rbwb() rejects an Rbwb above U16_MAX, so cap the
		 * advertised maximum to the same bound. Userspace then cannot
		 * request a value the hardware path would reject. mrbwb is a
		 * u16 today, so this only bites if its width ever grows.
		 */
		r_ctrl->membw.max_bw = min_t(u32, ctrl->bc.mrbwb, U16_MAX);
		r_ctrl->membw.bw_gran = 1;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * Pick one BC to back the MB resource. Both the MIN and WGHT controls of
 * that resource use this single BC.
 */
static int cbqri_resctrl_pick_bw_alloc(void)
{
	struct cbqri_resctrl_res *mb = &cbqri_resctrl_resources[RDT_RESOURCE_MBA];
	struct cbqri_controller *ctrl;

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		if (ctrl->type != CBQRI_CONTROLLER_TYPE_BANDWIDTH)
			continue;
		if (!ctrl->alloc_capable)
			continue;

		if (mb->ctrl) {
			if (mb->ctrl->rcid_count != ctrl->rcid_count ||
			    mb->ctrl->bc.mrbwb != ctrl->bc.mrbwb) {
				pr_err("BW controllers have mismatched capabilities\n");
				return -EINVAL;
			}
			continue;
		}

		mb->ctrl = ctrl;
	}

	return 0;
}

static void cbqri_resctrl_accumulate_caps(void)
{
	struct cbqri_controller *l3_ctrl;
	int rid;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[rid];

		if (!hw_res->ctrl)
			continue;
		if (hw_res->ctrl->alloc_capable)
			exposed_alloc_capable = true;
	}

	/*
	 * exposed_mon_capable gates RMID allocation, so tie it to events that
	 * were actually enabled rather than raw controller mon_capable. A
	 * mon-capable controller with no exposed event (an L2 CC) would
	 * otherwise leave max_rmid at U32_MAX and OOM rmid_init().
	 */
	exposed_mon_capable =
		resctrl_is_mon_event_enabled(QOS_L3_OCCUP_EVENT_ID);

	/*
	 * Narrow max_rmid against the picked occupancy source (the L3 CC)
	 * only. A mon-capable controller that is not exposed as a counter
	 * source must not clamp the rmid space.
	 */
	l3_ctrl = cbqri_resctrl_resources[RDT_RESOURCE_L3].ctrl;
	if (l3_ctrl && l3_ctrl->mon_capable)
		max_rmid = min(max_rmid, l3_ctrl->mcid_count);

	if (!exposed_mon_capable) {
		max_rmid = 1;
		return;
	}

	/*
	 * num_rmid is the user-visible bound for the L3 monitoring rmid
	 * space. Track max_rmid (the picked-source minimum) so userspace is
	 * not told more RMIDs than can be allocated.
	 */
	cbqri_resctrl_resources[RDT_RESOURCE_L3].resctrl_res.mon.num_rmid = max_rmid;
}

/*
 * Create, list-insert, and online a fresh ctrl_domain backing hw on
 * resource res for control res_ctrl, seeded with cpu and identified by
 * dom_id. Caller must hold cbqri_domain_list_lock and must have already
 * verified that no existing ctrl_domain on res_ctrl carries this id.
 */
static struct rdt_ctrl_domain *cbqri_create_ctrl_domain(struct cbqri_controller *hw,
							struct rdt_resource *res,
							struct resctrl_ctrl *res_ctrl,
							unsigned int cpu, int dom_id)
{
	struct rdt_ctrl_domain *domain;
	struct list_head *pos = NULL;
	int err;

	domain = cbqri_new_domain(hw);
	if (!domain)
		return ERR_PTR(-ENOMEM);

	cpumask_set_cpu(cpu, &domain->hdr.cpu_mask);
	domain->hdr.id = dom_id;
	domain->hdr.type = RESCTRL_CTRL_DOMAIN;
	domain->hdr.rid = res->rid;

	err = cbqri_init_domain_ctrlval(res, res_ctrl, domain);
	if (err) {
		kfree(container_of(domain, struct cbqri_resctrl_dom,
				   resctrl_ctrl_dom));
		return ERR_PTR(err);
	}

	/* Insert sorted by id so user-visible ordering is deterministic. */
	resctrl_find_domain(&res_ctrl->domains, dom_id, &pos);
	list_add_tail(&domain->hdr.list, pos);

	resctrl_online_ctrl_domain(res, res_ctrl, domain);

	return domain;
}

static int cbqri_attach_cpu_to_l3_mon(struct cbqri_controller *ctrl,
				      struct rdt_resource *res, unsigned int cpu)
{
	struct rdt_l3_mon_domain *mon_dom;
	struct rdt_ctrl_domain *ctrl_dom;
	struct resctrl_ctrl *res_ctrl;
	struct list_head *mon_pos = NULL;
	int dom_id = ctrl->cache.cache_id;
	int err;

	lockdep_assert_held(&cbqri_domain_list_lock);

	mon_dom = cbqri_find_l3_mon_domain(&res->mon_domains, dom_id);
	if (mon_dom) {
		cpumask_set_cpu(cpu, &mon_dom->hdr.cpu_mask);
		return 0;
	}

	/* The L3 cache resource carries a single DEF control. */
	res_ctrl = cbqri_first_ctrl(res);
	ctrl_dom = res_ctrl ? cbqri_find_ctrl_domain(&res_ctrl->domains, dom_id) :
			      NULL;
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

	err = cbqri_init_mon_counters(ctrl);
	if (err)
		goto err_offline;

	return 0;

err_offline:
	/*
	 * cancel_delayed_work avoids deadlocking against the cqm_limbo
	 * worker which takes cpus_read_lock while this hotplug callback
	 * already holds cpus_write_lock.
	 */
	cancel_delayed_work(&mon_dom->cqm_limbo);
	resctrl_offline_mon_domain(res, &mon_dom->hdr);
err_listdel:
	list_del(&mon_dom->hdr.list);
err_free:
	kfree(mon_dom);
	return err;
}

/*
 * Attach a CPU to one control's domain list. Find the ctrl_domain for dom_id;
 * if absent create it. Returns a pointer to the domain, *created set true if
 * this call allocated it. ERR_PTR on failure.
 */
static struct rdt_ctrl_domain *
cbqri_attach_cpu_to_ctrl_dom(struct cbqri_controller *hw, struct rdt_resource *res,
			     struct resctrl_ctrl *res_ctrl, unsigned int cpu,
			     int dom_id, bool *created)
{
	struct rdt_ctrl_domain *domain;

	*created = false;

	domain = cbqri_find_ctrl_domain(&res_ctrl->domains, dom_id);
	if (domain) {
		cpumask_set_cpu(cpu, &domain->hdr.cpu_mask);
		return domain;
	}

	domain = cbqri_create_ctrl_domain(hw, res, res_ctrl, cpu, dom_id);
	if (IS_ERR(domain))
		return domain;

	*created = true;
	return domain;
}

/* Detach a CPU from one control's domain, freeing it when its mask empties. */
static void cbqri_detach_cpu_from_ctrl_dom(struct rdt_resource *res,
					   struct resctrl_ctrl *res_ctrl,
					   unsigned int cpu, int dom_id)
{
	struct rdt_ctrl_domain *domain;

	domain = cbqri_find_ctrl_domain(&res_ctrl->domains, dom_id);
	if (!domain || !cpumask_test_cpu(cpu, &domain->hdr.cpu_mask))
		return;

	cpumask_clear_cpu(cpu, &domain->hdr.cpu_mask);
	if (cpumask_empty(&domain->hdr.cpu_mask)) {
		resctrl_offline_ctrl_domain(res, res_ctrl, domain);
		list_del(&domain->hdr.list);
		kfree(container_of(domain, struct cbqri_resctrl_dom,
				   resctrl_ctrl_dom));
	}
}

static int cbqri_attach_cpu_to_cap_ctrl(struct cbqri_controller *ctrl,
					unsigned int cpu)
{
	struct cbqri_resctrl_res *hw_res;
	struct rdt_ctrl_domain *domain;
	struct resctrl_ctrl *res_ctrl;
	struct rdt_resource *res;
	bool new_domain;
	int dom_id;
	int err;

	if (ctrl->cache.cache_level == 2)
		hw_res = &cbqri_resctrl_resources[RDT_RESOURCE_L2];
	else if (ctrl->cache.cache_level == 3)
		hw_res = &cbqri_resctrl_resources[RDT_RESOURCE_L3];
	else
		return 0;

	if (!hw_res->ctrl)
		return 0;

	res = &hw_res->resctrl_res;
	dom_id = ctrl->cache.cache_id;

	/* Cache resources carry a single DEF control. */
	res_ctrl = cbqri_first_ctrl(res);
	if (!res_ctrl)
		return 0;

	domain = cbqri_attach_cpu_to_ctrl_dom(ctrl, res, res_ctrl, cpu, dom_id,
					      &new_domain);
	if (IS_ERR(domain))
		return PTR_ERR(domain);

	if (ctrl->mon_capable && ctrl->cache.cache_level == 3) {
		err = cbqri_attach_cpu_to_l3_mon(ctrl, res, cpu);
		if (err)
			goto err_undo_ctrl_dom;
	}

	return 0;

err_undo_ctrl_dom:
	/*
	 * The cpuhp core only rolls back states that successfully ran their
	 * startup. The L3 mon attach failure happens inside this state's
	 * startup, so its own offline callback is not invoked. Undo the
	 * cpumask_set and, if this attach created the ctrl_domain, tear it
	 * down so a retry sees a clean slate.
	 */
	cpumask_clear_cpu(cpu, &domain->hdr.cpu_mask);
	if (new_domain) {
		resctrl_offline_ctrl_domain(res, res_ctrl, domain);
		list_del(&domain->hdr.list);
		kfree(container_of(domain, struct cbqri_resctrl_dom,
				   resctrl_ctrl_dom));
	}
	return err;
}

/*
 * Attach a CPU to the bandwidth resource. The single BC backs both the MIN and
 * WGHT controls, each with its own per-prox-domain ctrl_domain list.
 */
static int cbqri_attach_cpu_to_bw_ctrl(struct cbqri_controller *ctrl,
				       unsigned int cpu)
{
	struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[RDT_RESOURCE_MBA];
	struct rdt_resource *res = &hw_res->resctrl_res;
	int dom_id = ctrl->mem.prox_dom;
	struct resctrl_ctrl *res_ctrl;
	struct rdt_ctrl_domain *domain;
	bool created;

	if (!hw_res->ctrl)
		return 0;

	for_each_resource_ctrl(res_ctrl, res) {
		domain = cbqri_attach_cpu_to_ctrl_dom(ctrl, res, res_ctrl, cpu,
						      dom_id, &created);
		if (IS_ERR(domain))
			goto err_detach;
	}

	return 0;

err_detach:
	/*
	 * Undo every control domain this CPU was attached to so a partial
	 * attach does not leak into the domain cpu_masks. cbqri_detach helper
	 * is idempotent and only acts when this CPU is set in the mask.
	 */
	for_each_resource_ctrl(res_ctrl, res)
		cbqri_detach_cpu_from_ctrl_dom(res, res_ctrl, cpu, dom_id);
	return PTR_ERR(domain);
}

static void cbqri_detach_cpu_from_l3_mon(struct rdt_resource *res,
					 unsigned int cpu)
{
	struct rdt_l3_mon_domain *mon_dom, *tmp;

	lockdep_assert_held(&cbqri_domain_list_lock);

	list_for_each_entry_safe(mon_dom, tmp, &res->mon_domains, hdr.list) {
		if (!cpumask_test_cpu(cpu, &mon_dom->hdr.cpu_mask))
			continue;
		cpumask_clear_cpu(cpu, &mon_dom->hdr.cpu_mask);
		if (cpumask_empty(&mon_dom->hdr.cpu_mask)) {
			/*
			 * This runs as a cpuhp offline callback under
			 * cpus_write_lock. The cqm_limbo worker takes
			 * cpus_read_lock before touching a domain, so it
			 * cannot run or re-queue here. A non-sync cancel thus
			 * reliably dequeues any pending work before kfree, and
			 * cancel_delayed_work_sync() would instead deadlock
			 * against that cpus_read_lock.
			 */
			cancel_delayed_work(&mon_dom->cqm_limbo);
			/*
			 * resctrl_offline_mon_domain() force-flushes busy
			 * RMIDs, which re-enters resctrl_arch_rmid_read() and
			 * takes cbqri_domain_list_lock. Drop it across the call
			 * so the flush does not self-deadlock; cpus_write_lock
			 * held by this cpuhp callback keeps the domain lists
			 * stable while it is released.
			 */
			mutex_unlock(&cbqri_domain_list_lock);
			resctrl_offline_mon_domain(res, &mon_dom->hdr);
			mutex_lock(&cbqri_domain_list_lock);
			list_del(&mon_dom->hdr.list);
			kfree(mon_dom);
		}
	}
}

static void cbqri_detach_cpu_from_ctrl_domains(struct rdt_resource *res,
					       unsigned int cpu)
{
	struct rdt_ctrl_domain *domain, *tmp;
	struct resctrl_ctrl *res_ctrl;

	for_each_resource_ctrl(res_ctrl, res) {
		list_for_each_entry_safe(domain, tmp, &res_ctrl->domains, hdr.list) {
			if (!cpumask_test_cpu(cpu, &domain->hdr.cpu_mask))
				continue;
			cpumask_clear_cpu(cpu, &domain->hdr.cpu_mask);
			if (cpumask_empty(&domain->hdr.cpu_mask)) {
				resctrl_offline_ctrl_domain(res, res_ctrl, domain);
				list_del(&domain->hdr.list);
				kfree(container_of(domain, struct cbqri_resctrl_dom,
						   resctrl_ctrl_dom));
			}
		}
	}
}

/*
 * Remove a CPU from every domain it was attached to. The per-resource
 * detach helpers act only when the CPU is set in a domain's mask, so this
 * is idempotent and undoes a partial online attach as well as a full
 * offline. Caller holds cbqri_domain_list_lock.
 */
static void cbqri_detach_cpu_from_all_ctrls(unsigned int cpu)
{
	int rid;

	lockdep_assert_held(&cbqri_domain_list_lock);

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[rid];

		if (!hw_res->ctrl)
			continue;
		cbqri_detach_cpu_from_ctrl_domains(&hw_res->resctrl_res, cpu);
		if (rid == RDT_RESOURCE_L3 && hw_res->ctrl->mon_capable)
			cbqri_detach_cpu_from_l3_mon(&hw_res->resctrl_res, cpu);
	}
}

/*
 * Attach a CPU to every controller that claims it. On failure, detach the
 * CPU from everything attached so far: the cpuhp core does not run this
 * state's offline teardown when its startup fails, so a partial attach
 * would otherwise leak into the domain cpu_masks. Caller holds
 * cbqri_domain_list_lock.
 */
static int cbqri_attach_cpu_to_all_ctrls(unsigned int cpu)
{
	struct cbqri_controller *ctrl;
	int err = 0;

	lockdep_assert_held(&cbqri_domain_list_lock);

	list_for_each_entry(ctrl, &cbqri_controllers, list) {
		switch (ctrl->type) {
		case CBQRI_CONTROLLER_TYPE_CAPACITY:
			if (!cpumask_test_cpu(cpu, &ctrl->cache.cpu_mask))
				continue;
			if (!ctrl->alloc_capable)
				continue;
			err = cbqri_attach_cpu_to_cap_ctrl(ctrl, cpu);
			break;
		case CBQRI_CONTROLLER_TYPE_BANDWIDTH:
			if (!cpumask_test_cpu(cpu, &ctrl->mem.cpu_mask))
				continue;
			if (!ctrl->alloc_capable)
				continue;
			err = cbqri_attach_cpu_to_bw_ctrl(ctrl, cpu);
			break;
		default:
			continue;
		}
		if (err) {
			cbqri_detach_cpu_from_all_ctrls(cpu);
			break;
		}
	}

	return err;
}

static bool cbqri_resctrl_inited;

static void cbqri_resctrl_teardown(void)
{
	int rid;

	if (!cbqri_resctrl_inited)
		return;

	resctrl_exit();

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[rid];

		hw_res->ctrl = NULL;
		hw_res->cdp_enabled = false;
	}
	exposed_alloc_capable = false;
	exposed_mon_capable = false;
	max_rmid = U32_MAX;
	cbqri_resctrl_inited = false;
}

static int cbqri_resctrl_setup(void)
{
	int rid;
	int err;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		struct cbqri_resctrl_res *hw_res = &cbqri_resctrl_resources[rid];

		hw_res->resctrl_res.rid = rid;
		/*
		 * fs/resctrl walks r->controls on every resource regardless of
		 * whether CBQRI backs it, so the list head must be valid even
		 * when no control is added.
		 */
		INIT_LIST_HEAD(&hw_res->resctrl_res.controls);
		hw_res->nr_ctrls = 0;
	}

	err = cbqri_resctrl_pick_caches();
	if (err)
		return err;

	err = cbqri_resctrl_pick_bw_alloc();
	if (err)
		return err;

	for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
		err = cbqri_resctrl_control_init(&cbqri_resctrl_resources[rid]);
		if (err)
			return err;
	}

	cbqri_resctrl_accumulate_caps();

	if (!exposed_alloc_capable && !exposed_mon_capable) {
		pr_debug("no resctrl-capable CBQRI controllers found\n");
		return -ENODEV;
	}

	err = resctrl_init();
	if (err) {
		/*
		 * resctrl_init() failed before we set cbqri_resctrl_inited,
		 * so cbqri_resctrl_teardown() would no-op. Roll back the
		 * exposed_*_capable flags and the resource picks directly
		 * so resctrl_arch_alloc_capable() / _mon_capable() do not
		 * lie to callers after this returns.
		 */
		for (rid = 0; rid < RDT_NUM_RESOURCES; rid++) {
			cbqri_resctrl_resources[rid].ctrl = NULL;
			cbqri_resctrl_resources[rid].cdp_enabled = false;
		}
		exposed_alloc_capable = false;
		exposed_mon_capable = false;
		max_rmid = U32_MAX;
		return err;
	}

	cbqri_resctrl_inited = true;
	return 0;
}

static int cbqri_resctrl_online_cpu(unsigned int cpu)
{
	int err;

	mutex_lock(&cbqri_domain_list_lock);
	err = cbqri_attach_cpu_to_all_ctrls(cpu);
	mutex_unlock(&cbqri_domain_list_lock);
	if (err)
		return err;

	/*
	 * Seed the per-CPU default RCID/MCID to the reserved (0, 0) pair and
	 * notify the resctrl core so it tracks this CPU in the default group.
	 */
	resctrl_arch_set_cpu_default_closid_rmid(cpu, 0, 0);
	resctrl_online_cpu(cpu);
	return 0;
}

static int cbqri_resctrl_offline_cpu(unsigned int cpu)
{
	resctrl_offline_cpu(cpu);

	mutex_lock(&cbqri_domain_list_lock);
	cbqri_detach_cpu_from_all_ctrls(cpu);
	mutex_unlock(&cbqri_domain_list_lock);
	return 0;
}

/* Saved cpuhp slot from cpuhp_setup_state() for symmetric removal. */
static enum cpuhp_state cbqri_cpuhp_state;

static int __init cbqri_arch_late_init(void)
{
	int err;

	if (!riscv_isa_extension_available(NULL, SSQOSID))
		return -ENODEV;

	err = cbqri_resctrl_setup();
	if (err)
		return err;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "cbqri:online",
				cbqri_resctrl_online_cpu,
				cbqri_resctrl_offline_cpu);
	if (err < 0) {
		cbqri_resctrl_teardown();
		return err;
	}
	cbqri_cpuhp_state = err;

	return 0;
}
late_initcall(cbqri_arch_late_init);
