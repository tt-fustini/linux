// SPDX-License-Identifier: GPL-2.0-only
/*
 * User interface for Resource Allocation in Resource Director Technology(RDT)
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Author: Fenghua Yu <fenghua.yu@intel.com>
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/fs_parser.h>
#include <linux/sysfs.h>
#include <linux/kernfs.h>
#include <linux/seq_buf.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/user_namespace.h>

#include <asm/resctrl.h>
#include "internal.h"

DEFINE_STATIC_KEY_FALSE(rdt_enable_key);
DEFINE_STATIC_KEY_FALSE(rdt_mon_enable_key);
DEFINE_STATIC_KEY_FALSE(rdt_alloc_enable_key);

/*
 * This is safe against resctrl_sched_in() called from __switch_to()
 * because __switch_to() is executed with interrupts disabled. A local call
 * from update_closid_rmid() is protected against __switch_to() because
 * preemption is disabled.
 */
void resctrl_arch_sync_cpu_defaults(void *info)
{
	struct resctrl_cpu_sync *r = info;

	if (r) {
		this_cpu_write(pqr_state.default_closid, r->closid);
		this_cpu_write(pqr_state.default_rmid, r->rmid);
	}

	/*
	 * We cannot unconditionally write the MSR because the current
	 * executing task might have its own closid selected. Just reuse
	 * the context switch code.
	 */
	resctrl_sched_in();
}

#define INVALID_CONFIG_INDEX   UINT_MAX

/**
 * mon_event_config_index_get - get the hardware index for the
 *                              configurable event
 * @evtid: event id.
 *
 * Return: 0 for evtid == QOS_L3_MBM_TOTAL_EVENT_ID
 *         1 for evtid == QOS_L3_MBM_LOCAL_EVENT_ID
 *         INVALID_CONFIG_INDEX for invalid evtid
 */
static inline unsigned int mon_event_config_index_get(u32 evtid)
{
	switch (evtid) {
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		return 0;
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		return 1;
	default:
		/* Should never reach here */
		return INVALID_CONFIG_INDEX;
	}
}

void resctrl_arch_mon_event_config_read(void *info)
{
	struct resctrl_mon_config_info *mon_info = info;
	unsigned int index;
	u64 msrval;

	index = mon_event_config_index_get(mon_info->evtid);
	if (index == INVALID_CONFIG_INDEX) {
		pr_warn_once("Invalid event id %d\n", mon_info->evtid);
		return;
	}
	rdmsrl(MSR_IA32_EVT_CFG_BASE + index, msrval);

	/* Report only the valid event configuration bits */
	mon_info->mon_config = msrval & MAX_EVT_CONFIG_BITS;
}

void resctrl_arch_mon_event_config_write(void *info)
{
	struct resctrl_mon_config_info *mon_info = info;
	unsigned int index;

	index = mon_event_config_index_get(mon_info->evtid);
	if (index == INVALID_CONFIG_INDEX) {
		pr_warn_once("Invalid event id %d\n", mon_info->evtid);
		mon_info->err = -EINVAL;
		return;
	}
	wrmsr(MSR_IA32_EVT_CFG_BASE + index, mon_info->mon_config, 0);

	mon_info->err = 0;
}

static void l3_qos_cfg_update(void *arg)
{
	bool *enable = arg;

	wrmsrl(MSR_IA32_L3_QOS_CFG, *enable ? L3_QOS_CDP_ENABLE : 0ULL);
}

static void l2_qos_cfg_update(void *arg)
{
	bool *enable = arg;

	wrmsrl(MSR_IA32_L2_QOS_CFG, *enable ? L2_QOS_CDP_ENABLE : 0ULL);
}

static int set_cache_qos_cfg(int level, bool enable)
{
	void (*update)(void *arg);
	struct rdt_resource *r_l;
	cpumask_var_t cpu_mask;
	struct rdt_domain *d;
	int cpu;

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	if (level == RDT_RESOURCE_L3)
		update = l3_qos_cfg_update;
	else if (level == RDT_RESOURCE_L2)
		update = l2_qos_cfg_update;
	else
		return -EINVAL;

	if (!zalloc_cpumask_var(&cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	r_l = &rdt_resources_all[level].r_resctrl;
	list_for_each_entry(d, &r_l->domains, list) {
		if (r_l->cache.arch_has_per_cpu_cfg)
			/* Pick all the CPUs in the domain instance */
			for_each_cpu(cpu, &d->cpu_mask)
				cpumask_set_cpu(cpu, cpu_mask);
		else
			/* Pick one CPU from each domain instance to update MSR */
			cpumask_set_cpu(cpumask_any(&d->cpu_mask), cpu_mask);
	}

	/* Update QOS_CFG MSR on all the CPUs in cpu_mask */
	on_each_cpu_mask(cpu_mask, update, &enable, 1);

	free_cpumask_var(cpu_mask);

	return 0;
}

/* Restore the qos cfg state when a domain comes online */
void rdt_domain_reconfigure_cdp(struct rdt_resource *r)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);

	if (!r->cdp_capable)
		return;

	if (r->rid == RDT_RESOURCE_L2)
		l2_qos_cfg_update(&hw_res->cdp_enabled);

	if (r->rid == RDT_RESOURCE_L3)
		l3_qos_cfg_update(&hw_res->cdp_enabled);
}

static int cdp_enable(int level)
{
	struct rdt_resource *r_l = &rdt_resources_all[level].r_resctrl;
	int ret;

	if (!r_l->alloc_capable)
		return -EINVAL;

	ret = set_cache_qos_cfg(level, true);
	if (!ret)
		rdt_resources_all[level].cdp_enabled = true;

	return ret;
}

static void cdp_disable(int level)
{
	struct rdt_hw_resource *r_hw = &rdt_resources_all[level];

	if (r_hw->cdp_enabled) {
		set_cache_qos_cfg(level, false);
		r_hw->cdp_enabled = false;
	}
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level l, bool enable)
{
	struct rdt_hw_resource *hw_res = &rdt_resources_all[l];

	if (!hw_res->r_resctrl.cdp_capable)
		return -EINVAL;

	if (enable)
		return cdp_enable(l);

	cdp_disable(l);

	return 0;
}

static int reset_all_ctrls(struct rdt_resource *r)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);
	struct rdt_hw_domain *hw_dom;
	struct msr_param msr_param;
	cpumask_var_t cpu_mask;
	struct rdt_domain *d;
	int i;

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	if (!zalloc_cpumask_var(&cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	msr_param.res = r;
	msr_param.low = 0;
	msr_param.high = hw_res->num_closid;

	/*
	 * Disable resource control for this resource by setting all
	 * CBMs in all domains to the maximum mask value. Pick one CPU
	 * from each domain to update the MSRs below.
	 */
	list_for_each_entry(d, &r->domains, list) {
		hw_dom = resctrl_to_arch_dom(d);
		cpumask_set_cpu(cpumask_any(&d->cpu_mask), cpu_mask);

		for (i = 0; i < hw_res->num_closid; i++)
			hw_dom->ctrl_val[i] = r->default_ctrl;
	}

	/* Update CBM on all the CPUs in cpu_mask */
	on_each_cpu_mask(cpu_mask, rdt_ctrl_update, &msr_param, 1);

	free_cpumask_var(cpu_mask);

	return 0;
}

void resctrl_arch_reset_resources(void)
{
	struct rdt_resource *r;

	for_each_capable_rdt_resource(r)
		reset_all_ctrls(r);
}
<<<<<<< HEAD

/*
 * Move tasks from one to the other group. If @from is NULL, then all tasks
 * in the systems are moved unconditionally (used for teardown).
 *
 * If @mask is not NULL the cpus on which moved tasks are running are set
 * in that mask so the update smp function call is restricted to affected
 * cpus.
 */
static void rdt_move_group_tasks(struct rdtgroup *from, struct rdtgroup *to,
				 struct cpumask *mask)
{
	struct task_struct *p, *t;

	read_lock(&tasklist_lock);
	for_each_process_thread(p, t) {
		if (!from || is_closid_match(t, from) ||
		    is_rmid_match(t, from)) {
			resctrl_arch_set_closid_rmid(t, to->closid,
						     to->mon.rmid);

			/*
			 * Order the closid/rmid stores above before the loads
			 * in task_curr(). This pairs with the full barrier
			 * between the rq->curr update and resctrl_sched_in()
			 * during context switch.
			 */
			smp_mb();

			/*
			 * If the task is on a CPU, set the CPU in the mask.
			 * The detection is inaccurate as tasks might move or
			 * schedule before the smp function call takes place.
			 * In such a case the function call is pointless, but
			 * there is no other side effect.
			 */
			if (IS_ENABLED(CONFIG_SMP) && mask && task_curr(t))
				cpumask_set_cpu(task_cpu(t), mask);
		}
	}
	read_unlock(&tasklist_lock);
}

static void free_all_child_rdtgrp(struct rdtgroup *rdtgrp)
{
	struct rdtgroup *sentry, *stmp;
	struct list_head *head;

	head = &rdtgrp->mon.crdtgrp_list;
	list_for_each_entry_safe(sentry, stmp, head, mon.crdtgrp_list) {
		free_rmid(sentry->closid, sentry->mon.rmid);
		list_del(&sentry->mon.crdtgrp_list);

		if (atomic_read(&sentry->waitcount) != 0)
			sentry->flags = RDT_DELETED;
		else
			rdtgroup_remove(sentry);
	}
}

/*
 * Forcibly remove all of subdirectories under root.
 */
static void rmdir_all_sub(void)
{
	struct rdtgroup *rdtgrp, *tmp;

	/* Move all tasks to the default resource group */
	rdt_move_group_tasks(NULL, &rdtgroup_default, NULL);

	list_for_each_entry_safe(rdtgrp, tmp, &rdt_all_groups, rdtgroup_list) {
		/* Free any child rmids */
		free_all_child_rdtgrp(rdtgrp);

		/* Remove each rdtgroup other than root */
		if (rdtgrp == &rdtgroup_default)
			continue;

		if (rdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP ||
		    rdtgrp->mode == RDT_MODE_PSEUDO_LOCKED)
			rdtgroup_pseudo_lock_remove(rdtgrp);

		/*
		 * Give any CPUs back to the default group. We cannot copy
		 * cpu_online_mask because a CPU might have executed the
		 * offline callback already, but is still marked online.
		 */
		cpumask_or(&rdtgroup_default.cpu_mask,
			   &rdtgroup_default.cpu_mask, &rdtgrp->cpu_mask);

		free_rmid(rdtgrp->closid, rdtgrp->mon.rmid);

		kernfs_remove(rdtgrp->kn);
		list_del(&rdtgrp->rdtgroup_list);

		if (atomic_read(&rdtgrp->waitcount) != 0)
			rdtgrp->flags = RDT_DELETED;
		else
			rdtgroup_remove(rdtgrp);
	}
	/* Notify online CPUs to update per cpu storage and PQR_ASSOC MSR */
	update_closid_rmid(cpu_online_mask, &rdtgroup_default);

	kernfs_remove(kn_info);
	kernfs_remove(kn_mongrp);
	kernfs_remove(kn_mondata);
}

static void rdt_kill_sb(struct super_block *sb)
{
	cpus_read_lock();
	mutex_lock(&rdtgroup_mutex);

	set_mba_sc(false);

	/* Put everything back to default values. */
	resctrl_arch_reset_resources();

	cdp_disable_all();
	rmdir_all_sub();
	if (IS_ENABLED(CONFIG_RESCTRL_FS_PSEUDO_LOCK))
		rdt_pseudo_lock_release();
	rdtgroup_default.mode = RDT_MODE_SHAREABLE;
	schemata_list_destroy();
	if (resctrl_arch_alloc_capable())
		resctrl_arch_disable_alloc();
	if (resctrl_arch_mon_capable())
		resctrl_arch_disable_mon();
	resctrl_mounted = false;
	kernfs_kill_sb(sb);
	mutex_unlock(&rdtgroup_mutex);
	cpus_read_unlock();
}

static struct file_system_type rdt_fs_type = {
	.name			= "resctrl",
	.init_fs_context	= rdt_init_fs_context,
	.parameters		= rdt_fs_parameters,
	.kill_sb		= rdt_kill_sb,
};

static int mon_addfile(struct kernfs_node *parent_kn, const char *name,
		       void *priv)
{
	struct kernfs_node *kn;
	int ret = 0;

	kn = __kernfs_create_file(parent_kn, name, 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &kf_mondata_ops, priv, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret) {
		kernfs_remove(kn);
		return ret;
	}

	return ret;
}

/*
 * Remove all subdirectories of mon_data of ctrl_mon groups
 * and monitor groups with given domain id.
 */
static void rmdir_mondata_subdir_allrdtgrp(struct rdt_resource *r,
					   unsigned int dom_id)
{
	struct rdtgroup *prgrp, *crgrp;
	char name[32];

	list_for_each_entry(prgrp, &rdt_all_groups, rdtgroup_list) {
		sprintf(name, "mon_%s_%02d", r->name, dom_id);
		kernfs_remove_by_name(prgrp->mon.mon_data_kn, name);

		list_for_each_entry(crgrp, &prgrp->mon.crdtgrp_list, mon.crdtgrp_list)
			kernfs_remove_by_name(crgrp->mon.mon_data_kn, name);
	}
}

static int mkdir_mondata_subdir(struct kernfs_node *parent_kn,
				struct rdt_domain *d,
				struct rdt_resource *r, struct rdtgroup *prgrp)
{
	union mon_data_bits priv;
	struct kernfs_node *kn;
	struct mon_evt *mevt;
	struct rmid_read rr;
	char name[32];
	int ret;

	sprintf(name, "mon_%s_%02d", r->name, d->id);
	/* create the directory */
	kn = kernfs_create_dir(parent_kn, name, parent_kn->mode, prgrp);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;

	if (WARN_ON(list_empty(&r->evt_list))) {
		ret = -EPERM;
		goto out_destroy;
	}

	priv.u.rid = r->rid;
	priv.u.domid = d->id;
	list_for_each_entry(mevt, &r->evt_list, list) {
		priv.u.evtid = mevt->evtid;
		ret = mon_addfile(kn, mevt->name, priv.priv);
		if (ret)
			goto out_destroy;

		if (resctrl_is_mbm_event(mevt->evtid))
			mon_event_read(&rr, r, d, prgrp, mevt->evtid, true);
	}
	kernfs_activate(kn);
	return 0;

out_destroy:
	kernfs_remove(kn);
	return ret;
}

/*
 * Add all subdirectories of mon_data for "ctrl_mon" groups
 * and "monitor" groups with given domain id.
 */
static void mkdir_mondata_subdir_allrdtgrp(struct rdt_resource *r,
					   struct rdt_domain *d)
{
	struct kernfs_node *parent_kn;
	struct rdtgroup *prgrp, *crgrp;
	struct list_head *head;

	list_for_each_entry(prgrp, &rdt_all_groups, rdtgroup_list) {
		parent_kn = prgrp->mon.mon_data_kn;
		mkdir_mondata_subdir(parent_kn, d, r, prgrp);

		head = &prgrp->mon.crdtgrp_list;
		list_for_each_entry(crgrp, head, mon.crdtgrp_list) {
			parent_kn = crgrp->mon.mon_data_kn;
			mkdir_mondata_subdir(parent_kn, d, r, crgrp);
		}
	}
}

static int mkdir_mondata_subdir_alldom(struct kernfs_node *parent_kn,
				       struct rdt_resource *r,
				       struct rdtgroup *prgrp)
{
	struct rdt_domain *dom;
	int ret;

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	list_for_each_entry(dom, &r->domains, list) {
		ret = mkdir_mondata_subdir(parent_kn, dom, r, prgrp);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * This creates a directory mon_data which contains the monitored data.
 *
 * mon_data has one directory for each domain which are named
 * in the format mon_<domain_name>_<domain_id>. For ex: A mon_data
 * with L3 domain looks as below:
 * ./mon_data:
 * mon_L3_00
 * mon_L3_01
 * mon_L3_02
 * ...
 *
 * Each domain directory has one file per event:
 * ./mon_L3_00/:
 * llc_occupancy
 *
 */
static int mkdir_mondata_all(struct kernfs_node *parent_kn,
			     struct rdtgroup *prgrp,
			     struct kernfs_node **dest_kn)
{
	enum resctrl_res_level i;
	struct rdt_resource *r;
	struct kernfs_node *kn;
	int ret;

	/*
	 * Create the mon_data directory first.
	 */
	ret = mongroup_create_dir(parent_kn, prgrp, "mon_data", &kn);
	if (ret)
		return ret;

	if (dest_kn)
		*dest_kn = kn;

	/*
	 * Create the subdirectories for each domain. Note that all events
	 * in a domain like L3 are grouped into a resource whose domain is L3
	 */
	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		r = resctrl_arch_get_resource(i);
		if (!r->mon_capable)
			continue;

		ret = mkdir_mondata_subdir_alldom(kn, r, prgrp);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_destroy:
	kernfs_remove(kn);
	return ret;
}

/**
 * cbm_ensure_valid - Enforce validity on provided CBM
 * @_val:	Candidate CBM
 * @r:		RDT resource to which the CBM belongs
 *
 * The provided CBM represents all cache portions available for use. This
 * may be represented by a bitmap that does not consist of contiguous ones
 * and thus be an invalid CBM.
 * Here the provided CBM is forced to be a valid CBM by only considering
 * the first set of contiguous bits as valid and clearing all bits.
 * The intention here is to provide a valid default CBM with which a new
 * resource group is initialized. The user can follow this with a
 * modification to the CBM if the default does not satisfy the
 * requirements.
 */
static u32 cbm_ensure_valid(u32 _val, struct rdt_resource *r)
{
	unsigned int cbm_len = r->cache.cbm_len;
	unsigned long first_bit, zero_bit;
	unsigned long val = _val;

	if (!val)
		return 0;

	first_bit = find_first_bit(&val, cbm_len);
	zero_bit = find_next_zero_bit(&val, cbm_len, first_bit);

	/* Clear any remaining bits to ensure contiguous region */
	bitmap_clear(&val, zero_bit, cbm_len - zero_bit);
	return (u32)val;
}

/*
 * Initialize cache resources per RDT domain
 *
 * Set the RDT domain up to start off with all usable allocations. That is,
 * all shareable and unused bits. All-zero CBM is invalid.
 */
static int __init_one_rdt_domain(struct rdt_domain *d, struct resctrl_schema *s,
				 u32 closid)
{
	enum resctrl_conf_type peer_type = resctrl_peer_type(s->conf_type);
	enum resctrl_conf_type t = s->conf_type;
	struct resctrl_staged_config *cfg;
	struct rdt_resource *r = s->res;
	u32 used_b = 0, unused_b = 0;
	unsigned long tmp_cbm;
	enum rdtgrp_mode mode;
	u32 peer_ctl, ctrl_val;
	int i;

	cfg = &d->staged_config[t];
	cfg->have_new_ctrl = false;
	cfg->new_ctrl = r->cache.shareable_bits;
	used_b = r->cache.shareable_bits;
	for (i = 0; i < closids_supported(); i++) {
		if (closid_allocated(i) && i != closid) {
			mode = rdtgroup_mode_by_closid(i);
			if (mode == RDT_MODE_PSEUDO_LOCKSETUP)
				/*
				 * ctrl values for locksetup aren't relevant
				 * until the schemata is written, and the mode
				 * becomes RDT_MODE_PSEUDO_LOCKED.
				 */
				continue;
			/*
			 * If CDP is active include peer domain's
			 * usage to ensure there is no overlap
			 * with an exclusive group.
			 */
			if (resctrl_arch_get_cdp_enabled(r->rid))
				peer_ctl = resctrl_arch_get_config(r, d, i,
								   peer_type);
			else
				peer_ctl = 0;
			ctrl_val = resctrl_arch_get_config(r, d, i,
							   s->conf_type);
			used_b |= ctrl_val | peer_ctl;
			if (mode == RDT_MODE_SHAREABLE)
				cfg->new_ctrl |= ctrl_val | peer_ctl;
		}
	}
	if (d->plr && d->plr->cbm > 0)
		used_b |= d->plr->cbm;
	unused_b = used_b ^ (BIT_MASK(r->cache.cbm_len) - 1);
	unused_b &= BIT_MASK(r->cache.cbm_len) - 1;
	cfg->new_ctrl |= unused_b;
	/*
	 * Force the initial CBM to be valid, user can
	 * modify the CBM based on system availability.
	 */
	cfg->new_ctrl = cbm_ensure_valid(cfg->new_ctrl, r);
	/*
	 * Assign the u32 CBM to an unsigned long to ensure that
	 * bitmap_weight() does not access out-of-bound memory.
	 */
	tmp_cbm = cfg->new_ctrl;
	if (bitmap_weight(&tmp_cbm, r->cache.cbm_len) < r->cache.min_cbm_bits) {
		rdt_last_cmd_printf("No space on %s:%d\n", s->name, d->id);
		return -ENOSPC;
	}
	cfg->have_new_ctrl = true;

	return 0;
}

/*
 * Initialize cache resources with default values.
 *
 * A new RDT group is being created on an allocation capable (CAT)
 * supporting system. Set this group up to start off with all usable
 * allocations.
 *
 * If there are no more shareable bits available on any domain then
 * the entire allocation will fail.
 */
static int rdtgroup_init_cat(struct resctrl_schema *s, u32 closid)
{
	struct rdt_domain *d;
	int ret;

	list_for_each_entry(d, &s->res->domains, list) {
		ret = __init_one_rdt_domain(d, s, closid);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/* Initialize MBA resource with default values. */
static void rdtgroup_init_mba(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	struct rdt_domain *d;

	list_for_each_entry(d, &r->domains, list) {
		if (is_mba_sc(r)) {
			d->mbps_val[closid] = MBA_MAX_MBPS;
			continue;
		}

		cfg = &d->staged_config[CDP_NONE];
		cfg->new_ctrl = r->default_ctrl;
		cfg->have_new_ctrl = true;
	}
}

/* Initialize the RDT group's allocations. */
static int rdtgroup_init_alloc(struct rdtgroup *rdtgrp)
{
	struct resctrl_schema *s;
	struct rdt_resource *r;
	int ret;

	list_for_each_entry(s, &resctrl_schema_all, list) {
		r = s->res;
		if (r->rid == RDT_RESOURCE_MBA ||
		    r->rid == RDT_RESOURCE_SMBA) {
			rdtgroup_init_mba(r, rdtgrp->closid);
			if (is_mba_sc(r))
				continue;
		} else {
			ret = rdtgroup_init_cat(s, rdtgrp->closid);
			if (ret < 0)
				return ret;
		}

		ret = resctrl_arch_update_domains(r, rdtgrp->closid);
		if (ret < 0) {
			rdt_last_cmd_puts("Failed to initialize allocations\n");
			return ret;
		}

	}

	rdtgrp->mode = RDT_MODE_SHAREABLE;

	return 0;
}

static int mkdir_rdt_prepare_rmid_alloc(struct rdtgroup *rdtgrp)
{
	int ret;

	if (!resctrl_arch_mon_capable())
		return 0;

	ret = alloc_rmid(rdtgrp->closid);
	if (ret < 0) {
		rdt_last_cmd_puts("Out of RMIDs\n");
		return ret;
	}
	rdtgrp->mon.rmid = ret;

	ret = mkdir_mondata_all(rdtgrp->kn, rdtgrp, &rdtgrp->mon.mon_data_kn);
	if (ret) {
		rdt_last_cmd_puts("kernfs subdir error\n");
		free_rmid(rdtgrp->closid, rdtgrp->mon.rmid);
		return ret;
	}

	return 0;
}

static void mkdir_rdt_prepare_rmid_free(struct rdtgroup *rgrp)
{
	if (resctrl_arch_mon_capable())
		free_rmid(rgrp->closid, rgrp->mon.rmid);
}

static int mkdir_rdt_prepare(struct kernfs_node *parent_kn,
			     const char *name, umode_t mode,
			     enum rdt_group_type rtype, struct rdtgroup **r)
{
	struct rdtgroup *prdtgrp, *rdtgrp;
	struct kernfs_node *kn;
	uint files = 0;
	int ret;

	prdtgrp = rdtgroup_kn_lock_live(parent_kn);
	if (!prdtgrp) {
		ret = -ENODEV;
		goto out_unlock;
	}

	if (rtype == RDTMON_GROUP &&
	    (prdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP ||
	     prdtgrp->mode == RDT_MODE_PSEUDO_LOCKED)) {
		ret = -EINVAL;
		rdt_last_cmd_puts("Pseudo-locking in progress\n");
		goto out_unlock;
	}

	/* allocate the rdtgroup. */
	rdtgrp = kzalloc(sizeof(*rdtgrp), GFP_KERNEL);
	if (!rdtgrp) {
		ret = -ENOSPC;
		rdt_last_cmd_puts("Kernel out of memory\n");
		goto out_unlock;
	}
	*r = rdtgrp;
	rdtgrp->mon.parent = prdtgrp;
	rdtgrp->type = rtype;
	INIT_LIST_HEAD(&rdtgrp->mon.crdtgrp_list);

	/* kernfs creates the directory for rdtgrp */
	kn = kernfs_create_dir(parent_kn, name, mode, rdtgrp);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		rdt_last_cmd_puts("kernfs create error\n");
		goto out_free_rgrp;
	}
	rdtgrp->kn = kn;

	/*
	 * kernfs_remove() will drop the reference count on "kn" which
	 * will free it. But we still need it to stick around for the
	 * rdtgroup_kn_unlock(kn) call. Take one extra reference here,
	 * which will be dropped by kernfs_put() in rdtgroup_remove().
	 */
	kernfs_get(kn);

	ret = rdtgroup_kn_set_ugid(kn);
	if (ret) {
		rdt_last_cmd_puts("kernfs perm error\n");
		goto out_destroy;
	}

	files = RFTYPE_BASE | BIT(RF_CTRLSHIFT + rtype);
	ret = rdtgroup_add_files(kn, files);
	if (ret) {
		rdt_last_cmd_puts("kernfs fill error\n");
		goto out_destroy;
	}

	/*
	 * The caller unlocks the parent_kn upon success.
	 */
	return 0;

out_destroy:
	kernfs_put(rdtgrp->kn);
	kernfs_remove(rdtgrp->kn);
out_free_rgrp:
	kfree(rdtgrp);
out_unlock:
	rdtgroup_kn_unlock(parent_kn);
	return ret;
}

static void mkdir_rdt_prepare_clean(struct rdtgroup *rgrp)
{
	kernfs_remove(rgrp->kn);
	rdtgroup_remove(rgrp);
}

/*
 * Create a monitor group under "mon_groups" directory of a control
 * and monitor group(ctrl_mon). This is a resource group
 * to monitor a subset of tasks and cpus in its parent ctrl_mon group.
 */
static int rdtgroup_mkdir_mon(struct kernfs_node *parent_kn,
			      const char *name, umode_t mode)
{
	struct rdtgroup *rdtgrp, *prgrp;
	int ret;

	ret = mkdir_rdt_prepare(parent_kn, name, mode, RDTMON_GROUP, &rdtgrp);
	if (ret)
		return ret;

	prgrp = rdtgrp->mon.parent;
	rdtgrp->closid = prgrp->closid;

	ret = mkdir_rdt_prepare_rmid_alloc(rdtgrp);
	if (ret) {
		mkdir_rdt_prepare_clean(rdtgrp);
		goto out_unlock;
	}

	kernfs_activate(rdtgrp->kn);

	/*
	 * Add the rdtgrp to the list of rdtgrps the parent
	 * ctrl_mon group has to track.
	 */
	list_add_tail(&rdtgrp->mon.crdtgrp_list, &prgrp->mon.crdtgrp_list);

out_unlock:
	rdtgroup_kn_unlock(parent_kn);
	return ret;
}

/*
 * These are rdtgroups created under the root directory. Can be used
 * to allocate and monitor resources.
 */
static int rdtgroup_mkdir_ctrl_mon(struct kernfs_node *parent_kn,
				   const char *name, umode_t mode)
{
	struct rdtgroup *rdtgrp;
	struct kernfs_node *kn;
	u32 closid;
	int ret;

	ret = mkdir_rdt_prepare(parent_kn, name, mode, RDTCTRL_GROUP, &rdtgrp);
	if (ret)
		return ret;

	kn = rdtgrp->kn;
	ret = closid_alloc();
	if (ret < 0) {
		rdt_last_cmd_puts("Out of CLOSIDs\n");
		goto out_common_fail;
	}
	closid = ret;
	ret = 0;

	rdtgrp->closid = closid;

	ret = mkdir_rdt_prepare_rmid_alloc(rdtgrp);
	if (ret)
		goto out_id_free;

	kernfs_activate(rdtgrp->kn);

	ret = rdtgroup_init_alloc(rdtgrp);
	if (ret < 0)
		goto out_rmid_free;

	list_add(&rdtgrp->rdtgroup_list, &rdt_all_groups);

	if (resctrl_arch_mon_capable()) {
		/*
		 * Create an empty mon_groups directory to hold the subset
		 * of tasks and cpus to monitor.
		 */
		ret = mongroup_create_dir(kn, rdtgrp, "mon_groups", NULL);
		if (ret) {
			rdt_last_cmd_puts("kernfs subdir error\n");
			goto out_del_list;
		}
	}

	goto out_unlock;

out_del_list:
	list_del(&rdtgrp->rdtgroup_list);
out_rmid_free:
	mkdir_rdt_prepare_rmid_free(rdtgrp);
out_id_free:
	closid_free(closid);
out_common_fail:
	mkdir_rdt_prepare_clean(rdtgrp);
out_unlock:
	rdtgroup_kn_unlock(parent_kn);
	return ret;
}

/*
 * We allow creating mon groups only with in a directory called "mon_groups"
 * which is present in every ctrl_mon group. Check if this is a valid
 * "mon_groups" directory.
 *
 * 1. The directory should be named "mon_groups".
 * 2. The mon group itself should "not" be named "mon_groups".
 *   This makes sure "mon_groups" directory always has a ctrl_mon group
 *   as parent.
 */
static bool is_mon_groups(struct kernfs_node *kn, const char *name)
{
	return (!strcmp(kn->name, "mon_groups") &&
		strcmp(name, "mon_groups"));
}

static int rdtgroup_mkdir(struct kernfs_node *parent_kn, const char *name,
			  umode_t mode)
{
	/* Do not accept '\n' to avoid unparsable situation. */
	if (strchr(name, '\n'))
		return -EINVAL;

	/*
	 * If the parent directory is the root directory and RDT
	 * allocation is supported, add a control and monitoring
	 * subdirectory
	 */
	if (resctrl_arch_alloc_capable() && parent_kn == rdtgroup_default.kn)
		return rdtgroup_mkdir_ctrl_mon(parent_kn, name, mode);

	/*
	 * If RDT monitoring is supported and the parent directory is a valid
	 * "mon_groups" directory, add a monitoring subdirectory.
	 */
	if (resctrl_arch_mon_capable() && is_mon_groups(parent_kn, name))
		return rdtgroup_mkdir_mon(parent_kn, name, mode);

	return -EPERM;
}

static int rdtgroup_rmdir_mon(struct rdtgroup *rdtgrp, cpumask_var_t tmpmask)
{
	struct rdtgroup *prdtgrp = rdtgrp->mon.parent;
	int cpu;

	/* Give any tasks back to the parent group */
	rdt_move_group_tasks(rdtgrp, prdtgrp, tmpmask);

	/* Update per cpu rmid of the moved CPUs first */
	for_each_cpu(cpu, &rdtgrp->cpu_mask)
		resctrl_arch_set_cpu_default_closid_rmid(cpu, rdtgrp->closid,
							 prdtgrp->mon.rmid);

	/*
	 * Update the MSR on moved CPUs and CPUs which have moved
	 * task running on them.
	 */
	cpumask_or(tmpmask, tmpmask, &rdtgrp->cpu_mask);
	update_closid_rmid(tmpmask, NULL);

	rdtgrp->flags = RDT_DELETED;
	free_rmid(rdtgrp->closid, rdtgrp->mon.rmid);

	/*
	 * Remove the rdtgrp from the parent ctrl_mon group's list
	 */
	WARN_ON(list_empty(&prdtgrp->mon.crdtgrp_list));
	list_del(&rdtgrp->mon.crdtgrp_list);

	kernfs_remove(rdtgrp->kn);

	return 0;
}

static int rdtgroup_ctrl_remove(struct rdtgroup *rdtgrp)
{
	rdtgrp->flags = RDT_DELETED;
	list_del(&rdtgrp->rdtgroup_list);

	kernfs_remove(rdtgrp->kn);
	return 0;
}

static int rdtgroup_rmdir_ctrl(struct rdtgroup *rdtgrp, cpumask_var_t tmpmask)
{
	u32 closid, rmid;
	int cpu;

	/* Give any tasks back to the default group */
	rdt_move_group_tasks(rdtgrp, &rdtgroup_default, tmpmask);

	/* Give any CPUs back to the default group */
	cpumask_or(&rdtgroup_default.cpu_mask,
		   &rdtgroup_default.cpu_mask, &rdtgrp->cpu_mask);

	/* Update per cpu closid and rmid of the moved CPUs first */
	closid = rdtgroup_default.closid;
	rmid = rdtgroup_default.mon.rmid;
	for_each_cpu(cpu, &rdtgrp->cpu_mask)
		resctrl_arch_set_cpu_default_closid_rmid(cpu, closid, rmid);

	/*
	 * Update the MSR on moved CPUs and CPUs which have moved
	 * task running on them.
	 */
	cpumask_or(tmpmask, tmpmask, &rdtgrp->cpu_mask);
	update_closid_rmid(tmpmask, NULL);

	free_rmid(rdtgrp->closid, rdtgrp->mon.rmid);
	closid_free(rdtgrp->closid);

	rdtgroup_ctrl_remove(rdtgrp);

	/*
	 * Free all the child monitor group rmids.
	 */
	free_all_child_rdtgrp(rdtgrp);

	return 0;
}

static int rdtgroup_rmdir(struct kernfs_node *kn)
{
	struct kernfs_node *parent_kn = kn->parent;
	struct rdtgroup *rdtgrp;
	cpumask_var_t tmpmask;
	int ret = 0;

	if (!zalloc_cpumask_var(&tmpmask, GFP_KERNEL))
		return -ENOMEM;

	rdtgrp = rdtgroup_kn_lock_live(kn);
	if (!rdtgrp) {
		ret = -EPERM;
		goto out;
	}

	/*
	 * If the rdtgroup is a ctrl_mon group and parent directory
	 * is the root directory, remove the ctrl_mon group.
	 *
	 * If the rdtgroup is a mon group and parent directory
	 * is a valid "mon_groups" directory, remove the mon group.
	 */
	if (rdtgrp->type == RDTCTRL_GROUP && parent_kn == rdtgroup_default.kn &&
	    rdtgrp != &rdtgroup_default) {
		if (rdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP ||
		    rdtgrp->mode == RDT_MODE_PSEUDO_LOCKED) {
			ret = rdtgroup_ctrl_remove(rdtgrp);
		} else {
			ret = rdtgroup_rmdir_ctrl(rdtgrp, tmpmask);
		}
	} else if (rdtgrp->type == RDTMON_GROUP &&
		 is_mon_groups(parent_kn, kn->name)) {
		ret = rdtgroup_rmdir_mon(rdtgrp, tmpmask);
	} else {
		ret = -EPERM;
	}

out:
	rdtgroup_kn_unlock(kn);
	free_cpumask_var(tmpmask);
	return ret;
}

static int rdtgroup_show_options(struct seq_file *seq, struct kernfs_root *kf)
{
	if (resctrl_arch_get_cdp_enabled(RDT_RESOURCE_L3))
		seq_puts(seq, ",cdp");

	if (resctrl_arch_get_cdp_enabled(RDT_RESOURCE_L2))
		seq_puts(seq, ",cdpl2");

	if (is_mba_sc(resctrl_arch_get_resource(RDT_RESOURCE_MBA)))
		seq_puts(seq, ",mba_MBps");

	return 0;
}

static struct kernfs_syscall_ops rdtgroup_kf_syscall_ops = {
	.mkdir		= rdtgroup_mkdir,
	.rmdir		= rdtgroup_rmdir,
	.show_options	= rdtgroup_show_options,
};

static int rdtgroup_setup_root(void)
{
	int ret;

	rdt_root = kernfs_create_root(&rdtgroup_kf_syscall_ops,
				      KERNFS_ROOT_CREATE_DEACTIVATED |
				      KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK,
				      &rdtgroup_default);
	if (IS_ERR(rdt_root))
		return PTR_ERR(rdt_root);

	mutex_lock(&rdtgroup_mutex);

	rdtgroup_default.closid = 0;
	rdtgroup_default.mon.rmid = 0;
	rdtgroup_default.type = RDTCTRL_GROUP;
	INIT_LIST_HEAD(&rdtgroup_default.mon.crdtgrp_list);

	list_add(&rdtgroup_default.rdtgroup_list, &rdt_all_groups);

	ret = rdtgroup_add_files(kernfs_root_to_node(rdt_root), RF_CTRL_BASE);
	if (ret) {
		kernfs_destroy_root(rdt_root);
		goto out;
	}

	rdtgroup_default.kn = kernfs_root_to_node(rdt_root);
	kernfs_activate(rdtgroup_default.kn);

out:
	mutex_unlock(&rdtgroup_mutex);

	return ret;
}

static void domain_destroy_mon_state(struct rdt_domain *d)
{
	bitmap_free(d->rmid_busy_llc);
	kfree(d->mbm_total);
	kfree(d->mbm_local);
}

static void _resctrl_offline_domain(struct rdt_resource *r,
				    struct rdt_domain *d)
{
	lockdep_assert_held(&rdtgroup_mutex);

	if (supports_mba_mbps() && r->rid == RDT_RESOURCE_MBA)
		mba_sc_domain_destroy(r, d);

	if (!r->mon_capable)
		return;

	/*
	 * If resctrl is mounted, remove all the
	 * per domain monitor data directories.
	 */
	if (resctrl_mounted && resctrl_arch_mon_capable())
		rmdir_mondata_subdir_allrdtgrp(r, d->id);

	if (resctrl_is_mbm_enabled())
		cancel_delayed_work(&d->mbm_over);
	if (resctrl_arch_is_llc_occupancy_enabled() && has_busy_rmid(r, d)) {
		/*
		 * When a package is going down, forcefully
		 * decrement rmid->ebusy. There is no way to know
		 * that the L3 was flushed and hence may lead to
		 * incorrect counts in rare scenarios, but leaving
		 * the RMID as busy creates RMID leaks if the
		 * package never comes back.
		 */
		__check_limbo(d, true);
		cancel_delayed_work(&d->cqm_limbo);
	}

	domain_destroy_mon_state(d);
}

void resctrl_offline_domain(struct rdt_resource *r, struct rdt_domain *d)
{
	mutex_lock(&rdtgroup_mutex);
	_resctrl_offline_domain(r, d);
	mutex_unlock(&rdtgroup_mutex);
}

static int domain_setup_mon_state(struct rdt_resource *r, struct rdt_domain *d)
{
	u32 idx_limit = resctrl_arch_system_num_rmid_idx();
	size_t tsize;

	if (resctrl_arch_is_llc_occupancy_enabled()) {
		d->rmid_busy_llc = bitmap_zalloc(idx_limit, GFP_KERNEL);
		if (!d->rmid_busy_llc)
			return -ENOMEM;
	}
	if (resctrl_arch_is_mbm_total_enabled()) {
		tsize = sizeof(*d->mbm_total);
		d->mbm_total = kcalloc(idx_limit, tsize, GFP_KERNEL);
		if (!d->mbm_total) {
			bitmap_free(d->rmid_busy_llc);
			return -ENOMEM;
		}
	}
	if (resctrl_arch_is_mbm_local_enabled()) {
		tsize = sizeof(*d->mbm_local);
		d->mbm_local = kcalloc(idx_limit, tsize, GFP_KERNEL);
		if (!d->mbm_local) {
			bitmap_free(d->rmid_busy_llc);
			kfree(d->mbm_total);
			return -ENOMEM;
		}
	}

	return 0;
}

static int _resctrl_online_domain(struct rdt_resource *r, struct rdt_domain *d)
{
	int err;

	lockdep_assert_held(&rdtgroup_mutex);

	if (is_mba_sc(r))
		/* RDT_RESOURCE_MBA is never mon_capable */
		return mba_sc_domain_allocate(r, d);

	if (!r->mon_capable)
		return 0;

	err = domain_setup_mon_state(r, d);
	if (err)
		return err;

	if (resctrl_is_mbm_enabled()) {
		INIT_DELAYED_WORK(&d->mbm_over, mbm_handle_overflow);
		mbm_setup_overflow_handler(d, MBM_OVERFLOW_INTERVAL,
					   RESCTRL_PICK_ANY_CPU);
	}

	if (resctrl_arch_is_llc_occupancy_enabled())
		INIT_DELAYED_WORK(&d->cqm_limbo, cqm_handle_limbo);

	if (resctrl_mounted && resctrl_arch_mon_capable())
		mkdir_mondata_subdir_allrdtgrp(r, d);

	return 0;
}

int resctrl_online_domain(struct rdt_resource *r, struct rdt_domain *d)
{
	int err;

	mutex_lock(&rdtgroup_mutex);
	err = _resctrl_online_domain(r, d);
	mutex_unlock(&rdtgroup_mutex);

	return err;
}

int resctrl_online_cpu(unsigned int cpu)
{
	mutex_lock(&rdtgroup_mutex);
	/* The cpu is set in default rdtgroup after online. */
	cpumask_set_cpu(cpu, &rdtgroup_default.cpu_mask);
	mutex_unlock(&rdtgroup_mutex);

	return 0;
}

static void clear_childcpus(struct rdtgroup *r, unsigned int cpu)
{
	struct rdtgroup *cr;

	list_for_each_entry(cr, &r->mon.crdtgrp_list, mon.crdtgrp_list) {
		if (cpumask_test_and_clear_cpu(cpu, &cr->cpu_mask))
			break;
	}
}

void resctrl_offline_cpu(unsigned int cpu)
{
	struct rdt_domain *d;
	struct rdtgroup *rdtgrp;
	struct rdt_resource *l3 = resctrl_arch_get_resource(RDT_RESOURCE_L3);

	mutex_lock(&rdtgroup_mutex);
	list_for_each_entry(rdtgrp, &rdt_all_groups, rdtgroup_list) {
		if (cpumask_test_and_clear_cpu(cpu, &rdtgrp->cpu_mask)) {
			clear_childcpus(rdtgrp, cpu);
			break;
		}
	}

	d = resctrl_get_domain_from_cpu(cpu, l3);
	if (d) {
		if (resctrl_is_mbm_enabled() && cpu == d->mbm_work_cpu) {
			cancel_delayed_work(&d->mbm_over);
			mbm_setup_overflow_handler(d, 0, cpu);
		}
		if (resctrl_arch_is_llc_occupancy_enabled() &&
		    cpu == d->cqm_work_cpu && has_busy_rmid(l3, d)) {
			cancel_delayed_work(&d->cqm_limbo);
			cqm_setup_limbo_handler(d, 0, cpu);
		}
	}
	mutex_unlock(&rdtgroup_mutex);
}

/*
 * resctrl_init - resctrl filesystem initialization
 *
 * Setup resctrl file system including set up root, create mount point,
 * register resctrl filesystem, and initialize files under root directory.
 *
 * Return: 0 on success or -errno
 */
int resctrl_init(void)
{
	int ret = 0;

	seq_buf_init(&last_cmd_status, last_cmd_status_buf,
		     sizeof(last_cmd_status_buf));

	ret = resctrl_mon_resource_init();
	if (ret)
		return ret;

	thread_throttle_mode_init();

	ret = rdtgroup_setup_root();
	if (ret)
		return ret;

	ret = sysfs_create_mount_point(fs_kobj, "resctrl");
	if (ret)
		goto cleanup_root;

	ret = register_filesystem(&rdt_fs_type);
	if (ret)
		goto cleanup_mountpoint;

	/*
	 * Adding the resctrl debugfs directory here may not be ideal since
	 * it would let the resctrl debugfs directory appear on the debugfs
	 * filesystem before the resctrl filesystem is mounted.
	 * It may also be ok since that would enable debugging of RDT before
	 * resctrl is mounted.
	 * The reason why the debugfs directory is created here and not in
	 * rdt_get_tree() is because rdt_get_tree() takes rdtgroup_mutex and
	 * during the debugfs directory creation also &sb->s_type->i_mutex_key
	 * (the lockdep class of inode->i_rwsem). Other filesystem
	 * interactions (eg. SyS_getdents) have the lock ordering:
	 * &sb->s_type->i_mutex_key --> &mm->mmap_lock
	 * During mmap(), called with &mm->mmap_lock, the rdtgroup_mutex
	 * is taken, thus creating dependency:
	 * &mm->mmap_lock --> rdtgroup_mutex for the latter that can cause
	 * issues considering the other two lock dependencies.
	 * By creating the debugfs directory here we avoid a dependency
	 * that may cause deadlock (even though file operations cannot
	 * occur until the filesystem is mounted, but I do not know how to
	 * tell lockdep that).
	 */
	debugfs_resctrl = debugfs_create_dir("resctrl", NULL);

	return 0;

cleanup_mountpoint:
	sysfs_remove_mount_point(fs_kobj, "resctrl");
cleanup_root:
	kernfs_destroy_root(rdt_root);

	return ret;
}

void resctrl_exit(void)
{
	debugfs_remove_recursive(debugfs_resctrl);
	unregister_filesystem(&rdt_fs_type);
	sysfs_remove_mount_point(fs_kobj, "resctrl");
	kernfs_destroy_root(rdt_root);
}
=======
>>>>>>> 5e2e13855c46 (rdtgroup)
