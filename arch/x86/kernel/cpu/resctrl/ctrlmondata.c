// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Authors:
 *    Fenghua Yu <fenghua.yu@intel.com>
 *    Tony Luck <tony.luck@intel.com>
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2016, volume 3, section 17.17.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/cpu.h>
#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/tick.h>
#include "internal.h"

static bool apply_config(struct rdt_hw_domain *hw_dom,
			 struct resctrl_staged_config *cfg, u32 idx,
			 cpumask_var_t cpu_mask)
{
	struct rdt_domain *dom = &hw_dom->d_resctrl;

	if (cfg->new_ctrl != hw_dom->ctrl_val[idx]) {
		cpumask_set_cpu(cpumask_any(&dom->cpu_mask), cpu_mask);
		hw_dom->ctrl_val[idx] = cfg->new_ctrl;

		return true;
	}

	return false;
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	u32 idx = resctrl_get_config_index(closid, t);
	struct msr_param msr_param;

	if (!cpumask_test_cpu(smp_processor_id(), &d->cpu_mask))
		return -EINVAL;

	hw_dom->ctrl_val[idx] = cfg_val;

	msr_param.res = r;
	msr_param.low = idx;
	msr_param.high = idx + 1;
	hw_res->msr_update(d, &msr_param, r);

	return 0;
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	struct rdt_hw_domain *hw_dom;
	struct msr_param msr_param;
	enum resctrl_conf_type t;
	cpumask_var_t cpu_mask;
	struct rdt_domain *d;
	u32 idx;

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	if (!zalloc_cpumask_var(&cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	msr_param.res = NULL;
	list_for_each_entry(d, &r->domains, list) {
		hw_dom = resctrl_to_arch_dom(d);
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &hw_dom->d_resctrl.staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;

			idx = resctrl_get_config_index(closid, t);
			if (!apply_config(hw_dom, cfg, idx, cpu_mask))
				continue;

			if (!msr_param.res) {
				msr_param.low = idx;
				msr_param.high = msr_param.low + 1;
				msr_param.res = r;
			} else {
				msr_param.low = min(msr_param.low, idx);
				msr_param.high = max(msr_param.high, idx + 1);
			}
		}
	}

	if (cpumask_empty(cpu_mask))
		goto done;

	/* Update resource control msr on all the CPUs. */
	on_each_cpu_mask(cpu_mask, rdt_ctrl_update, &msr_param, 1);

done:
	free_cpumask_var(cpu_mask);

	return 0;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	u32 idx = resctrl_get_config_index(closid, type);

	return hw_dom->ctrl_val[idx];
}
<<<<<<< HEAD

static void show_doms(struct seq_file *s, struct resctrl_schema *schema, int closid)
{
	struct rdt_resource *r = schema->res;
	struct rdt_domain *dom;
	bool sep = false;
	u32 ctrl_val;

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	seq_printf(s, "%*s:", max_name_width, schema->name);
	list_for_each_entry(dom, &r->domains, list) {
		if (sep)
			seq_puts(s, ";");

		if (is_mba_sc(r))
			ctrl_val = dom->mbps_val[closid];
		else
			ctrl_val = resctrl_arch_get_config(r, dom, closid,
							   schema->conf_type);

		seq_printf(s, r->format_str, dom->id, max_data_width,
			   ctrl_val);
		sep = true;
	}
	seq_puts(s, "\n");
}

int rdtgroup_schemata_show(struct kernfs_open_file *of,
			   struct seq_file *s, void *v)
{
	struct resctrl_schema *schema;
	struct rdtgroup *rdtgrp;
	int ret = 0;
	u32 closid;

	rdtgrp = rdtgroup_kn_lock_live(of->kn);
	if (rdtgrp) {
		if (rdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP) {
			list_for_each_entry(schema, &resctrl_schema_all, list) {
				seq_printf(s, "%s:uninitialized\n", schema->name);
			}
		} else if (rdtgrp->mode == RDT_MODE_PSEUDO_LOCKED) {
			if (!rdtgrp->plr->d) {
				rdt_last_cmd_clear();
				rdt_last_cmd_puts("Cache domain offline\n");
				ret = -ENODEV;
			} else {
				seq_printf(s, "%s:%d=%x\n",
					   rdtgrp->plr->s->res->name,
					   rdtgrp->plr->d->id,
					   rdtgrp->plr->cbm);
			}
		} else {
			closid = rdtgrp->closid;
			list_for_each_entry(schema, &resctrl_schema_all, list) {
				if (closid < schema->num_closid)
					show_doms(s, schema, closid);
			}
		}
	} else {
		ret = -ENOENT;
	}
	rdtgroup_kn_unlock(of->kn);
	return ret;
}

void mon_event_read(struct rmid_read *rr, struct rdt_resource *r,
		    struct rdt_domain *d, struct rdtgroup *rdtgrp,
		    int evtid, int first)
{
	int cpu;

	/* When picking a cpu from cpu_mask, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	/*
	 * setup the parameters to pass to mon_event_count() to read the data.
	 */
	rr->rgrp = rdtgrp;
	rr->evtid = evtid;
	rr->r = r;
	rr->d = d;
	rr->val = 0;
	rr->first = first;

	cpu = cpumask_any_housekeeping(&d->cpu_mask);
	smp_call_on_cpu(cpu, mon_event_count, rr, false);
}

int rdtgroup_mondata_show(struct seq_file *m, void *arg)
{
	struct kernfs_open_file *of = m->private;
	u32 resid, evtid, domid;
	struct rdtgroup *rdtgrp;
	struct rdt_resource *r;
	union mon_data_bits md;
	struct rdt_domain *d;
	struct rmid_read rr;
	int ret = 0;

	rdtgrp = rdtgroup_kn_lock_live(of->kn);
	if (!rdtgrp) {
		ret = -ENOENT;
		goto out;
	}

	md.priv = of->kn->priv;
	resid = md.u.rid;
	domid = md.u.domid;
	evtid = md.u.evtid;

	r = resctrl_arch_get_resource(resid);
	d = resctrl_arch_find_domain(r, domid);
	if (IS_ERR_OR_NULL(d)) {
		ret = -ENOENT;
		goto out;
	}

	mon_event_read(&rr, r, d, rdtgrp, evtid, false);

	if (rr.err == -EIO)
		seq_puts(m, "Error\n");
	else if (rr.err == -EINVAL)
		seq_puts(m, "Unavailable\n");
	else
		seq_printf(m, "%llu\n", rr.val);

out:
	rdtgroup_kn_unlock(of->kn);
	return ret;
}
=======
>>>>>>> 8d5950564c66 (ctrlmondata)
