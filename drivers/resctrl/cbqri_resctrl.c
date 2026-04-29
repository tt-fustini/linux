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

/*
 * Probe a controller's hardware.  Capacity and bandwidth controller
 * support is added in subsequent patches; the scaffolding patch only
 * validates the descriptor and rejects every type so a misconfigured
 * platform fails fast at boot instead of advertising a half-initialised
 * resource through resctrl.
 */
static int cbqri_probe_controller(struct cbqri_controller *ctrl)
{
	pr_debug("controller info: type=%d addr=%pa size=%pa max-rcid=%u max-mcid=%u\n",
		 ctrl->type, &ctrl->addr, &ctrl->size,
		 ctrl->rcid_count, ctrl->mcid_count);

	if (!ctrl->addr) {
		pr_warn("controller has invalid addr=0x0, skipping\n");
		return -EINVAL;
	}

	pr_warn("controller type %d not yet supported\n", ctrl->type);
	return -ENODEV;
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
	/* No allocation resources backed in scaffolding; added per-feature later. */
}

void resctrl_arch_pre_mount(void)
{
	/* All controllers discovered at boot via late_initcall; nothing to do */
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	/* No allocation resources backed in scaffolding; added per-feature later. */
	return -EINVAL;
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	/* No allocation resources backed in scaffolding; added per-feature later. */
	return 0;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	/* No allocation resources backed in scaffolding; report the default. */
	return resctrl_get_default_ctrl(r);
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
	struct cbqri_controller *ctrl, *tmp;

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
	 * Probe every controller.  No controller types are supported in
	 * the scaffolding patch -- each successful registration falls
	 * straight into a probe failure here.  Per-type probe and resctrl
	 * integration land in the cache and bandwidth feature patches.
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

	err = resctrl_init();
	if (err)
		goto err_free_controllers_list;
	qos_resctrl_inited = true;

	return 0;

err_free_controllers_list:
	qos_resctrl_teardown();
	return err;
}

int qos_resctrl_online_cpu(unsigned int cpu)
{
	/*
	 * Hardware resets CSR_SRMCFG to 0 when a CPU is offlined/re-onlined.
	 * Zero the cached value so the next context switch always re-programs
	 * the CSR rather than skipping it as "unchanged".
	 */
	per_cpu(cpu_srmcfg, cpu) = 0;
	resctrl_online_cpu(cpu);
	return 0;
}

int qos_resctrl_offline_cpu(unsigned int cpu)
{
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
