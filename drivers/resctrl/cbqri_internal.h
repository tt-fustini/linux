/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DRIVERS_RESCTRL_CBQRI_INTERNAL_H
#define _DRIVERS_RESCTRL_CBQRI_INTERNAL_H

#include <linux/cbqri.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/resctrl.h>
#include <linux/types.h>

#define RISCV_RESCTRL_EMPTY_CLOSID	((u32)~0)

struct cbqri_controller {
	void __iomem *base;
	/*
	 * Serialises multi-step MMIO register sequences on this
	 * controller.  Each CBQRI operation (CONFIG_LIMIT, READ_LIMIT,
	 * CONFIG_EVENT, READ_COUNTER, ...) is a write-then-poll-busy
	 * cycle that may take up to 1 ms on slow firmware; using a
	 * sleeping mutex (paired with the sleeping readq_poll_timeout()
	 * variant in cbqri_wait_busy_flag()) keeps preemption enabled
	 * across the busy-wait, which is required for PREEMPT_RT and
	 * avoids interrupt-latency spikes on contending CPUs.  All
	 * resctrl-arch entry points run in process context, so a
	 * sleeping lock is safe.
	 */
	struct mutex lock;
	/*
	 * Sticky failure flag.  Set when cbqri_wait_busy_flag() times
	 * out -- typically a stuck or unresponsive controller.  Once
	 * set, every subsequent CBQRI op fails fast with -EIO instead
	 * of repeating the 1 ms busy-poll.
	 */
	bool faulted;

	int ver_major;
	int ver_minor;

	bool alloc_capable;
	bool mon_capable;

	phys_addr_t addr;
	phys_addr_t size;
	enum cbqri_controller_type type;
	u32 rcid_count;
	u32 mcid_count;

	struct list_head list;

	struct cache_controller {
		u32 cache_level;
		u32 cache_size; /* in bytes */
		struct cpumask cpu_mask;
		/* Unique Cache ID from the PPTT table's Cache Type Structure */
		u32 cache_id;
	} cache;

	struct mem_controller {
		/* Proximity Domain from SRAT table Memory Affinity Controller */
		u32 prox_dom;
		struct cpumask cpu_mask;
	} mem;
};

extern struct list_head cbqri_controllers;

void cbqri_controller_destroy(struct cbqri_controller *ctrl);

int qos_resctrl_setup(void);
void qos_resctrl_teardown(void);
int qos_resctrl_online_cpu(unsigned int cpu);
int qos_resctrl_offline_cpu(unsigned int cpu);

/**
 * struct cbqri_resctrl_res - resctrl resource backed by one CBQRI controller
 * @ctrl:        the controller chosen by cbqri_resctrl_pick_*() to back this
 *               rid; NULL means no probed controller could back this rid.
 *               When multiple controllers share the same rid (e.g. one L3
 *               capacity controller per socket), @ctrl is one representative
 *               used to fill rdt_resource caps; per-controller rdt_ctrl_domains
 *               are still registered for every matching controller.
 * @resctrl_res: the rdt_resource exposed to fs/resctrl.
 */
struct cbqri_resctrl_res {
	struct cbqri_controller *ctrl;
	struct rdt_resource     resctrl_res;
};

#endif /* _DRIVERS_RESCTRL_CBQRI_INTERNAL_H */
