/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LINUX_RISCV_QOS_H
#define __LINUX_RISCV_QOS_H

#include <linux/mutex.h>
#include <linux/resctrl_types.h>
#include <linux/types.h>

#include <asm/qos.h>

enum cbqri_controller_type {
	CBQRI_CONTROLLER_TYPE_CAPACITY,
	CBQRI_CONTROLLER_TYPE_BANDWIDTH,
	CBQRI_CONTROLLER_TYPE_UNKNOWN
};

/* Capacity Controller hardware capabilities */
struct riscv_cbqri_capacity_caps {
	u16 ncblks; /* number of capacity blocks */

	bool supports_alloc_at_code;
};

/* Bandwidth Controller hardware capabilities */
struct riscv_cbqri_bandwidth_caps {
	u16 nbwblks; /* number of bandwidth blocks */
	u16 mrbwb;   /* max reserved bw blocks */

	bool supports_alloc_at_code;
};

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

	struct riscv_cbqri_bandwidth_caps bc;
	struct riscv_cbqri_capacity_caps cc;

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

bool resctrl_arch_alloc_capable(void);

struct rdt_resource;
/*
 * Note about terminology between x86 (Intel RDT/AMD QoS) and RISC-V:
 *   CLOSID on x86 is RCID on RISC-V
 *     RMID on x86 is MCID on RISC-V
 *      CDP on x86 is AT (access type) on RISC-V
 */
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid);
void resctrl_arch_sched_in(struct task_struct *tsk);
void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid);
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid);

/* Not needed for RISC-V */
static inline void resctrl_arch_enable_alloc(void) { }
static inline void resctrl_arch_disable_alloc(void) { }

#endif /* __LINUX_RISCV_QOS_H */
