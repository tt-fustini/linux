/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LINUX_RISCV_QOS_H
#define __LINUX_RISCV_QOS_H

#include <linux/spinlock.h>
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
	bool supports_alloc_op_flush_rcid;
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
	 * Protects multi-step MMIO register sequences on this controller.
	 * CBQRI operations (e.g. CONFIG_LIMIT, READ_LIMIT) require writing
	 * an operation register, waiting for the busy flag to clear, then
	 * reading back the result. These sequences must be atomic per
	 * controller to prevent interleaving.
	 */
	spinlock_t lock;

	int ver_major;
	int ver_minor;

	struct riscv_cbqri_bandwidth_caps bc;
	struct riscv_cbqri_capacity_caps cc;

	bool alloc_capable;

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

#endif /* __LINUX_RISCV_QOS_H */
