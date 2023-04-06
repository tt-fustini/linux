/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LINUX_RISCV_QOS_H
#define __LINUX_RISCV_QOS_H

#include <linux/iommu.h>
#include <linux/types.h>

#include <asm/qos.h>

enum cbqri_controller_type {
	CBQRI_CONTROLLER_TYPE_CAPACITY,
	CBQRI_CONTROLLER_TYPE_BANDWIDTH,
	CBQRI_CONTROLLER_TYPE_UNKNOWN
};

struct cbqri_controller_info {
	unsigned long addr;
	unsigned long size;
	enum cbqri_controller_type type;
	u32 rcid_count;
	u32 mcid_count;
	struct list_head list;

	struct cache_controller {
		int cache_level;
		u32 cache_size; /* in bytes */
		struct cpumask cpu_mask;
	} cache;
};

extern struct list_head cbqri_controllers;

#endif /* __LINUX_RISCV_QOS_H */
