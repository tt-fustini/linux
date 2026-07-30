/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Public registration API for the RISC-V Capacity and Bandwidth QoS
 * Register Interface (CBQRI) core. Discovery layers call
 * riscv_cbqri_register_cc() to hand a capacity controller descriptor to
 * the core, which owns all subsequent state.
 */
#ifndef _LINUX_RISCV_CBQRI_H
#define _LINUX_RISCV_CBQRI_H

#include <linux/types.h>

enum cbqri_controller_type {
	CBQRI_CONTROLLER_TYPE_CAPACITY,
};

/**
 * struct cbqri_controller_info - registration descriptor
 * @addr:        MMIO base address of the controller's register interface
 * @size:        size of the MMIO region
 * @type:        controller type (capacity)
 * @rcid_count:  number of supported RCIDs
 * @cache_id:    cache id used as the resctrl domain id
 * @cache_level: cache level (2 or 3) the controller backs
 * @base:        mapped register block, which the caller keeps mapped for
 *               the life of the system
 */
struct cbqri_controller_info {
	phys_addr_t			addr;
	phys_addr_t			size;
	void __iomem			*base;
	enum cbqri_controller_type	type;
	u32				rcid_count;
	u32				cache_id;
	u32				cache_level;
};

#if IS_ENABLED(CONFIG_RISCV_CBQRI)
int riscv_cbqri_register_cc(const struct cbqri_controller_info *info);
#else
static inline int
riscv_cbqri_register_cc(const struct cbqri_controller_info *info)
{
	return -ENODEV;
}
#endif

#endif /* _LINUX_RISCV_CBQRI_H */
