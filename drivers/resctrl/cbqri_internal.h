/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DRIVERS_RESCTRL_CBQRI_INTERNAL_H
#define _DRIVERS_RESCTRL_CBQRI_INTERNAL_H

#include <linux/bitfield.h>
#include <linux/cbqri.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/resctrl.h>
#include <linux/types.h>

#define RISCV_RESCTRL_EMPTY_CLOSID	((u32)~0)

#define CBQRI_CC_CAPABILITIES_OFF 0
#define CBQRI_CC_MON_CTL_OFF      8
#define CBQRI_CC_ALLOC_CTL_OFF   24
#define CBQRI_CC_BLOCK_MASK_OFF  32

/*
 * Smallest MMIO span the driver actually accesses: highest defined
 * register offset (0x20) plus the 8-byte register width.  Used by
 * cbqri_probe_controller() to reject undersized firmware-supplied
 * mappings before request_mem_region/ioremap, so a u64 access at
 * BLOCK_MASK does not walk past the end of the mapping.
 */
#define CBQRI_CTRL_MIN_REG_SPAN  0x28u

#define CBQRI_CC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_CC_CAPABILITIES_NCBLKS_MASK  GENMASK(23, 8)

#define CBQRI_CONTROL_REGISTERS_OP_MASK      GENMASK(4, 0)
#define CBQRI_CONTROL_REGISTERS_AT_MASK      GENMASK(7, 5)
#define CBQRI_CONTROL_REGISTERS_AT_DATA      0
#define CBQRI_CONTROL_REGISTERS_AT_CODE      1
#define CBQRI_CONTROL_REGISTERS_RCID_MASK    GENMASK(19, 8)
#define CBQRI_CONTROL_REGISTERS_STATUS_MASK  GENMASK_ULL(38, 32)
#define CBQRI_CONTROL_REGISTERS_BUSY_MASK    GENMASK_ULL(39, 39)

#define CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS  1

/* Capacity Controller hardware capabilities */
struct riscv_cbqri_capacity_caps {
	u16 ncblks; /* number of capacity blocks */

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
	 * out - typically a stuck or unresponsive controller.  Once
	 * set, every subsequent CBQRI op fails fast with -EIO instead
	 * of repeating the 1 ms busy-poll.
	 */
	bool faulted;

	int ver_major;
	int ver_minor;

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
 * @cdp_enabled: resctrl has enabled CDP for this rid via
 *               resctrl_arch_set_cdp_enabled().  Read by
 *               cbqri_apply_cache_config() to decide whether one or two
 *               CONFIG_LIMIT operations are issued per schemata write.
 *               Only meaningful for RDT_RESOURCE_L2 / RDT_RESOURCE_L3.
 *               Mirrors struct rdt_hw_resource::cdp_enabled on x86; the
 *               capability flag lives on @resctrl_res.cdp_capable
 *               (struct rdt_resource), populated by
 *               cbqri_resctrl_control_init().
 * @resctrl_res: the rdt_resource exposed to fs/resctrl.
 */
struct cbqri_resctrl_res {
	struct cbqri_controller *ctrl;
	bool                    cdp_enabled;
	struct rdt_resource     resctrl_res;
};

struct cbqri_resctrl_dom {
	struct rdt_ctrl_domain  resctrl_ctrl_dom;
	struct cbqri_controller *hw_ctrl;
};

#endif /* _DRIVERS_RESCTRL_CBQRI_INTERNAL_H */
