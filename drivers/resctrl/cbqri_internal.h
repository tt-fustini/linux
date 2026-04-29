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
#define CBQRI_CC_MON_CTL_VAL_OFF 16
#define CBQRI_CC_ALLOC_CTL_OFF   24
#define CBQRI_CC_BLOCK_MASK_OFF  32

#define CBQRI_BC_CAPABILITIES_OFF 0
#define CBQRI_BC_MON_CTL_OFF      8
#define CBQRI_BC_ALLOC_CTL_OFF   24
#define CBQRI_BC_BW_ALLOC_OFF    32

/*
 * Smallest MMIO span the driver actually accesses: highest defined
 * register offset (0x20) plus the 8-byte register width.  Used by
 * cbqri_probe_controller() to reject undersized firmware-supplied
 * mappings before request_mem_region/ioremap, so a u64 access at
 * BLOCK_MASK / BW_ALLOC does not walk past the end of the mapping.
 */
#define CBQRI_CTRL_MIN_REG_SPAN  0x28u

#define CBQRI_CC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_CC_CAPABILITIES_NCBLKS_MASK  GENMASK(23, 8)

#define CBQRI_BC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_BC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_BC_CAPABILITIES_NBWBLKS_MASK  GENMASK(23, 8)
#define CBQRI_BC_CAPABILITIES_MRBWB_MASK    GENMASK_ULL(47, 32)

#define CBQRI_CONTROL_REGISTERS_OP_MASK      GENMASK(4, 0)
#define CBQRI_CONTROL_REGISTERS_AT_MASK      GENMASK(7, 5)
#define CBQRI_CONTROL_REGISTERS_AT_DATA      0
#define CBQRI_CONTROL_REGISTERS_AT_CODE      1
#define CBQRI_CONTROL_REGISTERS_RCID_MASK    GENMASK(19, 8)
#define CBQRI_CONTROL_REGISTERS_STATUS_MASK  GENMASK_ULL(38, 32)
#define CBQRI_CONTROL_REGISTERS_BUSY_MASK    GENMASK_ULL(39, 39)
#define CBQRI_CONTROL_REGISTERS_RBWB_MASK    GENMASK(15, 0)
#define CBQRI_CONTROL_REGISTERS_MWEIGHT_MASK GENMASK(27, 20)

#define CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS  1

#define CBQRI_BC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS  1

#define CBQRI_CC_MON_CTL_OP_CONFIG_EVENT 1
#define CBQRI_CC_MON_CTL_OP_READ_COUNTER 2
#define CBQRI_CC_MON_CTL_STATUS_SUCCESS  1

/*
 * bc_mon_ctl op and status used during probe to detect monitoring support.
 * The full monitoring path (CONFIG_EVENT, READ_COUNTER on a real RMID) is
 * added by the bandwidth monitoring patch.
 */
#define CBQRI_BC_MON_CTL_OP_READ_COUNTER 2
#define CBQRI_BC_MON_CTL_STATUS_SUCCESS  1

/* cc_mon_ctl / bc_mon_ctl field masks (same layout as alloc_ctl plus EVT_ID) */
#define CBQRI_MON_CTL_OP_MASK        GENMASK(4, 0)
#define CBQRI_MON_CTL_MCID_MASK      GENMASK(19, 8)
#define CBQRI_MON_CTL_EVT_ID_MASK    GENMASK(27, 20)
#define CBQRI_MON_CTL_STATUS_MASK    GENMASK_ULL(38, 32)

/* Capacity usage monitoring event IDs (CBQRI spec Table 4) */
#define CBQRI_CC_EVT_ID_NONE         0
#define CBQRI_CC_EVT_ID_OCCUPANCY    1

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
	 * out - typically a stuck or unresponsive controller.  Once
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

	/*
	 * Per-RCID cache of the most recent Rbwb value applied via
	 * CONFIG_LIMIT.  Lets cbqri_apply_rbwb() validate the
	 * sum(Rbwb) <= MRBWB invariant in O(rcid_count) memory accesses
	 * instead of O(rcid_count) READ_LIMIT round trips, each of which
	 * spends up to 1 ms in cbqri_wait_busy_flag() under ->lock.
	 * Allocated by cbqri_probe_bc(); NULL on capacity controllers.
	 */
	u16 *rbwb_cache;

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

struct cbqri_resctrl_dom {
	struct rdt_ctrl_domain  resctrl_ctrl_dom;
	struct cbqri_controller *hw_ctrl;
};

#endif /* _DRIVERS_RESCTRL_CBQRI_INTERNAL_H */
