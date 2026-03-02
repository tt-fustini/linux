/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LINUX_RISCV_QOS_H
#define __LINUX_RISCV_QOS_H

#include <linux/resctrl_types.h>
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
		u32 cache_level;
		u32 cache_size; /* in bytes */
		struct cpumask cpu_mask;
		// Unique Cache ID from the PPTT table's Cache Type Structure
		u32 cache_id;
	} cache;

	struct mem_controller {
		// Proximity Domain from SRAT table Memory Affifinty Controller
		u32 prox_dom;
	} mem;
};

/* Capacity Controller hardware capabilities */
struct riscv_cbqri_capacity_caps {
        u16 ncblks; /* number of capacity blocks */
        u16 cache_level;
        u32 blk_size;

        bool supports_alloc_at_data;
        bool supports_alloc_at_code;

        bool supports_alloc_op_config_limit;
        bool supports_alloc_op_read_limit;
        bool supports_alloc_op_flush_rcid;

        bool supports_mon_at_data;
        bool supports_mon_at_code;

        bool supports_mon_op_config_event;
        bool supports_mon_op_read_counter;

        bool supports_mon_evt_id_none;
        bool supports_mon_evt_id_occupancy;
};

/* Bandwidth Controller hardware capabilities */
struct riscv_cbqri_bandwidth_caps {
        u16 nbwblks; /* number of bandwidth blocks */
        u16 mrbwb;   /* max reserved bw blocks */

        bool supports_alloc_at_data;
        bool supports_alloc_at_code;

        bool supports_alloc_op_config_limit;
        bool supports_alloc_op_read_limit;

        bool supports_mon_at_data;
        bool supports_mon_at_code;

        bool supports_mon_op_config_event;
        bool supports_mon_op_read_counter;

        bool supports_mon_evt_id_none;
        bool supports_mon_evt_id_rdwr_count;
        bool supports_mon_evt_id_rdonly_count;
        bool supports_mon_evt_id_wronly_count;
};

struct cbqri_controller {
        struct cbqri_controller_info *ctrl_info;
        void __iomem *base;

        int ver_major;
        int ver_minor;

        struct riscv_cbqri_bandwidth_caps bc;
        struct riscv_cbqri_capacity_caps cc;

        bool alloc_capable;
        bool mon_capable;
};

extern struct list_head cbqri_controllers;
extern int cbqri_controllers_size;

bool resctrl_arch_alloc_capable(void);
bool resctrl_arch_mon_capable(void);
bool resctrl_arch_is_llc_occupancy_enabled(void);
bool resctrl_arch_is_mbm_local_enabled(void);
bool resctrl_arch_is_mbm_total_enabled(void);

struct rdt_resource;
/*
 * Note about terminology between x86 (Intel RDT/AMD QoS) and RISC-V:
 *   CLOSID on x86 is RCID on RISC-V
 *     RMID on x86 is MCID on RISC-V
 *      CDP on x86 is AT (access type) on RISC-V
 */
u32  resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid);
void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid);
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 pmg);
void resctrl_arch_sched_in(struct task_struct *tsk);
void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid);
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
void resctrl_arch_reset_resources(void);
void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r, enum resctrl_event_id evtid);
void resctrl_arch_mon_ctx_free(struct rdt_resource *r, enum resctrl_event_id evtid,
			       void *arch_mon_ctx);
struct rdt_domain_hdr *resctrl_arch_find_domain(struct list_head *domain_list, int id);

static inline bool resctrl_arch_event_is_free_running(enum resctrl_event_id evt)
{
	/* must be true for resctrl L3 monitoring files to be created */
	return true;
}

static inline unsigned int resctrl_arch_round_mon_val(unsigned int val)
{
	return val;
}

/* Not needed for RISC-V */
static inline void resctrl_arch_enable_mon(void) { }
static inline void resctrl_arch_disable_mon(void) { }
static inline void resctrl_arch_enable_alloc(void) { }
static inline void resctrl_arch_disable_alloc(void) { }

#endif /* __LINUX_RISCV_QOS_H */
