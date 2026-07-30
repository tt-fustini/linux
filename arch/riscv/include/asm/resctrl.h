/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_RESCTRL_H
#define _ASM_RISCV_RESCTRL_H

#include <linux/resctrl_types.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <asm/qos.h>

struct rdt_resource;

/*
 * Sentinel "no CLOSID assigned" used by resctrl_arch_rmid_idx_decode().
 * resctrl treats this opaquely. CBQRI uses MCID directly as the linear
 * rmid index, so closid is unused on decode.
 */
#define RISCV_RESCTRL_EMPTY_CLOSID	((u32)~0)

/*
 * Terminology mapping between x86 (Intel RDT/AMD QoS) and RISC-V:
 *
 *  CLOSID on x86 is RCID on RISC-V
 *    RMID on x86 is MCID on RISC-V
 *     CDP on x86 is AT (access type) on RISC-V
 */

/**
 * resctrl_arch_alloc_capable() - any CBQRI controller exposes resctrl alloc
 *
 * True while at least one resource set up by cbqri_resctrl_setup() has
 * rdt_resource::alloc_capable set, so it gives the same answer as walking
 * the resources. Only meaningful after late_initcall.
 */
bool resctrl_arch_alloc_capable(void);

/**
 * resctrl_arch_mon_capable() - any CBQRI controller exposes resctrl monitoring
 *
 * The CBQRI driver implements capacity allocation only and wires up no
 * monitoring events, so this always returns false. resctrl references it
 * unconditionally, hence the stub.
 */
bool resctrl_arch_mon_capable(void);

/**
 * resctrl_arch_rmid_idx_encode() - encode (RCID, MCID) into a linear index
 * @closid: RCID (resource control id)
 * @rmid:   MCID (monitoring counter id)
 *
 * RISC-V uses MCID directly as the linear index into per-RMID arrays
 * managed by resctrl, since CBQRI controllers admit any MCID for any
 * RCID. closid is unused here. CDP is encoded via the AT field on each
 * CBQRI op rather than via the index.
 */
u32  resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid);

/**
 * resctrl_arch_rmid_idx_decode() - inverse of resctrl_arch_rmid_idx_encode()
 * @idx:    linear index
 * @closid: out: always RISCV_RESCTRL_EMPTY_CLOSID
 * @rmid:   out: the MCID that @idx encodes
 */
void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid);

/**
 * resctrl_arch_set_cpu_default_closid_rmid() - install per-CPU srmcfg default
 * @cpu:    CPU number
 * @closid: the CPU's default RCID
 * @rmid:   the CPU's default MCID
 *
 * Sets the per-CPU cpu_srmcfg_default that __switch_to_srmcfg() falls back
 * to, field by field: a task whose RCID is RESCTRL_RESERVED_CLOSID (0)
 * takes the CPU's RCID, and one whose MCID is RESCTRL_RESERVED_RMID (0)
 * takes the CPU's MCID. Implements resctrl allocation rule 2 ("CPU
 * default") on RISC-V.
 */
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid);

/**
 * resctrl_arch_sched_in() - install the current task's RCID/MCID on this CPU
 * @tsk: the task to install, always the current task
 *
 * Writes tsk->thread.srmcfg into the srmcfg CSR through
 * __switch_to_srmcfg(), the same path switch_to() takes. resctrl calls it
 * on the task's own CPU after retagging the task or changing the CPU
 * default. A zero RCID or MCID field takes the per-CPU default set via
 * resctrl_arch_set_cpu_default_closid_rmid().
 */
void resctrl_arch_sched_in(struct task_struct *tsk);

/**
 * resctrl_arch_set_closid_rmid() - tag a task with an RCID/MCID
 * @tsk:    task to tag
 * @closid: RCID to install
 * @rmid:   MCID to install
 *
 * Updates tsk->thread.srmcfg with the encoded (RCID, MCID) pair. The new
 * value reaches the CSR at the task's next switch_to(), or right away
 * through resctrl_arch_sched_in() when resctrl retags a running task.
 */
void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid);

/**
 * resctrl_arch_match_closid() - test whether a task carries a given RCID
 * @tsk:    task
 * @closid: RCID
 */
bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid);

/**
 * resctrl_arch_match_rmid() - test whether a task carries a given (RCID, MCID)
 * @tsk:    task
 * @closid: RCID
 * @rmid:   MCID
 */
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid);

/**
 * resctrl_arch_mon_ctx_alloc() - allocate per-monitor-event arch context
 * @r:     resctrl resource being monitored
 * @evtid: which monitor event needs context
 *
 * The CBQRI driver implements no monitoring events, so there is no per-event
 * context to allocate and the stub returns NULL.
 */
void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r, enum resctrl_event_id evtid);

/**
 * resctrl_arch_mon_ctx_free() - release context returned by mon_ctx_alloc()
 * @r:            resctrl resource
 * @evtid:        monitor event id
 * @arch_mon_ctx: pointer returned by resctrl_arch_mon_ctx_alloc()
 */
void resctrl_arch_mon_ctx_free(struct rdt_resource *r, enum resctrl_event_id evtid,
			       void *arch_mon_ctx);

static inline unsigned int resctrl_arch_round_mon_val(unsigned int val)
{
	return val;
}

/* Not needed for RISC-V */
static inline void resctrl_arch_enable_mon(void) { }
static inline void resctrl_arch_disable_mon(void) { }
static inline void resctrl_arch_enable_alloc(void) { }
static inline void resctrl_arch_disable_alloc(void) { }

#endif /* _ASM_RISCV_RESCTRL_H */
