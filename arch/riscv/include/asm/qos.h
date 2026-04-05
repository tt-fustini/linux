/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_QOS_H
#define _ASM_RISCV_QOS_H

#include <linux/percpu-defs.h>

#ifdef CONFIG_RISCV_ISA_SSQOSID

#include <linux/cpufeature.h>
#include <linux/sched.h>

#include <asm/csr.h>
#include <asm/fence.h>
#include <asm/hwcap.h>

/* cached value of srmcfg csr for each cpu */
DECLARE_PER_CPU(u32, cpu_srmcfg);

/* default srmcfg value for each cpu, set via resctrl cpu assignment */
DECLARE_PER_CPU(u32, cpu_srmcfg_default);

static inline void __switch_to_srmcfg(struct task_struct *next)
{
	u32 thread_srmcfg;

	thread_srmcfg = READ_ONCE(next->thread.srmcfg);

	/*
	 * Tasks in the default resource group have closid=0 and rmid=0,
	 * so thread.srmcfg is 0.  For these tasks, use this CPU's default
	 * srmcfg instead.  This implements resctrl rule 2: a default-group
	 * task running on a CPU assigned to a specific group uses that
	 * group's allocations.
	 */
	if (thread_srmcfg == 0)
		thread_srmcfg = __this_cpu_read(cpu_srmcfg_default);

	if (thread_srmcfg != __this_cpu_read(cpu_srmcfg)) {
		/*
		 * Drain any in-flight loads/stores from the departing task
		 * before the CSR change.  Without `fence rw,o`, RISC-V WMO
		 * permits stores still in this hart's store buffer to reach
		 * the cache interconnect AFTER the new SRMCFG has taken
		 * effect, where they would be tagged with the new task's
		 * RCID/MCID and charged to the wrong resource group.
		 * Mirrors how ARM MPAM emits `dsb(ish)` before the MPAM
		 * register write to drain old-task traffic.
		 */
		RISCV_FENCE(rw, o);

		__this_cpu_write(cpu_srmcfg, thread_srmcfg);
		csr_write(CSR_SRMCFG, thread_srmcfg);
		/*
		 * Order the CSR write before the new task's first memory
		 * accesses.  Per Zicsr 6.1.1, CSR writes are weakly ordered
		 * against memory operations and classified as device-output
		 * for fence purposes; without `fence o,rw` the new task's
		 * loads/stores could be tagged at the cache interconnect
		 * with the previous task's RCID/MCID before the csrw is
		 * observed.  Mirrors how ARM MPAM emits `isb()` after the
		 * MPAM register write to make the new tag visible to the
		 * pipeline before subsequent ops execute.
		 * The Ssqosid v1.0 spec itself is silent on synchronisation
		 * requirements, so honour the general CSR-ordering rule.
		 */
		RISCV_FENCE(o, rw);
	}
}

static __always_inline bool has_srmcfg(void)
{
	return riscv_has_extension_unlikely(RISCV_ISA_EXT_SSQOSID);
}

#else /* ! CONFIG_RISCV_ISA_SSQOSID  */

struct task_struct;
static __always_inline bool has_srmcfg(void) { return false; }
static inline void __switch_to_srmcfg(struct task_struct *next) { }

#endif /* CONFIG_RISCV_ISA_SSQOSID */
#endif /* _ASM_RISCV_QOS_H */
