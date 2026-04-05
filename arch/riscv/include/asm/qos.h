/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_QOS_H
#define _ASM_RISCV_QOS_H

#ifdef CONFIG_RISCV_ISA_SSQOSID

#include <linux/sched.h>

#include <asm/csr.h>
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
		__this_cpu_write(cpu_srmcfg, thread_srmcfg);
		csr_write(CSR_SRMCFG, thread_srmcfg);
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
