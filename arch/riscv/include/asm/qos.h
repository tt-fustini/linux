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

	/* Default-group tasks (thread.srmcfg == 0) follow this CPU's default. */
	if (thread_srmcfg == 0)
		thread_srmcfg = __this_cpu_read(cpu_srmcfg_default);

	if (thread_srmcfg != __this_cpu_read(cpu_srmcfg)) {
		/*
		 * Drain stores from the outgoing task before the CSR write
		 * so they retain the previous RCID/MCID tag at the cache
		 * interconnect.
		 */
		RISCV_FENCE(rw, o);

		__this_cpu_write(cpu_srmcfg, thread_srmcfg);
		csr_write(CSR_SRMCFG, thread_srmcfg);
		/*
		 * Order the csrw before the new task's loads/stores so they
		 * pick up the new tag. Zicsr 6.1.1 makes CSR writes weakly
		 * ordered (device-output) vs memory ops. Ssqosid v1.0 is
		 * silent so honor the general CSR rule.
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
