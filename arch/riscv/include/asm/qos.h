/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_QOS_H
#define _ASM_RISCV_QOS_H

#ifdef CONFIG_RISCV_ISA_SSQOSID

#include <linux/sched.h>
#include <linux/jump_label.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/csr.h>
#include <asm/hwcap.h>

/* cached value of sqoscfg csr for each cpu */
DECLARE_PER_CPU(u32, cpu_sqoscfg);

static inline void __switch_to_sqoscfg(struct task_struct *prev,
				       struct task_struct *next)
{
	u32 *cpu_sqoscfg_ptr = this_cpu_ptr(&cpu_sqoscfg);
	u32 thread_sqoscfg;

	thread_sqoscfg = READ_ONCE(next->thread.sqoscfg);

	if (thread_sqoscfg != *cpu_sqoscfg_ptr) {
		*cpu_sqoscfg_ptr = thread_sqoscfg;
		csr_write(CSR_SQOSCFG, thread_sqoscfg);
	}
}

static __always_inline bool has_sqoscfg(void)
{
	return riscv_has_extension_likely(RISCV_ISA_EXT_SSQOSID);
}

#else /* ! CONFIG_RISCV_ISA_SSQOSID  */

static __always_inline bool has_sqoscfg(void) { return false; }
#define __switch_to_sqoscfg(__prev, __next) do { } while (0)

#endif /* CONFIG_RISCV_ISA_SSQOSID */

#endif /* _ASM_RISCV_QOS_H */
