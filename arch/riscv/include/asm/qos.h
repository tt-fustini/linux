/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_QOS_H
#define _ASM_RISCV_QOS_H

#ifdef CONFIG_RISCV_ISA_SSQOSID

#include <linux/sched.h>
#include <linux/jump_label.h>

#include <asm/barrier.h>
#include <asm/csr.h>
#include <asm/hwcap.h>

/* cached value of sqoscfg csr for each cpu */
static DEFINE_PER_CPU(u32, cpu_sqoscfg);

static void __qos_sched_in(struct task_struct *task)
{
	u32 *cpu_sqoscfg_ptr = this_cpu_ptr(&cpu_sqoscfg);
	u32 thread_sqoscfg;

	thread_sqoscfg = READ_ONCE(task->thread.sqoscfg);

	if (thread_sqoscfg != *cpu_sqoscfg_ptr) {
		*cpu_sqoscfg_ptr = thread_sqoscfg;
		csr_write(CSR_SQOSCFG, thread_sqoscfg);
	}
}

static inline void qos_sched_in(struct task_struct *task)
{
	if (riscv_has_extension_likely(RISCV_ISA_EXT_SSQOSID))
		__qos_sched_in(task);
}
#else

static inline void qos_sched_in(struct task_struct *task) {}

#endif /* CONFIG_RISCV_ISA_SSQOSID */
#endif /* _ASM_RISCV_QOS_H */
