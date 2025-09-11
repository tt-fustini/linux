/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_QOS_H
#define _ASM_RISCV_QOS_H

#ifdef CONFIG_RISCV_ISA_SSQOSID

#include <linux/sched.h>
#include <linux/jump_label.h>

#include <asm/barrier.h>
#include <asm/csr.h>
#include <asm/hwcap.h>

static inline void __switch_to_srmcfg(struct task_struct *prev, struct task_struct *next)
{
	u32 csr_srmcfg, prev_srmcfg, next_srmcfg;

	prev_srmcfg = READ_ONCE(prev->thread.srmcfg);
	next_srmcfg = READ_ONCE(next->thread.srmcfg);
	csr_srmcfg = csr_read(CSR_SRMCFG);

	if(csr_srmcfg != prev_srmcfg)
	{
		trace_printk("WARNING CSR_SRCFG = 0x%02x \t prev_srmcfg: 0x%02x \t next_srmcfg: 0x%02x\n", csr_srmcfg, prev_srmcfg, next_srmcfg);
		pr_err("WARNING CSR_SRCFG = 0x%02x \t prev_srmcfg: 0x%02x \t next_srmcfg: 0x%02x\n", csr_srmcfg, prev_srmcfg, next_srmcfg);
	}

	if ( prev_srmcfg != csr_srmcfg )
	{
		//trace_printk("CSR_SRCFG = 0x%02x \t prev: %03d [0x%02x] srmcfg: 0x%02x \t next: %03d [0x%02x] srmcfg: 0x%02x\n", csr_srmcfg, prev->pid, prev->pid, prev_srmcfg, next->pid, next->pid, next_srmcfg);
	}

	if (next_srmcfg != prev_srmcfg)
	{
		//trace_printk("next_srmcfg != prev_srmcfg; write next_srmcfg 0x%02x to CSR_SRMCFG\n", next_srmcfg);
		csr_write(CSR_SRMCFG, next_srmcfg);
	}
}

static __always_inline bool has_srmcfg(void)
{
	return riscv_has_extension_unlikely(RISCV_ISA_EXT_SSQOSID);
}

#else /* ! CONFIG_RISCV_ISA_SSQOSID  */

static __always_inline bool has_srmcfg(void) { return false; }
#define __switch_to_srmcfg(__prev, __next) do { } while (0)

#endif /* CONFIG_RISCV_ISA_SSQOSID */
#endif /* _ASM_RISCV_QOS_H */
