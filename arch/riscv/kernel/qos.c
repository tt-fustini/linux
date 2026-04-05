// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/percpu-defs.h>
#include <linux/types.h>

#include <asm/cpufeature-macros.h>
#include <asm/hwcap.h>
#include <asm/qos.h>

/* cached value of srmcfg csr for each cpu */
DEFINE_PER_CPU(u32, cpu_srmcfg);

/* default srmcfg value for each cpu, set via resctrl cpu assignment */
DEFINE_PER_CPU(u32, cpu_srmcfg_default);

/*
 * Invalidate the per-cpu CSR_SRMCFG cache when a hart comes online so the
 * next context switch unconditionally writes the CSR.  Ssqosid v1.0 leaves
 * CSR behaviour across hart stop/start implementation-defined, so the
 * cached value held by software (which survives offline) cannot be
 * trusted to match what hardware presents after online.  U32_MAX is a
 * valid sentinel because real srmcfg values pack (MCID << 16) | RCID with
 * each field bounded well below 16 bits.
 */
static int riscv_srmcfg_online(unsigned int cpu)
{
	per_cpu(cpu_srmcfg, cpu) = U32_MAX;
	return 0;
}

static int __init riscv_srmcfg_init(void)
{
	unsigned int cpu;
	int err;

	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SSQOSID))
		return 0;

	/*
	 * Seed cpu_srmcfg to U32_MAX on every already-online CPU so the
	 * first __switch_to_srmcfg() unconditionally writes the CSR; the
	 * zero-init default would compare equal against a default-group
	 * task's thread.srmcfg and skip the write, leaving hardware at
	 * whatever firmware left it.
	 */
	for_each_online_cpu(cpu)
		per_cpu(cpu_srmcfg, cpu) = U32_MAX;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "riscv/srmcfg:online",
				riscv_srmcfg_online, NULL);
	if (err < 0)
		pr_warn("srmcfg cpuhp registration failed (%d); cpus brought online after boot will not invalidate the CSR_SRMCFG cache\n",
			err);
	return err;
}
arch_initcall(riscv_srmcfg_init);
