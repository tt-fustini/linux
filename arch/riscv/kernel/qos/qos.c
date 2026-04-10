// SPDX-License-Identifier: GPL-2.0-only
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/riscv_qos.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "internal.h"

/* cached value of srmcfg csr for each cpu */
DEFINE_PER_CPU(u32, cpu_srmcfg);

/* default srmcfg value for each cpu, set via resctrl cpu assignment */
DEFINE_PER_CPU(u32, cpu_srmcfg_default);

static int __init qos_arch_late_init(void)
{
	int err;

	if (!riscv_isa_extension_available(NULL, SSQOSID))
		return -ENODEV;

	err = qos_resctrl_setup();
	if (err)
		return err;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "qos:online",
				qos_resctrl_online_cpu,
				qos_resctrl_offline_cpu);
	if (err < 0) {
		resctrl_exit();
		return err;
	}

	return 0;
}
late_initcall(qos_arch_late_init);
