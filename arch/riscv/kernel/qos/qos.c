// SPDX-License-Identifier: GPL-2.0-only
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/riscv_qos.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "internal.h"

/* cached value of srmcfg csr for each cpu */
DEFINE_PER_CPU(u32, cpu_srmcfg);

/* default srmcfg value for each cpu, set via resctrl cpu assignment */
DEFINE_PER_CPU(u32, cpu_srmcfg_default);

/* Saved cpuhp slot from cpuhp_setup_state() for symmetric removal. */
static enum cpuhp_state qos_cpuhp_state;

static int __init qos_arch_late_init(void)
{
	int err;

	if (!riscv_isa_extension_available(NULL, SSQOSID))
		return -ENODEV;

	/*
	 * qos_resctrl_setup() is responsible for its own cleanup on any
	 * failure path -- including the resctrl_init() that happens
	 * inside it -- via qos_resctrl_teardown().  Don't call
	 * resctrl_exit() here: it might run before resctrl_init() did.
	 */
	err = qos_resctrl_setup();
	if (err)
		return err;

	err = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "qos:online",
				qos_resctrl_online_cpu,
				qos_resctrl_offline_cpu);
	if (err < 0) {
		qos_resctrl_teardown();
		return err;
	}
	qos_cpuhp_state = err;

	return 0;
}
late_initcall(qos_arch_late_init);
