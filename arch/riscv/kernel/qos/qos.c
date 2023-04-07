// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2022 Rivos Inc.

#include <linux/slab.h>
#include <linux/err.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/riscv_qos.h>

#include <asm/csr.h>
#include <asm/qos.h>

#include "internal.h"

static int __init qos_arch_late_init(void)
{
	int err;

	if (!riscv_isa_extension_available(NULL, SSQOSID))
		return -ENODEV;

	err = qos_resctrl_setup();
	if (err != 0)
		return err;

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "qos:online", qos_resctrl_online_cpu,
			  qos_resctrl_offline_cpu);

	return err;
}
late_initcall(qos_arch_late_init);
