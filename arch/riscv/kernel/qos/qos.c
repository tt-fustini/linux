// SPDX-License-Identifier: GPL-2.0-only
#include <asm/qos.h>

/* cached value of srmcfg csr for each cpu */
DEFINE_PER_CPU(u32, cpu_srmcfg);

/* default srmcfg value for each cpu, set via resctrl cpu assignment */
DEFINE_PER_CPU(u32, cpu_srmcfg_default);
