// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2024, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include "init.h"

void __init acpi_arch_init(void)
{
	struct acpi_table_header *rqsc;
	acpi_status status;
	int rc;

	riscv_acpi_init_gsi_mapping();

	if (IS_ENABLED(CONFIG_ACPI_RIMT))
		riscv_acpi_rimt_init();

	if (IS_ENABLED(CONFIG_RISCV_ISA_SSQOSID) && !acpi_disabled) {
		status = acpi_get_table(ACPI_SIG_RQSC, 0, &rqsc);
		if (status == AE_NOT_FOUND) {
			/* RQSC is optional; silence on systems without it */
		} else if (ACPI_FAILURE(status)) {
			pr_err("failed to get ACPI RQSC table: %s\n",
			       acpi_format_exception(status));
		} else {
			rc = acpi_parse_rqsc(rqsc);
			if (rc < 0)
				pr_err("failed to parse ACPI RQSC table: %d\n",
				       rc);
			acpi_put_table(rqsc);
		}
	}
}
