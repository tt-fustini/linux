// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023-2024, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 */

#include <linux/acpi.h>
#include "init.h"
#include <linux/riscv_qos.h>

void __init acpi_arch_init(void)
{
	struct acpi_table_header *rqsc;
	acpi_status status;
	int rc;

	riscv_acpi_init_gsi_mapping();

	if (IS_ENABLED(CONFIG_ACPI_RIMT))
		riscv_acpi_rimt_init();

	if (!acpi_disabled) {
		status = acpi_get_table(ACPI_SIG_RQSC, 0, &rqsc);
		if (ACPI_FAILURE(status)) {
			pr_err("%s(): failed to find ACPI RQSC table: %d", __func__,
			       ACPI_FAILURE(status));
		} else {
			rc = acpi_parse_rqsc(rqsc);
			if (rc < 0)
				pr_err("%s(): failed to parse ACPI RQSC table: %d", __func__, rc);
		}
		acpi_put_table((struct acpi_table_header *)rqsc);
	}
}
