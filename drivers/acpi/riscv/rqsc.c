// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Tenstorrent
 *	Author: Drew Fustini <fustini@kernel.org>
 *
 */

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/riscv_qos.h>

#ifdef CONFIG_RISCV_ISA_SSQOSID

#define CBQRI_CTRL_SIZE 0x1000

static struct acpi_table_rqsc *acpi_get_rqsc(void)
{
	static struct acpi_table_header *rqsc;
	acpi_status status;

	/*
	 * RQSC will be used at runtime on every CPU, so we
	 * don't need to call acpi_put_table() to release the table mapping.
	 */
	if (!rqsc) {
		status = acpi_get_table(ACPI_SIG_RQSC, 0, &rqsc);
		if (ACPI_FAILURE(status)) {
			pr_warn_once("No RQSC table found\n");
			return NULL;
		}
	}

	return (struct acpi_table_rqsc *)rqsc;
}

int acpi_parse_rqsc(struct acpi_table_header *table)
{
	struct acpi_table_rqsc *rqsc;
	int err;

	BUG_ON(acpi_disabled);
	if (!table) {
		rqsc = acpi_get_rqsc();
		if (!rqsc)
			return -ENOENT;
	} else {
		rqsc = (struct acpi_table_rqsc *)table;
	}

	for (int i = 0; i < rqsc->num; i++) {
		struct cbqri_controller_info *ctrl_info;

		ctrl_info = kzalloc(sizeof(*ctrl_info), GFP_KERNEL);
		if (!ctrl_info)
			return -ENOMEM;

		ctrl_info->type = rqsc->f[i].type;
		ctrl_info->addr = rqsc->f[i].reg[1];
		ctrl_info->size = CBQRI_CTRL_SIZE;
		ctrl_info->rcid_count = rqsc->f[i].rcid;
		ctrl_info->mcid_count = rqsc->f[i].mcid;

		pr_info("Found controller with type %u addr 0x%lx size  %lu rcid  %u mcid  %u",
			ctrl_info->type, ctrl_info->addr, ctrl_info->size,
			ctrl_info->rcid_count, ctrl_info->mcid_count);

		if (ctrl_info->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
			ctrl_info->cache.cache_id = rqsc->f[i].res.id1;
			ctrl_info->cache.cache_level =
				find_acpi_cache_level_from_id(ctrl_info->cache.cache_id);

			struct acpi_pptt_cache *cache;

			cache = find_acpi_cache_from_id(ctrl_info->cache.cache_id);
			if (cache) {
				ctrl_info->cache.cache_size = cache->size;
			} else {
				pr_warn("%s(): failed to determine size for cache id 0x%x",
					__func__, ctrl_info->cache.cache_id);
				ctrl_info->cache.cache_size = 0;
			}

			pr_info("Cache controller has ID 0x%x level %u size %u ",
				ctrl_info->cache.cache_id, ctrl_info->cache.cache_level,
				ctrl_info->cache.cache_size);

			/*
			 * For CBQRI, any cpu (technically a hart in RISC-V terms)
			 * can access the memory-mapped registers of any CBQRI
			 * controller in the system.
			 */
			err = cpumask_parse("FF", &ctrl_info->cache.cpu_mask);
			if (err)
				pr_err("Failed to convert cores mask string to cpumask (%d)", err);

		} else if (ctrl_info->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
			ctrl_info->mem.prox_dom = rqsc->f[i].res.id1;
			pr_info("Memory controller with proximity domain %u",
				ctrl_info->mem.prox_dom);
		}

		/* Fill the list shared with RISC-V QoS resctrl */
		INIT_LIST_HEAD(&ctrl_info->list);
		list_add_tail(&ctrl_info->list, &cbqri_controllers);
	}

	return 0;
}

#endif /* CONFIG_RISCV_ISA_SSQOSID */
