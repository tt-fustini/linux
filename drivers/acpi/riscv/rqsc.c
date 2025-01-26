// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Tenstorrent
 *	Author: Drew Fustini <fustini@kernel.org>
 */

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/riscv_qos.h>

#ifdef CONFIG_RISCV_ISA_SSQOSID

#define CBQRI_CTRL_SIZE 0x1000

int acpi_parse_rqsc(struct acpi_table_header *table)
{
	struct acpi_table_rqsc *rqsc;
	struct acpi_table_rqsc_fields *end;
	struct acpi_table_rqsc_fields *node;
	int err;

	BUG_ON(acpi_disabled);

	rqsc = (struct acpi_table_rqsc *)table;

	end = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, rqsc, rqsc->header.length);

	for (node = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, rqsc,
				 sizeof(struct acpi_table_rqsc));
	     node < end;
	     node = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, node, node->length)
	) {
		struct cbqri_controller *ctrl;

		ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
		if (!ctrl)
			return -ENOMEM;

		ctrl->type = node->type;
		ctrl->addr = node->reg[1];
		ctrl->size = CBQRI_CTRL_SIZE;
		ctrl->rcid_count = node->rcid;
		ctrl->mcid_count = node->rcid;

		pr_info("Found controller with type %u addr 0x%lx size  %lu rcid  %u mcid  %u",
			ctrl->type, ctrl->addr, ctrl->size,
			ctrl->rcid_count, ctrl->mcid_count);
		if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
			ctrl->cache.cache_id = node->res.id1;
			ctrl->cache.cache_level =
				find_acpi_cache_level_from_id(ctrl->cache.cache_id);

			struct acpi_pptt_cache *cache;

			cache = find_acpi_cache_from_id(ctrl->cache.cache_id);
			if (cache) {
				ctrl->cache.cache_size = cache->size;
			} else {
				pr_warn("%s(): failed to determine size for cache id 0x%x",
					__func__, ctrl->cache.cache_id);
				ctrl->cache.cache_size = 0;
			}

			pr_info("Cache controller has ID 0x%x level %u size %u ",
				ctrl->cache.cache_id, ctrl->cache.cache_level,
				ctrl->cache.cache_size);

			/*
			 * For CBQRI, any cpu (technically a hart in RISC-V terms)
			 * can access the memory-mapped registers of any CBQRI
			 * controller in the system.
			 */
			err = acpi_pptt_get_cpumask_from_cache_id(ctrl->cache.cache_id,
								  &ctrl->cache.cpu_mask);
			if (err)
				pr_err("Failed to convert cores mask string to cpumask (%d)", err);

		} else if (ctrl->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
			ctrl->mem.prox_dom = node->res.id1;
			pr_info("Memory controller with proximity domain %u",
				ctrl->mem.prox_dom);
		}

		/* List shared with RISC-V QoS resctrl implementation */
		INIT_LIST_HEAD(&ctrl->list);
		list_add_tail(&ctrl->list, &cbqri_controllers);
	}
	return 0;

}

#endif /* CONFIG_RISCV_ISA_SSQOSID */
