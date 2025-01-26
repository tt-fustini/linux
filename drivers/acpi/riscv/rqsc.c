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

int acpi_parse_rqsc(struct acpi_table_header *table)
{
	struct acpi_table_rqsc *rqsc;
	struct acpi_table_rqsc_fields *end;
	struct acpi_table_rqsc_fields *node;
	int err;

	BUG_ON(acpi_disabled);

	rqsc = (struct acpi_table_rqsc *)table;

	end = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, rqsc, rqsc->header.length);

	cbqri_controllers_size = rqsc->num;

	for ( node = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, rqsc, sizeof(struct acpi_table_rqsc));
	      node < end;
	      node = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, node, node->length)
	    ) {
		struct cbqri_controller *ctrl;
		struct cbqri_controller_info *ctrl_info;

		ctrl_info = kzalloc(sizeof(*ctrl_info), GFP_KERNEL);
		if (!ctrl_info)
			return -ENOMEM;

		ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
		if (!ctrl)
			return -ENOMEM;

		ctrl->ctrl_info = ctrl_info;

		ctrl->ctrl_info->type = node->type;
		ctrl->ctrl_info->addr = node->reg[1];
		ctrl->ctrl_info->size = CBQRI_CTRL_SIZE;
		ctrl->ctrl_info->rcid_count = node->rcid;
		ctrl->ctrl_info->mcid_count = node->rcid;

		pr_info("Found controller with type %u addr 0x%lx size  %lu rcid  %u mcid  %u",
			ctrl->ctrl_info->type, ctrl->ctrl_info->addr, ctrl->ctrl_info->size,
			ctrl->ctrl_info->rcid_count, ctrl->ctrl_info->mcid_count);
		if (ctrl->ctrl_info->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
			ctrl->ctrl_info->cache.cache_id = node->res.id1;
			ctrl->ctrl_info->cache.cache_level =
				find_acpi_cache_level_from_id(ctrl->ctrl_info->cache.cache_id);

			struct acpi_pptt_cache *cache;

			cache = find_acpi_cache_from_id(ctrl->ctrl_info->cache.cache_id);
			if (cache) {
				ctrl->ctrl_info->cache.cache_size = cache->size;
			} else {
				pr_warn("%s(): failed to determine size for cache id 0x%x",
					__func__, ctrl->ctrl_info->cache.cache_id);
				ctrl->ctrl_info->cache.cache_size = 0;
			}

			pr_info("Cache controller has ID 0x%x level %u size %u ",
				ctrl->ctrl_info->cache.cache_id, ctrl->ctrl_info->cache.cache_level,
				ctrl->ctrl_info->cache.cache_size);

			/*
			 * For CBQRI, any cpu (technically a hart in RISC-V terms)
			 * can access the memory-mapped registers of any CBQRI
			 * controller in the system.
			 */
			err = acpi_pptt_get_cpumask_from_cache_id(ctrl->ctrl_info->cache.cache_id, &ctrl->ctrl_info->cache.cpu_mask);
			if (err)
				pr_err("Failed to convert cores mask string to cpumask (%d)", err);

		} else if (ctrl->ctrl_info->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
			ctrl->ctrl_info->mem.prox_dom = node->res.id1;
			pr_info("Memory controller with proximity domain %u",
				ctrl->ctrl_info->mem.prox_dom);
		}

		// Fill the list shared with RISC-V QoS resctrl
		INIT_LIST_HEAD(&ctrl->ctrl_info->list);
		list_add_tail(&ctrl->ctrl_info->list, &cbqri_controllers);
	}

	return 0;
}

#endif /* CONFIG_RISCV_ISA_SSQOSID */
