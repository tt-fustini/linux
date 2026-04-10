// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Tenstorrent
 *	Author: Drew Fustini <fustini@kernel.org>
 */

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/riscv_qos.h>

#define CBQRI_CTRL_SIZE 0x1000

int __init acpi_parse_rqsc(struct acpi_table_header *table)
{
	struct acpi_table_rqsc *rqsc;
	struct acpi_table_rqsc_fields *end;
	struct acpi_table_rqsc_fields *node;
	int err;
	int num_controllers = 0;

	rqsc = (struct acpi_table_rqsc *)table;

	end = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, rqsc, rqsc->header.length);

	for (node = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, rqsc,
				 sizeof(struct acpi_table_rqsc));
	     node < end;
	     node = ACPI_ADD_PTR(struct acpi_table_rqsc_fields, node, node->length)
	) {
		struct cbqri_controller *ctrl;

		if (node->length < sizeof(*node)) {
			pr_err("malformed RQSC entry: length %u < %zu, aborting\n",
			       node->length, sizeof(*node));
			err = -EINVAL;
			goto err_free_controllers;
		}

		ctrl = kzalloc_obj(*ctrl, GFP_KERNEL);
		if (!ctrl) {
			err = -ENOMEM;
			goto err_free_controllers;
		}

		ctrl->type = node->type;
		/* reg[1] is the MMIO base address per the RQSC table layout */
		ctrl->addr = node->reg[1];
		ctrl->size = CBQRI_CTRL_SIZE;
		ctrl->rcid_count = node->rcid;
		ctrl->mcid_count = node->mcid;

		if (!ctrl->addr) {
			pr_warn("skipping controller with invalid addr=0x0\n");
			kfree(ctrl);
			continue;
		}

		if (node->nres == 0) {
			pr_warn("controller at %pa has no resource descriptors, skipping\n",
				&ctrl->addr);
			kfree(ctrl);
			continue;
		}

		if (node->length < sizeof(*node) + sizeof(node->res[0])) {
			pr_warn("controller at %pa: node too short for resource descriptor, skipping\n",
				&ctrl->addr);
			kfree(ctrl);
			continue;
		}

		if (node->nres > 1)
			pr_warn("controller at %pa has %u resource descriptors, using first\n",
				&ctrl->addr, node->nres);

		pr_debug("Found controller with type %u addr %pa size %pa rcid %u mcid %u\n",
			 ctrl->type, &ctrl->addr, &ctrl->size,
			 ctrl->rcid_count, ctrl->mcid_count);
		if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
			ctrl->cache.cache_id = (u32)node->res[0].id1;
			ctrl->cache.cache_level =
				find_acpi_cache_level_from_id(ctrl->cache.cache_id);

			if (acpi_pptt_get_cache_size_from_id(ctrl->cache.cache_id,
							     &ctrl->cache.cache_size)) {
				pr_warn("failed to determine size for cache id 0x%x\n",
					ctrl->cache.cache_id);
				ctrl->cache.cache_size = 0;
			}

			pr_debug("Cache controller has ID 0x%x level %u size %u\n",
				 ctrl->cache.cache_id, ctrl->cache.cache_level,
				 ctrl->cache.cache_size);

			/*
			 * For CBQRI, any cpu (technically a hart in RISC-V terms)
			 * can access the memory-mapped registers of any CBQRI
			 * controller in the system.
			 */
			err = acpi_pptt_get_cpumask_from_cache_id(ctrl->cache.cache_id,
								  &ctrl->cache.cpu_mask);
			if (err) {
				pr_warn("Failed to get cpumask for cache id 0x%x (%d), skipping\n",
					ctrl->cache.cache_id, err);
				kfree(ctrl);
				continue;
			}

		} else if (ctrl->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
			ctrl->mem.prox_dom = (u32)node->res[0].id1;
			cpumask_copy(&ctrl->mem.cpu_mask,
				     cpumask_of_node(pxm_to_node(ctrl->mem.prox_dom)));
			pr_debug("Memory controller with proximity domain %u\n",
				 ctrl->mem.prox_dom);
		}

		/* List shared with RISC-V QoS resctrl implementation */
		list_add_tail(&ctrl->list, &cbqri_controllers);
		num_controllers++;
	}

	pr_info("found %d CBQRI controllers\n", num_controllers);
	return 0;

err_free_controllers:
	while (!list_empty(&cbqri_controllers)) {
		struct cbqri_controller *ctrl;

		ctrl = list_first_entry(&cbqri_controllers, struct cbqri_controller, list);
		list_del(&ctrl->list);
		kfree(ctrl);
	}
	return err;
}
