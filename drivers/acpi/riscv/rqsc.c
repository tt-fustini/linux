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
	struct acpi_rqsc_node *end;
	struct acpi_rqsc_node *node;
	int err;
	int num_controllers = 0;

	rqsc = (struct acpi_table_rqsc *)table;

	end = ACPI_ADD_PTR(struct acpi_rqsc_node, rqsc, rqsc->header.length);

	for (node = ACPI_ADD_PTR(struct acpi_rqsc_node, rqsc,
				 sizeof(struct acpi_table_rqsc));
	     node < end;
	     node = ACPI_ADD_PTR(struct acpi_rqsc_node, node, node->length)
	) {
		const struct acpi_rqsc_resource *res0;
		struct cbqri_controller *ctrl;

		if ((void *)node + sizeof(*node) > (void *)end) {
			pr_err("truncated entry at end of table, aborting\n");
			err = -EINVAL;
			goto err_free_controllers;
		}

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
		/* RQSC v0.9.2 §2 Table 2: 12-byte GAS-format register interface address */
		ctrl->addr = node->reg.address;
		ctrl->size = CBQRI_CTRL_SIZE;
		ctrl->rcid_count = node->rcid;
		ctrl->mcid_count = node->mcid;

		if (!ctrl->addr) {
			pr_warn("skipping controller with invalid addr=0x0\n");
			cbqri_controller_destroy(ctrl);
			continue;
		}

		if (node->nres == 0) {
			pr_warn("controller at %pa has no resource descriptors, skipping\n",
				&ctrl->addr);
			cbqri_controller_destroy(ctrl);
			continue;
		}

		/*
		 * Resources follow the node header in-line; walk them via
		 * the resource's own length field rather than indexing a
		 * typed flexible array, so a future RQSC revision that
		 * extends struct acpi_rqsc_resource cannot misalign older
		 * parsers.  We only consume res[0]; bound the deref to the
		 * fixed prefix that v0.9.2 mandates.
		 */
		res0 = (const struct acpi_rqsc_resource *)
		       ((const u8 *)node + sizeof(*node));
		/*
		 * The top-of-loop check guards reading node->length (and
		 * thus moving the loop forward), but the resource walk
		 * dereferences res0->length, which sits beyond sizeof(*node).
		 * Bound res0 against @end before reading its fixed prefix so
		 * a malformed table that ends partway through a resource
		 * subtable is rejected rather than reading past the mapping.
		 */
		if ((void *)res0 + sizeof(*res0) > (void *)end ||
		    node->length < sizeof(*node) + sizeof(*res0) ||
		    res0->length < sizeof(*res0)) {
			pr_warn("controller at %pa: node too short for resource descriptor, skipping\n",
				&ctrl->addr);
			cbqri_controller_destroy(ctrl);
			continue;
		}

		if (node->nres > 1)
			pr_warn("controller at %pa has %u resource descriptors, using first\n",
				&ctrl->addr, node->nres);

		pr_debug("Found controller with type %u addr %pa size %pa rcid %u mcid %u\n",
			 ctrl->type, &ctrl->addr, &ctrl->size,
			 ctrl->rcid_count, ctrl->mcid_count);
		if (ctrl->type == CBQRI_CONTROLLER_TYPE_CAPACITY) {
			ctrl->cache.cache_id = (u32)res0->id1;
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
				cbqri_controller_destroy(ctrl);
				continue;
			}

		} else if (ctrl->type == CBQRI_CONTROLLER_TYPE_BANDWIDTH) {
			int node_id;

			ctrl->mem.prox_dom = (u32)res0->id1;
			node_id = pxm_to_node(ctrl->mem.prox_dom);
			if (node_id == NUMA_NO_NODE) {
				pr_warn("controller at %pa: proximity domain %u has no NUMA node, skipping\n",
					&ctrl->addr, ctrl->mem.prox_dom);
				cbqri_controller_destroy(ctrl);
				continue;
			}
			cpumask_copy(&ctrl->mem.cpu_mask, cpumask_of_node(node_id));
			pr_debug("Memory controller with proximity domain %u\n",
				 ctrl->mem.prox_dom);
		} else {
			pr_warn("controller at %pa: unknown type %u, skipping\n",
				&ctrl->addr, ctrl->type);
			cbqri_controller_destroy(ctrl);
			continue;
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
		cbqri_controller_destroy(ctrl);
	}
	return err;
}
