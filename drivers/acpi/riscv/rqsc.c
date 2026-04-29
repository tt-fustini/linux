// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Tenstorrent
 *	Author: Drew Fustini <fustini@kernel.org>
 */

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/cbqri.h>

#include "rqsc.h"

#define CBQRI_CTRL_SIZE 0x1000

int __init acpi_parse_rqsc(struct acpi_table_header *table)
{
	struct acpi_table_rqsc *rqsc = (struct acpi_table_rqsc *)table;
	struct acpi_rqsc_node *end, *node;
	int num_controllers = 0;

	end = ACPI_ADD_PTR(struct acpi_rqsc_node, rqsc, rqsc->header.length);

	for (node = ACPI_ADD_PTR(struct acpi_rqsc_node, rqsc,
				 sizeof(struct acpi_table_rqsc));
	     node < end;
	     node = ACPI_ADD_PTR(struct acpi_rqsc_node, node, node->length)
	) {
		const struct acpi_rqsc_resource *res0;
		struct cbqri_controller_info info = {};

		if ((void *)node + sizeof(*node) > (void *)end) {
			pr_err("truncated entry at end of table, aborting\n");
			riscv_cbqri_unregister_last(num_controllers);
			return -EINVAL;
		}

		if (node->length < sizeof(*node)) {
			pr_err("malformed RQSC entry: length %u < %zu, aborting\n",
			       node->length, sizeof(*node));
			riscv_cbqri_unregister_last(num_controllers);
			return -EINVAL;
		}

		/*
		 * The GAS register-interface address must describe system memory
		 * because it is consumed by ioremap() during qos_arch_late_init.
		 * A non-MEMORY space_id (e.g. SYSTEM_IO, PCI_CONFIG) would map an
		 * unrelated phys range and corrupt other hardware on access.
		 */
		if (node->reg.space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY) {
			pr_warn("controller has unsupported address space_id=%u, skipping\n",
				node->reg.space_id);
			continue;
		}

		info.type = node->type;
		/* RQSC v0.9.2 section 2 Table 2: 12-byte GAS-format register interface address */
		info.addr = node->reg.address;
		info.size = CBQRI_CTRL_SIZE;
		info.rcid_count = node->rcid;
		info.mcid_count = node->mcid;

		if (node->nres == 0) {
			pr_warn("controller at %pa has no resource descriptors, skipping\n",
				&info.addr);
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
				&info.addr);
			continue;
		}

		if (node->nres > 1)
			pr_warn("controller at %pa has %u resource descriptors, using first\n",
				&info.addr, node->nres);

		switch (info.type) {
		case CBQRI_CONTROLLER_TYPE_CAPACITY:
			info.cache_id = (u32)res0->id1;
			break;
		case CBQRI_CONTROLLER_TYPE_BANDWIDTH:
			info.prox_dom = (u32)res0->id1;
			break;
		default:
			pr_warn("controller at %pa: unknown type %u, skipping\n",
				&info.addr, info.type);
			continue;
		}

		pr_debug("registering controller type=%u addr=%pa rcid=%u mcid=%u\n",
			 info.type, &info.addr, info.rcid_count, info.mcid_count);

		if (riscv_cbqri_register_controller(&info) == 0)
			num_controllers++;
	}

	pr_info("found %d CBQRI controllers\n", num_controllers);
	return 0;
}
