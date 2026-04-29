// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/riscv_cbqri.h>

#include "rqsc.h"

#define CBQRI_CTRL_SIZE 0x1000

int __init acpi_parse_rqsc(struct acpi_table_header *table)
{
	struct acpi_table_rqsc *rqsc = (struct acpi_table_rqsc *)table;
	struct acpi_rqsc_node *end, *node;
	int num_controllers = 0;

	/* Reject tables shorter than the fixed RQSC header. */
	if (rqsc->header.length < sizeof(struct acpi_table_rqsc)) {
		pr_err("RQSC table truncated: length %u < %zu, aborting\n",
		       rqsc->header.length, sizeof(struct acpi_table_rqsc));
		return -EINVAL;
	}

	end = ACPI_ADD_PTR(struct acpi_rqsc_node, rqsc, rqsc->header.length);

	for (node = ACPI_ADD_PTR(struct acpi_rqsc_node, rqsc,
				 sizeof(struct acpi_table_rqsc));
	     node < end;
	     node = ACPI_ADD_PTR(struct acpi_rqsc_node, node, node->length)
	) {
		const struct acpi_rqsc_resource *res0;
		struct cbqri_controller_info info = {};
		int ret;

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

		/* GAS must describe system memory. ioremap() consumes it later. */
		if (node->reg.space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY) {
			pr_warn("controller has unsupported address space_id=%u, skipping\n",
				node->reg.space_id);
			continue;
		}

		/* Address 0 would map page 0 (reset vectors, SBI, boot ROM). */
		if (!node->reg.address) {
			pr_warn("controller has zero address, skipping\n");
			continue;
		}

		info.type = node->type;
		/* RQSC v0.9.2 section 2 Table 2: 12-byte GAS-format register interface address */
		info.addr = node->reg.address;
		info.size = CBQRI_CTRL_SIZE;
		info.rcid_count = node->rcid;
		info.mcid_count = node->mcid;

		/* See CBQRI_MAX_RCID/MCID in <linux/riscv_cbqri.h> for the rationale. */
		if (info.rcid_count > CBQRI_MAX_RCID) {
			pr_warn("controller at %pa: rcid_count %u exceeds CBQRI_MAX_RCID %u, skipping\n",
				&info.addr, info.rcid_count, CBQRI_MAX_RCID);
			continue;
		}

		if (info.mcid_count > CBQRI_MAX_MCID) {
			pr_warn("controller at %pa: mcid_count %u exceeds CBQRI_MAX_MCID %u, skipping\n",
				&info.addr, info.mcid_count, CBQRI_MAX_MCID);
			continue;
		}

		if (node->nres == 0) {
			pr_warn("controller at %pa has no resource descriptors, skipping\n",
				&info.addr);
			continue;
		}

		/*
		 * Resources follow the node header in-line. Only res[0] is
		 * consumed. Bound it against end before reading its prefix so
		 * a table that ends partway through a resource subtable is
		 * rejected rather than read past the mapping.
		 */
		res0 = (const struct acpi_rqsc_resource *)
		       ((const u8 *)node + sizeof(*node));
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

		/*
		 * id1 is u64 on the wire but cache_id and prox_dom are u32
		 * downstream (PPTT cache_id, ACPI proximity domain). Reject
		 * rather than truncate, so a too-large id is not silently
		 * mapped to the wrong PPTT entry or NUMA node.
		 */
		if (res0->id1 > U32_MAX) {
			pr_warn("controller at %pa: id1 0x%llx exceeds u32, skipping\n",
				&info.addr, res0->id1);
			continue;
		}

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

		ret = riscv_cbqri_register_controller(&info);
		if (ret == 0)
			num_controllers++;
		else
			pr_warn("controller at %pa: registration failed (%d), skipping\n",
				&info.addr, ret);
	}

	pr_info("found %d CBQRI controllers\n", num_controllers);
	return 0;
}
