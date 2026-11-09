// SPDX-License-Identifier: GPL-2.0-only
/*
 * Create a platform device for each CBQRI controller described by the ACPI
 * RISC-V Quality of Service Controllers (RQSC) table.
 */

#define pr_fmt(fmt) "ACPI: RQSC: " fmt

#include <linux/acpi.h>
#include <linux/bug.h>
#include <linux/cleanup.h>
#include <linux/err.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/wordpart.h>

#include "init.h"
#include "rqsc.h"

static struct platform_device * __init
rqsc_add_device(unsigned int idx, const struct acpi_rqsc_controller *ctrl,
		const struct acpi_rqsc_resource *res)
{
	bool is_cc = ctrl->type == ACPI_RQSC_CONTROLLER_TYPE_CAPACITY;
	struct platform_device *pdev __free(platform_device_put) =
		platform_device_alloc(is_cc ? "cbqri-capacity" : "cbqri-bandwidth",
				      idx);
	phys_addr_t addr = ctrl->address.address;
	/* The GAS carries no length, so claim up to the end of the page. */
	struct resource mem = DEFINE_RES_MEM(addr, PAGE_SIZE - offset_in_page(addr));
	/* rcid, mcid, cache id and a sentinel */
	struct property_entry props[4] = {};
	unsigned int n = 0;
	int ret;

	if (!pdev)
		return ERR_PTR(-ENOMEM);

	ret = platform_device_add_resources(pdev, &mem, 1);
	if (ret)
		return ERR_PTR(ret);

	props[n++] = PROPERTY_ENTRY_U32("riscv,cbqri-rcid", ctrl->rcid_count);
	props[n++] = PROPERTY_ENTRY_U32("riscv,cbqri-mcid", ctrl->mcid_count);
	if (is_cc)
		props[n++] = PROPERTY_ENTRY_U32("riscv,cbqri-cache-id",
						lower_32_bits(res->id1));
	else
		set_dev_node(&pdev->dev, pxm_to_node(lower_32_bits(res->id1)));

	ret = device_create_managed_software_node(&pdev->dev, props, NULL);
	if (ret)
		return ERR_PTR(ret);

	ret = platform_device_add(pdev);
	if (ret)
		return ERR_PTR(ret);

	return_ptr(pdev);
}

/*
 * Check the one resource the controller is described with. A capacity
 * controller names a processor cache by PPTT Cache ID, a bandwidth
 * controller a memory range by SRAT proximity domain. Both IDs are
 * the low 32 bits of Resource ID 1, the upper half is reserved.
 */
static bool __init rqsc_resource_ok(const struct acpi_rqsc_controller *ctrl,
				    const struct acpi_rqsc_resource *res,
				    phys_addr_t addr)
{
	u8 want_type, want_id_type;

	if (ctrl->type == ACPI_RQSC_CONTROLLER_TYPE_CAPACITY) {
		want_type = ACPI_RQSC_RESOURCE_TYPE_CACHE;
		want_id_type = ACPI_RQSC_RESOURCE_ID_TYPE_PROCESSOR_CACHE;
	} else {
		want_type = ACPI_RQSC_RESOURCE_TYPE_MEMORY;
		want_id_type = ACPI_RQSC_RESOURCE_ID_TYPE_MEMORY_RANGE;
	}

	if (res->type != want_type || res->id_type != want_id_type) {
		pr_warn("controller at %pa: resource type %u id type %u does not match controller type %u, skipping\n",
			&addr, res->type, res->id_type, ctrl->type);
		return false;
	}

	return true;
}

static void __init rqsc_parse(const struct acpi_table_rqsc *rqsc)
{
	const void *end = (const void *)rqsc + rqsc->header.length;
	const struct acpi_rqsc_controller *ctrl = (const void *)(rqsc + 1);
	unsigned int idx = 0, added = 0;

	while ((const void *)ctrl < end) {
		const struct acpi_rqsc_resource *res = (const void *)(ctrl + 1);
		struct platform_device *pdev;
		phys_addr_t addr;

		/*
		 * The controller structure must fit and stay inside the
		 * table. Anything else is corruption and the remaining
		 * entries cannot be trusted.
		 */
		if ((const void *)ctrl + sizeof(*ctrl) > end ||
		    ctrl->length < sizeof(*ctrl) ||
		    (const void *)ctrl + ctrl->length > end) {
			pr_err("entry %u is malformed, stopping\n", idx);
			break;
		}

		addr = ctrl->address.address;

		if (ctrl->type != ACPI_RQSC_CONTROLLER_TYPE_CAPACITY &&
		    ctrl->type != ACPI_RQSC_CONTROLLER_TYPE_BANDWIDTH) {
			pr_warn("controller at %pa: unknown type %u, skipping\n",
				&addr, ctrl->type);
			goto next;
		}

		if (ctrl->address.space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY || !addr) {
			pr_warn("entry %u: no usable register interface address, skipping\n",
				idx);
			goto next;
		}

		if (!ctrl->rcid_count && !ctrl->mcid_count) {
			pr_warn("controller at %pa: no RCIDs and no MCIDs, skipping\n",
				&addr);
			goto next;
		}

		if (!ctrl->num_resources ||
		    ctrl->length < sizeof(*ctrl) + sizeof(*res) ||
		    res->length < sizeof(*res)) {
			pr_warn("controller at %pa: no usable resource, skipping\n",
				&addr);
			goto next;
		}

		if (ctrl->num_resources > 1)
			pr_warn("controller at %pa: %u resources, using the first\n",
				&addr, ctrl->num_resources);

		if (!rqsc_resource_ok(ctrl, res, addr))
			goto next;

		pdev = rqsc_add_device(idx, ctrl, res);
		if (IS_ERR(pdev)) {
			pr_warn("controller at %pa: failed to add device: %pe\n",
				&addr, pdev);
			goto next;
		}

		added++;
next:
		ctrl = (const void *)ctrl + ctrl->length;
		idx++;
	}

	if (idx != rqsc->num_controllers)
		pr_warn("table announces %u controllers, found %u\n",
			rqsc->num_controllers, idx);

	if (added)
		pr_info("%u CBQRI controllers\n", added);
	else
		pr_warn("no usable CBQRI controller\n");
}

void __init riscv_acpi_rqsc_init(void)
{
	struct acpi_table_header *table __free(acpi_put_table) = NULL;
	acpi_status status;

	BUILD_BUG_ON(sizeof(struct acpi_rqsc_resource) != 20);
	BUILD_BUG_ON(sizeof(struct acpi_rqsc_controller) != 24);
	BUILD_BUG_ON(sizeof(struct acpi_table_rqsc) != 40);

	status = acpi_get_table(ACPI_SIG_RQSC, 0, &table);
	if (status == AE_NOT_FOUND)
		return;

	if (ACPI_FAILURE(status)) {
		pr_err("failed to get table: %s\n",
		       acpi_format_exception(status));
		return;
	}

	/*
	 * A later revision could extend the fixed header, which would
	 * shift the first controller structure. Stop rather than guess.
	 */
	if (table->revision != ACPI_RQSC_REVISION) {
		pr_err("table revision %u, expected %u\n",
		       table->revision, ACPI_RQSC_REVISION);
		return;
	}

	if (table->length < sizeof(struct acpi_table_rqsc)) {
		pr_err("table truncated: length %u\n", table->length);
		return;
	}

	rqsc_parse((const struct acpi_table_rqsc *)table);
}
