// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 Arm Ltd.

/* Parse the MPAM ACPI table feeding the discovered nodes into the driver */

#define pr_fmt(fmt) "ACPI MPAM: " fmt

#include <linux/acpi.h>
#include <linux/arm_mpam.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/platform_device.h>

#include <acpi/processor.h>

#include <asm/mpam.h>

/* Flags for acpi_table_mpam_msc.*_interrupt_flags */
#define ACPI_MPAM_MSC_IRQ_MODE_EDGE                    1
#define ACPI_MPAM_MSC_IRQ_TYPE_MASK                    (3<<1)
#define ACPI_MPAM_MSC_IRQ_TYPE_WIRED                   0
#define ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER (1<<3)
#define ACPI_MPAM_MSC_IRQ_AFFINITY_VALID               (1<<4)

static bool frob_irq(struct platform_device *pdev, int intid, u32 flags,
		     int *irq, u32 processor_container_uid)
{
	int sense;

	if (!intid)
		return false;

	/* 0 in this field indicates a wired interrupt */
	if (flags & ACPI_MPAM_MSC_IRQ_TYPE_MASK)
		return false;

	if (flags & ACPI_MPAM_MSC_IRQ_MODE_EDGE)
		sense = ACPI_EDGE_SENSITIVE;
	else
		sense = ACPI_LEVEL_SENSITIVE;

	/*
	 * If the GSI is in the GIC's PPI range, try and create a partitioned
	 * percpu interrupt.
	 */
	if (16 <= intid && intid < 32 && processor_container_uid != ~0) {
		pr_err_once("Partitioned interrupts not supported\n");
		return false;
	} else {
		*irq = acpi_register_gsi(&pdev->dev, intid, sense,
					 ACPI_ACTIVE_HIGH);
	}
	if (*irq <= 0) {
		pr_err_once("Failed to register interrupt 0x%x with ACPI\n",
			    intid);
		return false;
	}

	return true;
}

static void acpi_mpam_parse_irqs(struct platform_device *pdev,
				 struct acpi_mpam_msc_node *tbl_msc,
				 struct resource *res, int *res_idx)
{
	u32 flags, aff = ~0;
	int irq;

	flags = tbl_msc->overflow_interrupt_flags;
	if (flags & ACPI_MPAM_MSC_IRQ_AFFINITY_VALID &&
	    flags & ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER)
		aff = tbl_msc->overflow_interrupt_affinity;
	if (frob_irq(pdev, tbl_msc->overflow_interrupt, flags, &irq, aff)) {
		res[*res_idx].start = irq;
		res[*res_idx].end = irq;
		res[*res_idx].flags = IORESOURCE_IRQ;
		res[*res_idx].name = "overflow";

		(*res_idx)++;
	}

	flags = tbl_msc->error_interrupt_flags;
	if (flags & ACPI_MPAM_MSC_IRQ_AFFINITY_VALID &&
	    flags & ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER)
		aff = tbl_msc->error_interrupt_affinity;
	else
		aff = ~0;
	if (frob_irq(pdev, tbl_msc->error_interrupt, flags, &irq, aff)) {
		res[*res_idx].start = irq;
		res[*res_idx].end = irq;
		res[*res_idx].flags = IORESOURCE_IRQ;
		res[*res_idx].name = "error";

		(*res_idx)++;
	}
}

#define UUID_MPAM_INTERCONNECT_TABLE		"fe2bd645-033b-49e6-9479-2e0b8b21d1cd"

struct acpi_mpam_interconnect_descriptor_table {
	u8	type_uuid[16];
	u32	num_descriptors;
};

struct acpi_mpam_interconnect_descriptor {
	u32	source_id;
	u32	destination_id;
	u8	link_type;
	u8	reserved[3];
};

static int acpi_mpam_parse_resource(struct acpi_mpam_msc_node *tbl_msc,
				    struct mpam_msc *msc,
				    struct acpi_mpam_resource_node *res)
{
	struct acpi_mpam_interconnect_descriptor_table *tbl_int_tbl;
	struct acpi_mpam_interconnect_descriptor *tbl_int;
	guid_t int_tbl_uuid, spec_uuid;
	u32 cache_id;
	off_t offset;
	int level;

	/*
	 * Class IDs are somewhat arbitary, but need to be co-ordinated.
	 * 0-N are caches,
	 * 64, 65: Interconnect, but ideally these would appear between the
	 *     classes the controls are adjacent to.
	 * 128: SMMU,
	 * 192-192+level: Memory Side Caches, nothing checks that N is a
	 *                small number.
	 * 255: Memory Controllers
	 *
	 * ACPI devices would need a class id allocated based on the _HID.
	 *
	 * Classes that the mpam driver can't currently plumb into resctrl
	 * are registered as UNKNOWN.
	 */
	switch (res->locator_type) {
	case ACPI_MPAM_LOCATION_TYPE_PROCESSOR_CACHE:
		cache_id = res->locator.cache_locator.cache_reference;
		level = find_acpi_cache_level_from_id(cache_id);
		if (level < 0 || level >= 64) {
			pr_err_once("Bad level for cache with id %u\n", cache_id);
			return -EINVAL;
		}
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_CACHE,
				       level, cache_id);
	case ACPI_MPAM_LOCATION_TYPE_MEMORY:
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_MEMORY,
				       255, res->locator.memory_locator.proximity_domain);
	case ACPI_MPAM_LOCATION_TYPE_SMMU:
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_UNKNOWN,
				       128, res->locator.smmu_locator.smmu_interface);
	case ACPI_MPAM_LOCATION_TYPE_MEMORY_CACHE:
		cache_id = res->locator.mem_cache_locator.reference;
		level = res->locator.mem_cache_locator.level;
		if (192 + level >= 255) {
			pr_err_once("Bad level for memory side cache with reference %u\n",
				    cache_id);
			return -EINVAL;
		}

		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_CACHE,
				       192 + level, cache_id);

	case ACPI_MPAM_LOCATION_TYPE_INTERCONNECT:
		/* Find the descriptor table, and check it lands in the parent msc */
		offset = res->locator.interconnect_ifc_locator.inter_connect_desc_tbl_off;
		if (offset >= tbl_msc->length) {
			pr_err_once("Bad offset for interconnect descriptor on msc %u\n",
				    tbl_msc->identifier);
			return -EINVAL;
		}
		tbl_int_tbl = ACPI_ADD_PTR(struct acpi_mpam_interconnect_descriptor_table,
					   tbl_msc, offset);
		guid_parse(UUID_MPAM_INTERCONNECT_TABLE, &spec_uuid);
		import_guid(&int_tbl_uuid, tbl_int_tbl->type_uuid);
		if (guid_equal(&spec_uuid, &int_tbl_uuid)) {
			pr_err_once("Bad UUID for interconnect descriptor on msc %u\n",
				    tbl_msc->identifier);
			return -EINVAL;
		}

		offset += sizeof(*tbl_int_tbl);
		offset += tbl_int_tbl->num_descriptors * sizeof(*tbl_int);
		if (offset >= tbl_msc->length) {
			pr_err_once("Bad num_descriptors for interconnect descriptor on msc %u\n",
				    tbl_msc->identifier);
			return -EINVAL;
		}

		tbl_int = ACPI_ADD_PTR(struct acpi_mpam_interconnect_descriptor,
				       tbl_int_tbl, sizeof(*tbl_int_tbl));
		cache_id = tbl_int->source_id;

		/* Unknown link type? */
		if (tbl_int->link_type != 0 && tbl_int->link_type == 1)
			return 0;

		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_UNKNOWN,
				       64 + tbl_int->link_type, cache_id);
	default:
		/* These get discovered later and treated as unknown */
		return 0;
	}
}

int acpi_mpam_parse_resources(struct mpam_msc *msc,
			      struct acpi_mpam_msc_node *tbl_msc)
{
	int i, err;
	struct acpi_mpam_resource_node *resources;

	resources = (struct acpi_mpam_resource_node *)(tbl_msc + 1);
	for (i = 0; i < tbl_msc->num_resouce_nodes; i++) {
		err = acpi_mpam_parse_resource(tbl_msc, msc, &resources[i]);
		if (err)
			return err;
	}

	return 0;
}

static bool __init parse_msc_pm_link(struct acpi_mpam_msc_node *tbl_msc,
				     struct platform_device *pdev,
				     u32 *acpi_id)
{
	bool acpi_id_valid = false;
	struct acpi_device *buddy;
	char hid[16], uid[16];
	int err;

	memset(&hid, 0, sizeof(hid));
	memcpy(hid, &tbl_msc->hardware_id_linked_device,
	       sizeof(tbl_msc->hardware_id_linked_device));

	if (!strcmp(hid, ACPI_PROCESSOR_CONTAINER_HID)) {
		*acpi_id = tbl_msc->instance_id_linked_device;
		acpi_id_valid = true;
	}

	err = snprintf(uid, sizeof(uid), "%u",
		       tbl_msc->instance_id_linked_device);
	if (err < 0 || err >= sizeof(uid))
		return acpi_id_valid;

	buddy = acpi_dev_get_first_match_dev(hid, uid, -1);
	if (buddy) {
		device_link_add(&pdev->dev, &buddy->dev, DL_FLAG_STATELESS);
	}

	return acpi_id_valid;
}

static int decode_interface_type(struct acpi_mpam_msc_node *tbl_msc,
				 enum mpam_msc_iface *iface)
{
	switch (tbl_msc->interface_type){
	case 0:
		*iface = MPAM_IFACE_MMIO;
		return 0;
	case 0xa:
		*iface = MPAM_IFACE_PCC;
		return 0;
	default:
		return -EINVAL;
	}
}

static int __init _parse_table(struct acpi_table_header *table)
{
	char *table_end, *table_offset = (char *)(table + 1);
	struct property_entry props[4]; /* needs a sentinel */
	struct acpi_mpam_msc_node *tbl_msc;
	int next_res, next_prop, err = 0;
	struct acpi_device *companion;
	struct platform_device *pdev;
	enum mpam_msc_iface iface;
	struct resource res[3];
	char uid[16];
	u32 acpi_id;

	table_end = (char *)table + table->length;

	while (table_offset < table_end) {
		tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
		table_offset += tbl_msc->length;

		/*
		 * If any of the reserved fields are set, make no attempt to
		 * parse the msc structure. This will prevent the driver from
		 * probing all the MSC, meaning it can't discover the system
		 * wide supported partid and pmg ranges. This avoids whatever
		 * this MSC is truncating the partids and creating a screaming
		 * error interrupt.
		 */
		if (tbl_msc->reserved || tbl_msc->reserved1 || tbl_msc->reserved2)
			continue;

		if (decode_interface_type(tbl_msc, &iface))
			continue;

		next_res = 0;
		next_prop = 0;
		memset(res, 0, sizeof(res));
		memset(props, 0, sizeof(props));

		pdev = platform_device_alloc("mpam_msc", tbl_msc->identifier);
		if (IS_ERR(pdev)) {
			err = PTR_ERR(pdev);
			break;
		}

		if (tbl_msc->length < sizeof(*tbl_msc)) {
			err = -EINVAL;
			break;
		}

		/* Some power management is described in the namespace: */
		err = snprintf(uid, sizeof(uid), "%u", tbl_msc->identifier);
		if (err > 0 && err < sizeof(uid)) {
			companion = acpi_dev_get_first_match_dev("ARMHAA5C", uid, -1);
			if (companion)
				ACPI_COMPANION_SET(&pdev->dev, companion);
		}

		if (iface == MPAM_IFACE_MMIO) {
			res[next_res].name = "MPAM:MSC";
			res[next_res].start = tbl_msc->base_address;
			res[next_res].end = tbl_msc->base_address + tbl_msc->mmio_size - 1;
			res[next_res].flags = IORESOURCE_MEM;
			next_res++;
		} else if (iface == MPAM_IFACE_PCC) {
			props[next_prop++] = PROPERTY_ENTRY_U32("pcc-channel",
								tbl_msc->base_address);
			next_prop++;
		}

		acpi_mpam_parse_irqs(pdev, tbl_msc, res, &next_res);
		err = platform_device_add_resources(pdev, res, next_res);
		if (err)
			break;

		props[next_prop++] = PROPERTY_ENTRY_U32("arm,not-ready-us",
							tbl_msc->max_nrdy_usec);

		/*
		 * The MSC's CPU affinity is described via its linked power
		 * management device, but only if it points at a Processor or
		 * Processor Container.
		 */
		if (parse_msc_pm_link(tbl_msc, pdev, &acpi_id)) {
			props[next_prop++] = PROPERTY_ENTRY_U32("cpu_affinity",
								acpi_id);
		}

		err = device_create_managed_software_node(&pdev->dev, props,
							  NULL);
		if (err)
			break;

		/* Come back later if you want the RIS too */
		err = platform_device_add_data(pdev, tbl_msc, tbl_msc->length);
		if (err)
			break;

		platform_device_add(pdev);
	}

	if (err)
		platform_device_put(pdev);

	return err;
}

static struct acpi_table_header *get_table(void)
{
	struct acpi_table_header *table;
	acpi_status status;

	if (acpi_disabled || !cpus_support_mpam())
		return NULL;

	status = acpi_get_table(ACPI_SIG_MPAM, 0, &table);
	if (ACPI_FAILURE(status))
		return NULL;

	if (table->revision != 1)
		return NULL;

	return table;
}



static int __init acpi_mpam_parse(void)
{
	struct acpi_table_header *mpam;
	int err;

	mpam = get_table();
	if (!mpam)
		return 0;

	err = _parse_table(mpam);
	acpi_put_table(mpam);

	return err;
}

static int _count_msc(struct acpi_table_header *table)
{
	char *table_end, *table_offset = (char *)(table + 1);
	struct acpi_mpam_msc_node *tbl_msc;
	int ret = 0;

	tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
	table_end = (char *)table + table->length;

	while (table_offset < table_end) {
		if (tbl_msc->length < sizeof(*tbl_msc))
			return -EINVAL;

		ret++;

		table_offset += tbl_msc->length;
		tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
	}

	return ret;
}


int acpi_mpam_count_msc(void)
{
	struct acpi_table_header *mpam;
	int ret;

	mpam = get_table();
	if (!mpam)
		return 0;

	ret = _count_msc(mpam);
	acpi_put_table(mpam);

	return ret;
}

/*
 * Call after ACPI devices have been created, which happens behind acpi_scan_init()
 * called from subsys_initcall(). PCC requires the mailbox driver, which is
 * initialised from postcore_initcall().
 */
subsys_initcall_sync(acpi_mpam_parse);
