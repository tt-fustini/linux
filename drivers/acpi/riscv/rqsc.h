/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Definitions for the RISC-V Quality of Service Controllers (RQSC) ACPI
 * table, kept here until ACPICA carries them in actbl2.h.
 */
#ifndef _DRIVERS_ACPI_RISCV_RQSC_H
#define _DRIVERS_ACPI_RISCV_RQSC_H

#include <linux/acpi.h>
#include <linux/types.h>

#define ACPI_SIG_RQSC	"RQSC"	/* RISC-V Quality of Service Controllers Table */

#define ACPI_RQSC_REVISION	1

/* QoS Controller Type */
#define ACPI_RQSC_CONTROLLER_TYPE_CAPACITY	0
#define ACPI_RQSC_CONTROLLER_TYPE_BANDWIDTH	1

/* Resource Type */
#define ACPI_RQSC_RESOURCE_TYPE_CACHE	0
#define ACPI_RQSC_RESOURCE_TYPE_MEMORY	1

/* Resource ID Type */
#define ACPI_RQSC_RESOURCE_ID_TYPE_PROCESSOR_CACHE	0
#define ACPI_RQSC_RESOURCE_ID_TYPE_MEMORY_RANGE		1
#define ACPI_RQSC_RESOURCE_ID_TYPE_MEMORY_SIDE_CACHE	2
#define ACPI_RQSC_RESOURCE_ID_TYPE_ACPI_DEVICE		3
#define ACPI_RQSC_RESOURCE_ID_TYPE_PCI_DEVICE		4

/* Controller Flags */
#define ACPI_RQSC_CONTROLLER_ZERO_BLOCKS	(1) /* Zero blocks can be allocated to an RCID */

struct acpi_rqsc_resource {
	u8 type;
	u8 reserved;
	u16 length;
	u16 flags;
	u8 reserved2;
	u8 id_type;
	u64 id1;
	u32 id2;
} __packed;

/* Resource Specific Data that follows a memory resource */
struct acpi_rqsc_memory_data {
	u64 bandwidth_per_block;	/* In bytes per second, 0 if not provided */
} __packed;

struct acpi_rqsc_controller {
	u8 type;
	u8 reserved;
	u16 length;
	struct acpi_generic_address address;
	u16 rcid_count;
	u16 mcid_count;
	u16 flags;
	u16 num_resources;
	/* Followed by num_resources struct acpi_rqsc_resource */
} __packed;

struct acpi_table_rqsc {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 num_controllers;
} __packed;

#endif /* _DRIVERS_ACPI_RISCV_RQSC_H */
