/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Local definitions for the RISC-V Quality of Service Controller (RQSC)
 * ACPI table.
 *
 * The RQSC spec is in the final phase before ratification.  These structs
 * mirror the spec's binary layout and will move to include/acpi/actbl2.h
 * via ACPICA once the spec is ratified.  Until then, keeping them in a
 * driver-private header avoids reserving an ACPICA signature/layout for
 * a still-changing spec.
 */
#ifndef _DRIVERS_ACPI_RISCV_RQSC_H
#define _DRIVERS_ACPI_RISCV_RQSC_H

#include <linux/types.h>
#include <acpi/actbl.h>

#define ACPI_SIG_RQSC	"RQSC"	/* RISC-V Quality of Service Controller */

/*
 * On-wire ACPI structures must be byte-packed: struct acpi_rqsc_resource
 * carries a u64 @id1 that the C compiler would otherwise pad to 8-byte
 * alignment, inflating sizeof(*res) from the spec's 20 bytes to 24 and
 * causing the parser to mis-size resource subtables.
 */
struct acpi_rqsc_resource {
	u8 type;
	u8 resv;
	u16 length;
	u16 flags;
	u8 resv2;
	u8 id_type;
	u64 id1;
	u32 id2;
} __packed;

struct acpi_rqsc_node {
	u8 type;
	u8 resv;
	u16 length;
	/* RQSC v0.9.2 section 2 Table 2: 12-byte GAS-format register interface address */
	struct acpi_generic_address reg;
	u16 rcid;
	u16 mcid;
	u16 flags;
	u16 nres;
	/*
	 * Followed by @nres acpi_rqsc_resource subtables.  Walk them via
	 * each resource's own length field rather than typed indexing,
	 * so a future RQSC revision that extends the resource layout
	 * does not silently misalign offsets in older parsers.
	 */
} __packed;

struct acpi_table_rqsc {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 num;
} __packed;

#endif /* _DRIVERS_ACPI_RISCV_RQSC_H */
