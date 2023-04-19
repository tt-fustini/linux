/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_QOS_INTERNAL_H
#define _ASM_RISCV_QOS_INTERNAL_H

#include <linux/resctrl.h>

#define CBQRI_CC_CAPABILITIES_OFF 0
#define CBQRI_CC_MON_CTL_OFF      8
#define CBQRI_CC_MON_CTL_VAL_OFF 16
#define CBQRI_CC_ALLOC_CTL_OFF   24
#define CBQRI_CC_BLOCK_MASK_OFF  32

#define CBQRI_BC_CAPABILITIES_OFF 0
#define CBQRI_BC_MON_CTL_OFF      8
#define CBQRI_BC_MON_CTR_VAL_OFF 16
#define CBQRI_BC_ALLOC_CTL_OFF   24
#define CBQRI_BC_BW_ALLOC_OFF    32

#define CBQRI_CC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_CC_CAPABILITIES_FRCID_MASK   0x1
#define CBQRI_CC_CAPABILITIES_FRCID_SHIFT  24

#define CBQRI_CC_CAPABILITIES_NCBLKS_SHIFT 8
#define CBQRI_CC_CAPABILITIES_NCBLKS_MASK  0xFFFF

#define CBQRI_BC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_BC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_BC_CAPABILITIES_NBWBLKS_SHIFT 8
#define CBQRI_BC_CAPABILITIES_NBWBLKS_MASK  0xFFFF
#define CBQRI_BC_CAPABILITIES_MRBWB_SHIFT   32
#define CBQRI_BC_CAPABILITIES_MRBWB_MASK    0xFFFF

#define CBQRI_CONTROL_REGISTERS_BUSY_SHIFT   39
#define CBQRI_CONTROL_REGISTERS_BUSY_MASK    0x01
#define CBQRI_CONTROL_REGISTERS_STATUS_SHIFT 32
#define CBQRI_CONTROL_REGISTERS_STATUS_MASK  0x7F
#define CBQRI_CONTROL_REGISTERS_OP_SHIFT     0
#define CBQRI_CONTROL_REGISTERS_OP_MASK      0x1F
#define CBQRI_CONTROL_REGISTERS_AT_SHIFT     5
#define CBQRI_CONTROL_REGISTERS_AT_MASK      0x07
#define CBQRI_CONTROL_REGISTERS_AT_DATA      0
#define CBQRI_CONTROL_REGISTERS_AT_CODE      1
#define CBQRI_CONTROL_REGISTERS_RCID_SHIFT   8
#define CBQRI_CONTROL_REGISTERS_RCID_MASK    0xFFF
#define CBQRI_CONTROL_REGISTERS_RBWB_SHIFT   0
#define CBQRI_CONTROL_REGISTERS_RBWB_MASK    0xFF

#define CBQRI_CC_MON_CTL_OP_CONFIG_EVENT 1
#define CBQRI_CC_MON_CTL_OP_READ_COUNTER 2
#define CBQRI_CC_MON_CTL_STATUS_SUCCESS  1

#define CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_CC_ALLOC_CTL_OP_FLUSH_RCID   3
#define CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS  1

#define CBQRI_BC_MON_CTL_OP_CONFIG_EVENT 1
#define CBQRI_BC_MON_CTL_OP_READ_COUNTER 2
#define CBQRI_BC_MON_CTL_STATUS_SUCCESS  1

#define CBQRI_BC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS  1

/* Capacity Controller hardware capabilities */
/* from qemu/include/hw/riscv/cbqri.h */
struct riscv_cbqri_capacity_caps {
	u16 ncblks;
	u16 cache_level;
	u32 blk_size;

	bool supports_alloc_at_data;
	bool supports_alloc_at_code;

	bool supports_alloc_op_config_limit;
	bool supports_alloc_op_read_limit;
	bool supports_alloc_op_flush_rcid;

	bool supports_mon_at_data;
	bool supports_mon_at_code;

	bool supports_mon_op_config_event;
	bool supports_mon_op_read_counter;

	bool supports_mon_evt_id_none;
	bool supports_mon_evt_id_occupancy;
};

/* Bandwidth Controller hardware capabilities */
/* from qemu/include/hw/riscv/cbqri.h */
struct riscv_cbqri_bandwidth_caps {
	u16 nbwblks; /* number of bandwidth block */
	u16 mrbwb;   /* max reserved bw blocks */

	bool supports_alloc_at_data;
	bool supports_alloc_at_code;

	bool supports_alloc_op_config_limit;
	bool supports_alloc_op_read_limit;

	bool supports_mon_at_data;
	bool supports_mon_at_code;

	bool supports_mon_op_config_event;
	bool supports_mon_op_read_counter;

	bool supports_mon_evt_id_none;
	bool supports_mon_evt_id_rdwr_count;
	bool supports_mon_evt_id_rdonly_count;
	bool supports_mon_evt_id_wronly_count;
};

struct cbqri_controller {
	struct cbqri_controller_info *ctrl_info;
	void __iomem *base;

	int ver_major;
	int ver_minor;

	struct riscv_cbqri_bandwidth_caps bc;
	struct riscv_cbqri_capacity_caps cc;

	bool alloc_capable;
	bool mon_capable;
};

#endif /* _ASM_RISCV_QOS_INTERNAL_H */
