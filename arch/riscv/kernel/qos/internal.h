/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_QOS_INTERNAL_H
#define _ASM_RISCV_QOS_INTERNAL_H

#include <linux/bitfield.h>
#include <linux/resctrl.h>
#include <linux/riscv_qos.h>

#define RISCV_RESCTRL_EMPTY_CLOSID	((u32)~0)

#define CBQRI_CC_CAPABILITIES_OFF 0
#define CBQRI_CC_MON_CTL_OFF      8
#define CBQRI_CC_MON_CTL_VAL_OFF 16
#define CBQRI_CC_ALLOC_CTL_OFF   24
#define CBQRI_CC_BLOCK_MASK_OFF  32

#define CBQRI_BC_CAPABILITIES_OFF 0
#define CBQRI_BC_MON_CTL_OFF      8
#define CBQRI_BC_MON_CTL_VAL_OFF 16
#define CBQRI_BC_ALLOC_CTL_OFF   24
#define CBQRI_BC_BW_ALLOC_OFF    32

#define CBQRI_CC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_CC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_CC_CAPABILITIES_NCBLKS_MASK  GENMASK(23, 8)

#define CBQRI_BC_CAPABILITIES_VER_MINOR_MASK  GENMASK(3, 0)
#define CBQRI_BC_CAPABILITIES_VER_MAJOR_MASK  GENMASK(7, 4)

#define CBQRI_BC_CAPABILITIES_NBWBLKS_MASK  GENMASK(23, 8)
#define CBQRI_BC_CAPABILITIES_MRBWB_MASK    GENMASK_ULL(47, 32)

#define CBQRI_CONTROL_REGISTERS_OP_MASK      GENMASK(4, 0)
#define CBQRI_CONTROL_REGISTERS_AT_MASK      GENMASK(7, 5)
#define CBQRI_CONTROL_REGISTERS_AT_DATA      0
#define CBQRI_CONTROL_REGISTERS_AT_CODE      1
#define CBQRI_CONTROL_REGISTERS_RCID_MASK    GENMASK(19, 8)
#define CBQRI_CONTROL_REGISTERS_STATUS_MASK  GENMASK_ULL(38, 32)
#define CBQRI_CONTROL_REGISTERS_BUSY_MASK    GENMASK_ULL(39, 39)
#define CBQRI_CONTROL_REGISTERS_RBWB_MASK    GENMASK(15, 0)
#define CBQRI_CONTROL_REGISTERS_MWEIGHT_MASK GENMASK(27, 20)

#define CBQRI_CC_MON_CTL_OP_CONFIG_EVENT 1
#define CBQRI_CC_MON_CTL_OP_READ_COUNTER 2
#define CBQRI_CC_MON_CTL_STATUS_SUCCESS  1

#define CBQRI_CC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_CC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_CC_ALLOC_CTL_STATUS_SUCCESS  1

#define CBQRI_BC_ALLOC_CTL_OP_CONFIG_LIMIT 1
#define CBQRI_BC_ALLOC_CTL_OP_READ_LIMIT   2
#define CBQRI_BC_ALLOC_CTL_STATUS_SUCCESS  1

#define CBQRI_BC_MON_CTL_OP_CONFIG_EVENT 1
#define CBQRI_BC_MON_CTL_OP_READ_COUNTER 2
#define CBQRI_BC_MON_CTL_STATUS_SUCCESS  1

/* cc_mon_ctl / bc_mon_ctl field masks (same layout as alloc_ctl plus EVT_ID) */
#define CBQRI_MON_CTL_OP_MASK        GENMASK(4, 0)
#define CBQRI_MON_CTL_MCID_MASK      GENMASK(19, 8)
#define CBQRI_MON_CTL_EVT_ID_MASK    GENMASK(27, 20)
#define CBQRI_MON_CTL_STATUS_MASK    GENMASK_ULL(38, 32)

/* Capacity usage monitoring event IDs (CBQRI spec Table 4) */
#define CBQRI_CC_EVT_ID_NONE         0
#define CBQRI_CC_EVT_ID_OCCUPANCY    1

/* Bandwidth usage monitoring event IDs (CBQRI spec Table 10) */
#define CBQRI_BC_EVT_ID_NONE              0
#define CBQRI_BC_EVT_ID_TOTAL_READ_WRITE  1
#define CBQRI_BC_EVT_ID_TOTAL_READ        2
#define CBQRI_BC_EVT_ID_TOTAL_WRITE       3

/* bc_mon_ctr_val layout (CBQRI spec §4.2) */
#define CBQRI_BC_MON_CTR_VAL_CTR_MASK    GENMASK_ULL(61, 0)
#define CBQRI_BC_MON_CTR_VAL_INVALID     BIT_ULL(62)
#define CBQRI_BC_MON_CTR_VAL_OVF         BIT_ULL(63)

int qos_resctrl_setup(void);
int qos_resctrl_online_cpu(unsigned int cpu);
int qos_resctrl_offline_cpu(unsigned int cpu);

struct cbqri_resctrl_res {
	struct rdt_resource     resctrl_res;
	u32 max_rcid;
	u32 max_mcid;
};

struct cbqri_resctrl_dom {
	struct rdt_ctrl_domain  resctrl_ctrl_dom;
	struct cbqri_controller *hw_ctrl;
};

struct cbqri_config {
	u64 cbm; /* capacity block mask */
	u64 rbwb; /* reserved bandwidth blocks */
	u64 mweight; /* opportunistic bandwidth weight (0-255) */
};

#endif /* _ASM_RISCV_QOS_INTERNAL_H */
