// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "cbqri-bandwidth: " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/riscv_qos.h>

static const struct of_device_id cbqri_mem_ctrl_ids[] = {
	{ .compatible = "riscv,cbqri-bandwidth" },
	{ }
};

static int __init cbqri_mem_ctrl_init(void)
{
	struct cbqri_controller_info *ctrl_info;
	struct device_node *np;
	u32 value;
	int err;

	for_each_matching_node(np, cbqri_mem_ctrl_ids) {
		if (!of_device_is_available(np)) {
			of_node_put(np);
			continue;
		}

		ctrl_info = kzalloc(sizeof(*ctrl_info), GFP_KERNEL);
		if (!ctrl_info)
			goto err_node_put;
		ctrl_info->type = CBQRI_CONTROLLER_TYPE_BANDWIDTH;

		err = of_property_read_u32_index(np, "reg", 1, &value);
		if (err) {
			pr_err("Failed to read reg base address (%d)", err);
			goto err_kfree_ctrl_info;
		}
		ctrl_info->addr = value;

		err = of_property_read_u32_index(np, "reg", 3, &value);
		if (err) {
			pr_err("Failed to read reg size (%d)", err);
			goto err_kfree_ctrl_info;
		}
		ctrl_info->size = value;

		err = of_property_read_u32(np, "riscv,cbqri-rcid", &value);
		if (err) {
			pr_err("Failed to read RCID count (%d)", err);
			goto err_kfree_ctrl_info;
		}
		ctrl_info->rcid_count = value;

		err = of_property_read_u32(np, "riscv,cbqri-mcid", &value);
		if (err) {
			pr_err("Failed to read MCID count (%d)", err);
			goto err_kfree_ctrl_info;
		}
		ctrl_info->mcid_count = value;

		of_node_put(np);

		pr_debug("addr=0x%lx max-rcid=%u max-mcid=%u", ctrl_info->addr,
			 ctrl_info->rcid_count, ctrl_info->mcid_count);

		/* Fill the list shared with RISC-V QoS resctrl */
		INIT_LIST_HEAD(&ctrl_info->list);
		list_add_tail(&ctrl_info->list, &cbqri_controllers);
	}

	return 0;

err_kfree_ctrl_info:
	kfree(ctrl_info);

err_node_put:
	of_node_put(np);

	return err;
}
device_initcall(cbqri_mem_ctrl_init);
