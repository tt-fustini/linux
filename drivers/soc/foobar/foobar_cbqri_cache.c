// SPDX-License-Identifier: GPL-2.0-only
/*
 * Foobar Systems CBQRI cache controller
 */

#define pr_fmt(fmt) "foobar-cache: " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/riscv_qos.h>

static const struct of_device_id foobar_cbqri_cache_ids[] = {
	{ .compatible = "foobar,cache-controller" },
	{ }
};

static int __init foobar_cbqri_cache_init(void)
{
	struct device_node *np;
	int err;
	u32 value;
	struct cbqri_controller_info *ctrl_info;

	for_each_matching_node(np, foobar_cbqri_cache_ids) {
		if (!of_device_is_available(np)) {
			of_node_put(np);
			continue;
		}

		ctrl_info = kzalloc(sizeof(*ctrl_info), GFP_KERNEL);
		if (!ctrl_info)
			goto err_node_put;
		ctrl_info->type = CBQRI_CONTROLLER_TYPE_CAPACITY;

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

		err = of_property_read_u32(np, "cache-level", &value);
		if (err) {
			pr_err("Failed to read cache level (%d)", err);
			goto err_kfree_ctrl_info;
		}
		ctrl_info->cache.cache_level = value;

		err = of_property_read_u32(np, "cache-size", &value);
		if (err) {
			pr_err("Failed to read cache size (%d)", err);
			goto err_kfree_ctrl_info;
		}
		ctrl_info->cache.cache_size = value;

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

		/*
		 * For CBQRI, any cpu (technically a hart in RISC-V terms)
		 * can access the memory-mapped registers of any CBQRI
		 * controller in the system. Therefore, set the CPU mask
		 * to 'FF' to allow all 8 cores in the example Foobar SoC
		 */
		err = cpumask_parse("FF", &ctrl_info->cache.cpu_mask);
		if (err) {
			pr_err("Failed to convert cores mask string to cpumask (%d)", err);
			goto err_kfree_ctrl_info;
		}

		of_node_put(np);

		pr_debug("addr=0x%lx max-rcid=%u max-mcid=%u level=%d size=%u",
			 ctrl_info->addr, ctrl_info->rcid_count, ctrl_info->mcid_count,
			 ctrl_info->cache.cache_level, ctrl_info->cache.cache_size);

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
device_initcall(foobar_cbqri_cache_init);
