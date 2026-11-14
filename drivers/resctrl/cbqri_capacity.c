// SPDX-License-Identifier: GPL-2.0-only
/*
 * Platform driver for a RISC-V CBQRI capacity controller that backs a CPU
 * cache. The controller is described in device tree by the generic
 * "riscv,cbqri-capacity-controller" compatible together with a phandle to the
 * cache node it governs, or in ACPI by the RQSC table, whose parser creates a
 * "cbqri-capacity" platform device that carries the PPTT Cache ID of the
 * cache. The driver hands it to the CBQRI core, which probes the capabilities
 * register and exposes a controller that supports allocation as the resctrl
 * cache allocation resource for that cache.
 */

#include <linux/acpi.h>
#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/device-id/of.h>
#include <linux/err.h>
#include <linux/ioport.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/riscv_cbqri.h>
#include <linux/types.h>

static int cbqri_capacity_of_cache(struct device *dev, u32 *cache_level,
				   u32 *cache_id)
{
	struct device_node *cache_np;
	bool found = false;
	int cpu, ret;

	cache_np = of_parse_phandle(dev->of_node, "riscv,cbqri-cache", 0);
	if (!cache_np) {
		dev_err(dev, "missing riscv,cbqri-cache phandle\n");
		return -EINVAL;
	}

	ret = of_property_read_u32(cache_np, "cache-level", cache_level);
	if (ret) {
		dev_err(dev, "%pOF: missing cache-level\n", cache_np);
		goto out_put;
	}

	if (*cache_level != 2 && *cache_level != 3) {
		dev_err(dev, "%pOF: unsupported cache-level %u\n",
			cache_np, *cache_level);
		ret = -EINVAL;
		goto out_put;
	}

	/*
	 * Associate the controller with its cache instance via cacheinfo.
	 * The matching cache provides the cache id used as the resctrl
	 * domain id.
	 *
	 * Taking the first leaf at the level is sufficient because a
	 * unified cache node yields one cacheinfo leaf and
	 * cache_setup_of_node() walks one cache node per leaf past L1, so
	 * the first leaf at the level has that level's node as fw_token.
	 *
	 * get_cpu_cacheinfo_level() returns the leaf only when cacheinfo
	 * assigned it an id (CACHE_ID), which the resctrl domain id needs.
	 */
	cpus_read_lock();
	for_each_online_cpu(cpu) {
		struct cacheinfo *ci = get_cpu_cacheinfo_level(cpu, *cache_level);

		if (ci && ci->fw_token == cache_np) {
			*cache_id = ci->id;
			found = true;
			break;
		}
	}
	cpus_read_unlock();

	if (!found) {
		dev_err(dev, "%pOF: no online hart reports an L%u cache with a cache id for this node\n",
			cache_np, *cache_level);
		ret = -ENODEV;
	}

out_put:
	of_node_put(cache_np);
	return ret;
}

/*
 * The RQSC table names the cache by its PPTT Cache ID, which the table parser
 * passes on in the riscv,cbqri-cache-id property. cacheinfo takes the cache
 * id from the same PPTT field, and the PPTT gives the level of the cache.
 */
static int cbqri_capacity_acpi_cache(struct device *dev, u32 *cache_level,
				     u32 *cache_id)
{
	int level, ret;

	ret = device_property_read_u32(dev, "riscv,cbqri-cache-id", cache_id);
	if (ret) {
		dev_err(dev, "missing riscv,cbqri-cache-id\n");
		return ret;
	}

	level = find_acpi_cache_level_from_id(*cache_id);
	if (level < 0) {
		dev_err(dev, "no PPTT cache with Cache ID %u\n", *cache_id);
		return level;
	}

	if (level != 2 && level != 3) {
		dev_err(dev, "unsupported cache level %d for Cache ID %u\n",
			level, *cache_id);
		return -EINVAL;
	}

	*cache_level = level;

	return 0;
}

static int cbqri_capacity_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cbqri_controller_info info = {};
	struct resource *res;
	void __iomem *base;
	u32 rcid_count, cache_level, cache_id;
	int ret;

	base = devm_platform_get_and_ioremap_resource(pdev, 0, &res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	ret = device_property_read_u32(dev, "riscv,cbqri-rcid", &rcid_count);
	if (ret) {
		dev_err(dev, "missing riscv,cbqri-rcid\n");
		return ret;
	}

	if (dev->of_node)
		ret = cbqri_capacity_of_cache(dev, &cache_level, &cache_id);
	else
		ret = cbqri_capacity_acpi_cache(dev, &cache_level, &cache_id);
	if (ret)
		return ret;

	info.type = CBQRI_CONTROLLER_TYPE_CAPACITY;
	info.base = base;
	info.addr = res->start;
	info.size = resource_size(res);
	info.rcid_count = rcid_count;
	info.cache_id = cache_id;
	info.cache_level = cache_level;

	ret = riscv_cbqri_register_cc(&info);
	if (ret) {
		dev_err(dev, "failed to register capacity controller: %d\n", ret);
		return ret;
	}

	dev_info(dev, "registered L%u capacity controller at %pa (cache_id=%u, rcid=%u)\n",
		 cache_level, &info.addr, cache_id, rcid_count);

	return 0;
}

static const struct of_device_id cbqri_capacity_of_match[] = {
	{ .compatible = "riscv,cbqri-capacity-controller" },
	{}
};
MODULE_DEVICE_TABLE(of, cbqri_capacity_of_match);

static struct platform_driver cbqri_capacity_driver = {
	.probe	= cbqri_capacity_probe,
	.driver = {
		.name		= "cbqri-capacity",
		.of_match_table	= cbqri_capacity_of_match,
		/*
		 * The controller is registered permanently into the
		 * CBQRI core for the life of the system. Block unbind
		 * so userspace cannot leave a dangling controller.
		 */
		.suppress_bind_attrs = true,
	},
};

/*
 * Register at device_initcall so probe runs before the resctrl glue's
 * late_initcall, which copies the cbqri_controllers list.
 */
builtin_platform_driver(cbqri_capacity_driver);
