// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe host controller driver for the Tenstorrent Atlantis SoC
 *
 * Copyright (C) 2026 Tenstorrent AI ULC
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/reset.h>
#include <linux/spinlock.h>

#include "pcie-designware.h"

/*
 * PCIe subsystem registers, shared by the three controllers. The resets and
 * clock gates in this block are owned by the reset and clock providers; only
 * the AXI sideband that marks DBI accesses is programmed here. The block is
 * mapped directly rather than through its syscon regmap, because the select
 * is toggled under the PCI core's raw configuration lock, where the regmap's
 * lock cannot be taken.
 */
#define TT_PCIE_SUBSYS_AWUSER0(n)		(0x20 + (n) * 0x40)
#define TT_PCIE_SUBSYS_ARUSER0(n)		(0x40 + (n) * 0x40)
#define TT_PCIE_SUBSYS_MISC_INFO_DBI		BIT(21)
#define TT_PCIE_SUBSYS_MISC_INFO_CTRL(n)	(0xe0 + (n) * 0x4)
#define TT_PCIE_SUBSYS_MISC_INFO_FROM_REG	BIT(0)

#define TT_PCIE_NUM_CONTROLLERS			3

/* Per-controller application registers */
#define TT_PCIE_APP_RADM_INT_MASK		0x0918
#define TT_PCIE_APP_RADM_INT_MASK_ALL		GENMASK(18, 0)
#define TT_PCIE_APP_LTSSM_ENABLE		0x8010
#define TT_PCIE_APP_LTSSM_ENABLE_EN		BIT(0)
#define TT_PCIE_APP_LTSSM_STATUS		0x80c4
#define TT_PCIE_APP_LTSSM_STATE			GENMASK(5, 0)
#define TT_PCIE_APP_RADM_MSG_LTR		0x81b4
#define TT_PCIE_APP_RADM_SLOT_PWR_LIMIT		0x81fc
#define TT_PCIE_APP_CONTROLLER_INT		0x82cc
#define TT_PCIE_APP_CONTROLLER_INT_STATE	BIT(0)
#define TT_PCIE_APP_INTR_MASK			0x82fc
#define TT_PCIE_APP_INTR_MASK_ALL		GENMASK(23, 0)
/* INTA to INTD occupy bits 14 down to 11 */
#define TT_PCIE_APP_INTR_MASK_INTX(x)		BIT(14 - (x))

struct tt_pcie {
	struct dw_pcie pci;
	void __iomem *app;
	void __iomem *sysreg;
	unsigned int id;
	struct reset_control *resets;
	struct gpio_desc *reset_gpio;
	struct irq_domain *intx_domain;
	int intx_irq;
	/* Serializes the DBI select sideband with the accesses that use it */
	raw_spinlock_t lock;
};

#define to_tt_pcie(x)	container_of((x), struct tt_pcie, pci)

/*
 * The controller has no dedicated DBI port. DBI, iATU and outbound TLP
 * accesses share the AXI slave interface and are told apart by bit 21 of
 * the a{w,r}misc_info sideband (the DesignWare "shared DBI" mode). The
 * subsystem block can source that sideband from a register instead of the
 * NoC: the register keeps the DBI bit set and only the source select is
 * toggled around each DBI access. The read-back makes sure the APB write
 * has landed before the AXI access that depends on it is issued.
 */
static void tt_pcie_dbi_select(struct tt_pcie *tt, bool dbi)
{
	void __iomem *reg = tt->sysreg + TT_PCIE_SUBSYS_MISC_INFO_CTRL(tt->id);

	writel(dbi ? TT_PCIE_SUBSYS_MISC_INFO_FROM_REG : 0, reg);
	readl(reg);
}

static u32 tt_pcie_read_dbi(struct dw_pcie *pci, void __iomem *base, u32 reg,
			    size_t size)
{
	struct tt_pcie *tt = to_tt_pcie(pci);
	unsigned long flags;
	u32 val;

	raw_spin_lock_irqsave(&tt->lock, flags);
	tt_pcie_dbi_select(tt, true);
	dw_pcie_read(base + reg, size, &val);
	tt_pcie_dbi_select(tt, false);
	raw_spin_unlock_irqrestore(&tt->lock, flags);

	return val;
}

static void tt_pcie_write_dbi(struct dw_pcie *pci, void __iomem *base, u32 reg,
			      size_t size, u32 val)
{
	struct tt_pcie *tt = to_tt_pcie(pci);
	unsigned long flags;

	raw_spin_lock_irqsave(&tt->lock, flags);
	tt_pcie_dbi_select(tt, true);
	dw_pcie_write(base + reg, size, val);
	tt_pcie_dbi_select(tt, false);
	raw_spin_unlock_irqrestore(&tt->lock, flags);
}

/* The Root Port's own configuration space is the DBI, so it needs the select too */
static int tt_pcie_rd_own_conf(struct pci_bus *bus, unsigned int devfn,
			       int where, int size, u32 *val)
{
	struct dw_pcie_rp *pp = bus->sysdata;
	struct tt_pcie *tt = to_tt_pcie(to_dw_pcie_from_pp(pp));
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&tt->lock, flags);
	tt_pcie_dbi_select(tt, true);
	ret = pci_generic_config_read(bus, devfn, where, size, val);
	tt_pcie_dbi_select(tt, false);
	raw_spin_unlock_irqrestore(&tt->lock, flags);

	return ret;
}

static int tt_pcie_wr_own_conf(struct pci_bus *bus, unsigned int devfn,
			       int where, int size, u32 val)
{
	struct dw_pcie_rp *pp = bus->sysdata;
	struct tt_pcie *tt = to_tt_pcie(to_dw_pcie_from_pp(pp));
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&tt->lock, flags);
	tt_pcie_dbi_select(tt, true);
	ret = pci_generic_config_write(bus, devfn, where, size, val);
	tt_pcie_dbi_select(tt, false);
	raw_spin_unlock_irqrestore(&tt->lock, flags);

	return ret;
}

static struct pci_ops tt_pcie_own_conf_ops = {
	.map_bus = dw_pcie_own_conf_map_bus,
	.read = tt_pcie_rd_own_conf,
	.write = tt_pcie_wr_own_conf,
};

static enum dw_pcie_ltssm tt_pcie_get_ltssm(struct dw_pcie *pci)
{
	struct tt_pcie *tt = to_tt_pcie(pci);

	return FIELD_GET(TT_PCIE_APP_LTSSM_STATE,
			 readl(tt->app + TT_PCIE_APP_LTSSM_STATUS));
}

static bool tt_pcie_link_up(struct dw_pcie *pci)
{
	enum dw_pcie_ltssm state = tt_pcie_get_ltssm(pci);

	/* The link is usable in L0 and in the L0s and L1 low-power states */
	return state >= DW_PCIE_LTSSM_L0 && state <= DW_PCIE_LTSSM_L1_IDLE;
}

static int tt_pcie_start_link(struct dw_pcie *pci)
{
	struct tt_pcie *tt = to_tt_pcie(pci);

	writel(TT_PCIE_APP_LTSSM_ENABLE_EN, tt->app + TT_PCIE_APP_LTSSM_ENABLE);

	return 0;
}

static void tt_pcie_stop_link(struct dw_pcie *pci)
{
	struct tt_pcie *tt = to_tt_pcie(pci);

	writel(0, tt->app + TT_PCIE_APP_LTSSM_ENABLE);
}

static const struct dw_pcie_ops tt_pcie_dw_ops = {
	.read_dbi = tt_pcie_read_dbi,
	.write_dbi = tt_pcie_write_dbi,
	.link_up = tt_pcie_link_up,
	.get_ltssm = tt_pcie_get_ltssm,
	.start_link = tt_pcie_start_link,
	.stop_link = tt_pcie_stop_link,
};

/*
 * The wrapper exposes no per-line INTx state, only the merged latch, which
 * follows the level of the unmasked sources. Find the asserted lines by
 * letting one line at a time through the mask and re-reading the latch.
 */
static unsigned long tt_pcie_intx_pending(struct tt_pcie *tt)
{
	unsigned long pending = 0;
	unsigned long flags;
	unsigned int i;
	u32 mask;

	raw_spin_lock_irqsave(&tt->pci.pp.lock, flags);
	mask = readl(tt->app + TT_PCIE_APP_INTR_MASK);
	for (i = 0; i < PCI_NUM_INTX; i++) {
		if (mask & TT_PCIE_APP_INTR_MASK_INTX(i))
			continue;
		writel(TT_PCIE_APP_INTR_MASK_ALL & ~TT_PCIE_APP_INTR_MASK_INTX(i),
		       tt->app + TT_PCIE_APP_INTR_MASK);
		writel(0, tt->app + TT_PCIE_APP_CONTROLLER_INT);
		if (readl(tt->app + TT_PCIE_APP_CONTROLLER_INT) &
		    TT_PCIE_APP_CONTROLLER_INT_STATE)
			pending |= BIT(i);
	}
	writel(mask, tt->app + TT_PCIE_APP_INTR_MASK);
	raw_spin_unlock_irqrestore(&tt->pci.pp.lock, flags);

	return pending;
}

static void tt_pcie_intx_handler(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct tt_pcie *tt = irq_desc_get_handler_data(desc);
	unsigned long pending;
	unsigned int hwirq;

	chained_irq_enter(chip, desc);

	/*
	 * A received LTR or Set_Slot_Power_Limit message is latched into a
	 * register of its own. Those two latches have no mask bit and drive
	 * the interrupt output directly, so they are cleared first, before
	 * the INTx lines are probed through the merged latch.
	 */
	writel(0, tt->app + TT_PCIE_APP_RADM_MSG_LTR);
	writel(0, tt->app + TT_PCIE_APP_RADM_SLOT_PWR_LIMIT);

	pending = tt_pcie_intx_pending(tt);
	for_each_set_bit(hwirq, &pending, PCI_NUM_INTX)
		generic_handle_domain_irq(tt->intx_domain, hwirq);

	/*
	 * The merged latch has to be cleared by software. An INTx that is
	 * still asserted, or that was masked while its handler is pending,
	 * sets it again once it is unmasked.
	 */
	writel(0, tt->app + TT_PCIE_APP_CONTROLLER_INT);

	chained_irq_exit(chip, desc);
}

static void tt_pcie_intx_mask(struct irq_data *d)
{
	struct tt_pcie *tt = irq_data_get_irq_chip_data(d);
	unsigned long flags;
	u32 val;

	raw_spin_lock_irqsave(&tt->pci.pp.lock, flags);
	val = readl(tt->app + TT_PCIE_APP_INTR_MASK);
	val |= TT_PCIE_APP_INTR_MASK_INTX(d->hwirq);
	writel(val, tt->app + TT_PCIE_APP_INTR_MASK);
	raw_spin_unlock_irqrestore(&tt->pci.pp.lock, flags);
}

static void tt_pcie_intx_unmask(struct irq_data *d)
{
	struct tt_pcie *tt = irq_data_get_irq_chip_data(d);
	unsigned long flags;
	u32 val;

	raw_spin_lock_irqsave(&tt->pci.pp.lock, flags);
	val = readl(tt->app + TT_PCIE_APP_INTR_MASK);
	val &= ~TT_PCIE_APP_INTR_MASK_INTX(d->hwirq);
	writel(val, tt->app + TT_PCIE_APP_INTR_MASK);
	raw_spin_unlock_irqrestore(&tt->pci.pp.lock, flags);
}

static struct irq_chip tt_pcie_intx_chip = {
	.name = "INTx",
	.irq_mask = tt_pcie_intx_mask,
	.irq_unmask = tt_pcie_intx_unmask,
};

static int tt_pcie_intx_map(struct irq_domain *domain, unsigned int irq,
			    irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &tt_pcie_intx_chip, handle_level_irq);
	irq_set_chip_data(irq, domain->host_data);

	return 0;
}

static const struct irq_domain_ops tt_pcie_intx_domain_ops = {
	.map = tt_pcie_intx_map,
};

static int tt_pcie_intx_init(struct tt_pcie *tt)
{
	struct device *dev = tt->pci.dev;
	struct fwnode_handle *intc;
	int irq;

	intc = device_get_named_child_node(dev, "interrupt-controller");
	if (!intc)
		return dev_err_probe(dev, -ENODEV,
				     "missing interrupt-controller node\n");

	irq = fwnode_irq_get(intc, 0);
	if (irq < 0) {
		fwnode_handle_put(intc);
		return dev_err_probe(dev, irq, "failed to get INTx interrupt\n");
	}

	tt->intx_domain = irq_domain_create_linear(intc, PCI_NUM_INTX,
						   &tt_pcie_intx_domain_ops, tt);
	fwnode_handle_put(intc);
	if (!tt->intx_domain)
		return dev_err_probe(dev, -ENOMEM,
				     "failed to create INTx domain\n");

	tt->intx_irq = irq;
	irq_set_chained_handler_and_data(irq, tt_pcie_intx_handler, tt);

	return 0;
}

static void tt_pcie_intx_exit(struct tt_pcie *tt)
{
	irq_set_chained_handler_and_data(tt->intx_irq, NULL, NULL);
	irq_domain_remove(tt->intx_domain);
}

static int tt_pcie_host_init(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);
	struct tt_pcie *tt = to_tt_pcie(pci);
	int ret;

	pp->bridge->ops = &tt_pcie_own_conf_ops;

	ret = reset_control_deassert(tt->resets);
	if (ret)
		return ret;

	/*
	 * PERST# also resets the Root Port's controller, all but its AXI
	 * interfaces, and the controller's registers cannot be accessed while
	 * it is asserted. Complete the endpoint reset pulse before anything
	 * else is programmed.
	 */
	if (tt->reset_gpio) {
		gpiod_set_value_cansleep(tt->reset_gpio, 1);
		msleep(PCIE_T_PVPERL_MS);
		gpiod_set_value_cansleep(tt->reset_gpio, 0);
		msleep(PCIE_RESET_CONFIG_WAIT_MS);
	}

	writel(TT_PCIE_SUBSYS_MISC_INFO_DBI, tt->sysreg + TT_PCIE_SUBSYS_AWUSER0(tt->id));
	writel(TT_PCIE_SUBSYS_MISC_INFO_DBI, tt->sysreg + TT_PCIE_SUBSYS_ARUSER0(tt->id));

	/*
	 * The Root Port advertises a VPD capability, but the application logic
	 * that has to serve a VPD request and set its completion flag does not
	 * exist, so every VPD access times out. Remove the capability before
	 * the Root Port is enumerated.
	 */
	dw_pcie_remove_capability(pci, PCI_CAP_ID_VPD);

	/*
	 * Only INTx is delivered through the application interrupt. The other
	 * events it can merge are reported through the Root Port's own
	 * capabilities, so keep them masked here.
	 */
	writel(TT_PCIE_APP_INTR_MASK_ALL, tt->app + TT_PCIE_APP_INTR_MASK);
	writel(TT_PCIE_APP_RADM_INT_MASK_ALL, tt->app + TT_PCIE_APP_RADM_INT_MASK);
	writel(0, tt->app + TT_PCIE_APP_CONTROLLER_INT);

	ret = tt_pcie_intx_init(tt);
	if (ret)
		goto err_assert_reset;

	return 0;

err_assert_reset:
	gpiod_set_value_cansleep(tt->reset_gpio, 1);
	reset_control_assert(tt->resets);

	return ret;
}

static void tt_pcie_host_deinit(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);
	struct tt_pcie *tt = to_tt_pcie(pci);

	gpiod_set_value_cansleep(tt->reset_gpio, 1);
	tt_pcie_intx_exit(tt);
	reset_control_assert(tt->resets);
}

static const struct dw_pcie_host_ops tt_pcie_host_ops = {
	.init = tt_pcie_host_init,
	.deinit = tt_pcie_host_deinit,
};

static int tt_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct of_phandle_args args;
	struct clk_bulk_data *clks;
	struct tt_pcie *tt;
	int ret;

	tt = devm_kzalloc(dev, sizeof(*tt), GFP_KERNEL);
	if (!tt)
		return -ENOMEM;

	tt->pci.dev = dev;
	tt->pci.ops = &tt_pcie_dw_ops;
	tt->pci.pp.ops = &tt_pcie_host_ops;
	/* Bus 0 ECAM accesses would bypass the DBI select in tt_pcie_own_conf_ops */
	tt->pci.pp.native_ecam = true;
	raw_spin_lock_init(&tt->lock);
	platform_set_drvdata(pdev, tt);

	tt->app = devm_platform_ioremap_resource_byname(pdev, "app");
	if (IS_ERR(tt->app))
		return PTR_ERR(tt->app);

	ret = of_parse_phandle_with_fixed_args(dev->of_node, "tenstorrent,sysreg",
					       1, 0, &args);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse tenstorrent,sysreg\n");

	tt->id = args.args[0];
	tt->sysreg = devm_of_iomap(dev, args.np, 0, NULL);
	of_node_put(args.np);
	if (IS_ERR(tt->sysreg))
		return dev_err_probe(dev, PTR_ERR(tt->sysreg),
				     "failed to map the subsystem registers\n");

	if (tt->id >= TT_PCIE_NUM_CONTROLLERS)
		return dev_err_probe(dev, -EINVAL, "invalid controller index %u\n",
				     tt->id);

	tt->resets = devm_reset_control_array_get_exclusive(dev);
	if (IS_ERR(tt->resets))
		return dev_err_probe(dev, PTR_ERR(tt->resets),
				     "failed to get resets\n");

	/* Hold the endpoint in reset until the controller is ready */
	tt->reset_gpio = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(tt->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(tt->reset_gpio),
				     "failed to get the reset GPIO\n");

	ret = devm_clk_bulk_get_all_enabled(dev, &clks);
	if (ret < 0)
		return dev_err_probe(dev, ret, "failed to enable clocks\n");

	return dw_pcie_host_init(&tt->pci.pp);
}

static void tt_pcie_remove(struct platform_device *pdev)
{
	struct tt_pcie *tt = platform_get_drvdata(pdev);

	dw_pcie_host_deinit(&tt->pci.pp);
}

static const struct of_device_id tt_pcie_of_match[] = {
	{ .compatible = "tenstorrent,atlantis-pcie" },
	{ }
};
MODULE_DEVICE_TABLE(of, tt_pcie_of_match);

static struct platform_driver tt_pcie_driver = {
	.driver = {
		.name = "pcie-tenstorrent",
		.of_match_table = tt_pcie_of_match,
	},
	.probe = tt_pcie_probe,
	.remove = tt_pcie_remove,
};
module_platform_driver(tt_pcie_driver);

MODULE_DESCRIPTION("Tenstorrent Atlantis PCIe host controller driver");
MODULE_LICENSE("GPL");
