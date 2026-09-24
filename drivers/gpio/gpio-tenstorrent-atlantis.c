// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tenstorrent Atlantis GPIO controller driver
 *
 * Copyright (c) 2026 Tenstorrent
 */

#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/gpio/driver.h>
#include <linux/gpio/generic.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/math.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/time64.h>

/* Every register below holds one bit per line. */
#define ATLANTIS_GPIO_DATA	0x00	/* Output value */
#define ATLANTIS_GPIO_DIR	0x04	/* Direction, 1 = output */
#define ATLANTIS_GPIO_EXT	0x0c	/* Line level (read-only) */
#define ATLANTIS_GPIO_IEN	0x10	/* Interrupt detection enable */
#define ATLANTIS_GPIO_IS	0x14	/* Interrupt sense, 1 = level */
#define ATLANTIS_GPIO_IBE	0x18	/* Interrupt on both edges */
#define ATLANTIS_GPIO_IEV	0x1c	/* Interrupt event, 1 = rising or high */
#define ATLANTIS_GPIO_RIS	0x20	/* Raw interrupt status */
#define ATLANTIS_GPIO_IM	0x24	/* Interrupt mask, 1 = masked */
#define ATLANTIS_GPIO_MIS	0x28	/* Masked interrupt status */
#define ATLANTIS_GPIO_IC	0x2c	/* Edge interrupt clear, write 1 */
#define ATLANTIS_GPIO_DB	0x30	/* Debounce enable */
#define ATLANTIS_GPIO_DFG	0x34	/* Debounce clock divider */

#define ATLANTIS_GPIO_NR_LINES	32
#define ATLANTIS_GPIO_NR_IRQS	2

/* All ones stops the debounce clock instead of dividing it. */
#define ATLANTIS_GPIO_DFG_MAX	(U32_MAX - 1)

struct atlantis_gpio {
	struct gpio_generic_chip chip;
	void __iomem *base;
	struct clk *clk;
	unsigned int irqs[ATLANTIS_GPIO_NR_IRQS];
};

static struct atlantis_gpio *to_atlantis_gpio(struct gpio_chip *gc)
{
	return container_of(to_gpio_generic_chip(gc), struct atlantis_gpio,
			    chip);
}

/* Read-modify-write one line's bit. The caller holds the chip lock. */
static void atlantis_gpio_update_bit(struct atlantis_gpio *gpio,
				     unsigned int reg, unsigned int offset,
				     bool set)
{
	u32 val;

	val = readl(gpio->base + reg);
	if (set)
		val |= BIT(offset);
	else
		val &= ~BIT(offset);
	writel(val, gpio->base + reg);
}

static int atlantis_gpio_set_debounce(struct atlantis_gpio *gpio,
				      unsigned int offset, u32 debounce_us)
{
	unsigned long rate;
	u64 dfg;
	u32 db;

	if (!debounce_us) {
		guard(gpio_generic_lock_irqsave)(&gpio->chip);
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_DB, offset, false);
		return 0;
	}

	/*
	 * The filter drops pulses shorter than two debounce clock periods
	 * and the debounce clock is pclk / (DFG + 1). Turn the requested
	 * time into that divider.
	 */
	rate = clk_get_rate(gpio->clk);
	dfg = DIV_ROUND_UP_ULL((u64)rate * debounce_us, 2 * USEC_PER_SEC);
	if (dfg)
		dfg--;
	if (dfg > ATLANTIS_GPIO_DFG_MAX)
		return -EINVAL;

	guard(gpio_generic_lock_irqsave)(&gpio->chip);

	/*
	 * One divider serves all 32 lines. Refuse to change it under lines
	 * that already depend on the current value.
	 */
	db = readl(gpio->base + ATLANTIS_GPIO_DB);
	if ((db & ~BIT(offset)) &&
	    readl(gpio->base + ATLANTIS_GPIO_DFG) != dfg)
		return -EBUSY;

	writel(dfg, gpio->base + ATLANTIS_GPIO_DFG);
	writel(db | BIT(offset), gpio->base + ATLANTIS_GPIO_DB);

	return 0;
}

static int atlantis_gpio_set_config(struct gpio_chip *gc, unsigned int offset,
				    unsigned long config)
{
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);

	switch (pinconf_to_config_param(config)) {
	case PIN_CONFIG_INPUT_DEBOUNCE:
		return atlantis_gpio_set_debounce(gpio, offset,
					pinconf_to_config_argument(config));
	default:
		return gpiochip_generic_config(gc, offset, config);
	}
}

static void atlantis_gpio_irq_ack(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);

	writel(BIT(irqd_to_hwirq(d)), gpio->base + ATLANTIS_GPIO_IC);
}

static void atlantis_gpio_irq_mask(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	scoped_guard(gpio_generic_lock_irqsave, &gpio->chip)
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IM, hwirq, true);

	gpiochip_disable_irq(gc, hwirq);
}

static void atlantis_gpio_irq_unmask(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	gpiochip_enable_irq(gc, hwirq);

	scoped_guard(gpio_generic_lock_irqsave, &gpio->chip)
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IM, hwirq, false);
}

static void atlantis_gpio_irq_enable(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	scoped_guard(gpio_generic_lock_irqsave, &gpio->chip)
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IEN, hwirq, true);

	atlantis_gpio_irq_unmask(d);
}

static void atlantis_gpio_irq_disable(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	atlantis_gpio_irq_mask(d);

	scoped_guard(gpio_generic_lock_irqsave, &gpio->chip)
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IEN, hwirq, false);
}

static int atlantis_gpio_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct atlantis_gpio *gpio = to_atlantis_gpio(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);
	bool level = false, both = false, high = false;

	switch (type) {
	case IRQ_TYPE_EDGE_RISING:
		high = true;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		break;
	case IRQ_TYPE_EDGE_BOTH:
		both = true;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		level = true;
		high = true;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		level = true;
		break;
	default:
		return -EINVAL;
	}

	scoped_guard(gpio_generic_lock_irqsave, &gpio->chip) {
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IS, hwirq, level);
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IBE, hwirq, both);
		atlantis_gpio_update_bit(gpio, ATLANTIS_GPIO_IEV, hwirq, high);
	}

	/* Drop any edge latched while the line was being reconfigured. */
	writel(BIT(hwirq), gpio->base + ATLANTIS_GPIO_IC);

	irq_set_handler_locked(d, level ? handle_level_irq : handle_edge_irq);

	return 0;
}

static void atlantis_gpio_irq_handler(struct irq_desc *desc)
{
	struct atlantis_gpio *gpio = irq_desc_get_handler_data(desc);
	struct irq_chip *ic = irq_desc_get_chip(desc);
	unsigned long pending;
	unsigned int hwirq;

	chained_irq_enter(ic, desc);

	pending = readl(gpio->base + ATLANTIS_GPIO_MIS);
	for_each_set_bit(hwirq, &pending, ATLANTIS_GPIO_NR_LINES)
		generic_handle_domain_irq(gpio->chip.gc.irq.domain, hwirq);

	chained_irq_exit(ic, desc);
}

static const struct irq_chip atlantis_gpio_irq_chip = {
	.name		= "atlantis-gpio",
	.irq_ack	= atlantis_gpio_irq_ack,
	.irq_mask	= atlantis_gpio_irq_mask,
	.irq_unmask	= atlantis_gpio_irq_unmask,
	.irq_enable	= atlantis_gpio_irq_enable,
	.irq_disable	= atlantis_gpio_irq_disable,
	.irq_set_type	= atlantis_gpio_irq_set_type,
	.flags		= IRQCHIP_IMMUTABLE | IRQCHIP_SKIP_SET_WAKE,
	GPIOCHIP_IRQ_RESOURCE_HELPERS,
};

static int atlantis_gpio_probe(struct platform_device *pdev)
{
	struct gpio_generic_chip_config config;
	struct device *dev = &pdev->dev;
	struct atlantis_gpio *gpio;
	struct gpio_irq_chip *girq;
	struct reset_control *rst;
	struct gpio_chip *gc;
	int i, ret;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	gpio->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(gpio->base))
		return PTR_ERR(gpio->base);

	for (i = 0; i < ATLANTIS_GPIO_NR_IRQS; i++) {
		ret = platform_get_irq(pdev, i);
		if (ret < 0)
			return ret;
		gpio->irqs[i] = ret;
	}

	rst = devm_reset_control_get_optional_exclusive_deasserted(dev, NULL);
	if (IS_ERR(rst))
		return dev_err_probe(dev, PTR_ERR(rst),
				     "failed to deassert reset\n");

	gpio->clk = devm_clk_get_enabled(dev, NULL);
	if (IS_ERR(gpio->clk))
		return dev_err_probe(dev, PTR_ERR(gpio->clk),
				     "failed to get clock\n");

	/*
	 * Quiesce the interrupt logic. Directions, output values and
	 * debounce settings left by firmware are kept as they are.
	 */
	writel(0, gpio->base + ATLANTIS_GPIO_IEN);
	writel(GENMASK(31, 0), gpio->base + ATLANTIS_GPIO_IM);
	writel(GENMASK(31, 0), gpio->base + ATLANTIS_GPIO_IC);

	config = (struct gpio_generic_chip_config) {
		.dev = dev,
		.sz = 4,
		.dat = gpio->base + ATLANTIS_GPIO_EXT,
		.set = gpio->base + ATLANTIS_GPIO_DATA,
		.dirout = gpio->base + ATLANTIS_GPIO_DIR,
	};

	ret = gpio_generic_chip_init(&gpio->chip, &config);
	if (ret)
		return dev_err_probe(dev, ret, "failed to init generic chip\n");

	gc = &gpio->chip.gc;
	gc->request = gpiochip_generic_request;
	gc->free = gpiochip_generic_free;
	gc->set_config = atlantis_gpio_set_config;

	girq = &gc->irq;
	gpio_irq_chip_set_chip(girq, &atlantis_gpio_irq_chip);
	girq->parent_handler = atlantis_gpio_irq_handler;
	girq->parent_handler_data = gpio;
	girq->num_parents = ATLANTIS_GPIO_NR_IRQS;
	girq->parents = gpio->irqs;
	girq->default_type = IRQ_TYPE_NONE;
	girq->handler = handle_bad_irq;

	return devm_gpiochip_add_data(dev, gc, gpio);
}

static const struct of_device_id atlantis_gpio_of_match[] = {
	{ .compatible = "tenstorrent,atlantis-gpio" },
	{ }
};
MODULE_DEVICE_TABLE(of, atlantis_gpio_of_match);

static struct platform_driver atlantis_gpio_driver = {
	.probe = atlantis_gpio_probe,
	.driver = {
		.name = "atlantis-gpio",
		.of_match_table = atlantis_gpio_of_match,
	},
};
module_platform_driver(atlantis_gpio_driver);

MODULE_AUTHOR("Drew Fustini <dfustini@oss.tenstorrent.com>");
MODULE_DESCRIPTION("Tenstorrent Atlantis GPIO controller driver");
MODULE_LICENSE("GPL");
