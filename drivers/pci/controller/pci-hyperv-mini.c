// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Microsoft Corporation.
 *
 * Author:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *
 * This mini driver is a helper driver allows other drivers to
 * have a common interface with the Hyper-V PCI frontend driver.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hyperv.h>

struct hyperv_pci_block_ops hvpci_block_ops;
EXPORT_SYMBOL(hvpci_block_ops);

int hyperv_read_cfg_blk(struct pci_dev *dev, void *buf, unsigned int buf_len,
			unsigned int block_id, unsigned int *bytes_returned)
{
	if (!hvpci_block_ops.read_block)
		return -EOPNOTSUPP;

	return hvpci_block_ops.read_block(dev, buf, buf_len, block_id,
					  bytes_returned);
}
EXPORT_SYMBOL(hyperv_read_cfg_blk);

int hyperv_write_cfg_blk(struct pci_dev *dev, void *buf, unsigned int len,
			 unsigned int block_id)
{
	if (!hvpci_block_ops.write_block)
		return -EOPNOTSUPP;

	return hvpci_block_ops.write_block(dev, buf, len, block_id);
}
EXPORT_SYMBOL(hyperv_write_cfg_blk);

int hyperv_reg_block_invalidate(struct pci_dev *dev, void *context,
				void (*block_invalidate)(void *context,
							 u64 block_mask))
{
	if (!hvpci_block_ops.reg_blk_invalidate)
		return -EOPNOTSUPP;

	return hvpci_block_ops.reg_blk_invalidate(dev, context,
						  block_invalidate);
}
EXPORT_SYMBOL(hyperv_reg_block_invalidate);

static void __exit exit_hv_pci_mini(void)
{
	pr_info("unloaded\n");
}

static int __init init_hv_pci_mini(void)
{
	pr_info("loaded\n");

	return 0;
}

module_init(init_hv_pci_mini);
module_exit(exit_hv_pci_mini);

MODULE_DESCRIPTION("Hyper-V PCI Mini");
MODULE_LICENSE("GPL v2");
