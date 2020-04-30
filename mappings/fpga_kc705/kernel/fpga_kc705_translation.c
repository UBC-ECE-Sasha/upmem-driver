/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/version.h>
#include <asm/cacheflush.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#endif /* __KERNEL__ */

#include "dpu_region_address_translation.h"
#include "dpu_region.h"

#include "dpu_dma_op.h"
#include "dpu_spi.h"
#include "dpu_utils.h"

#define DPU_HOST_CONTROLLER_BAR_OFFSET 0x40000
#define DPU_ANALYZER_OFFSET 0x8000
#define ILA_TRIGGER_OFFSET 0x0
#define ILA_EMPTY_FLAGS_OFFSET 0x8
#define ILA_FULL_FLAGS_OFFSET 0x10
#define ILA_RESET_OFFSET 0x18
#define ILA_VALUE_COUNTER_OFFSET 0x20
#define ILA_FILTER_OFFSET 0x28

#define ILA_POP_GROUP_0_OFFSET 0x40
#define ILA_POP_GROUP_1_OFFSET 0x50
#define ILA_POP_GROUP_2_OFFSET 0x60

#define MRAM_BYPASS_OFFSET 0x70
#define MRAM_EMUL_REFRESH_OFFSET 0x78

#define ILA_FIFO_DEPTH (1 << 16)
#define ILA_OUTPUT_ENTRY_LENGTH 79

#define TRIGGER_ENABLE_SHIFT 63
#define TRIGGER_SELECTION_SHIFT 56
#define TRIGGER_VALUE_SHIFT 0

#define ISTATE_TRIGGER_SELECTION 5ULL
#define ISTATE_BOOT_STATE_VALUE 3ULL

static int write_register64(const uint64_t *buff, uint32_t lw_off,
			    struct pci_device_fpga *pdev)
{
	volatile uint64_t *ptr = (uint64_t *)pdev->banks[0].addr;

	memcpy_toio((void *)(ptr + lw_off / 2), buff, 8);

	return 8;
}

static int read_register64(uint64_t *buff, uint32_t lw_off,
			   struct pci_device_fpga *pdev)
{
	volatile uint64_t *ptr = (uint64_t *)pdev->banks[0].addr;

	memcpy_fromio(buff, (void *)(ptr + lw_off / 2), 8);

	return 8;
}

ssize_t dpu_device_read_register(uint64_t *buf, uint32_t off,
				 struct pci_device_fpga *pdev,
				 struct dpu_region *region)
{
	uint32_t lw_offset = off >> 2;
	int err, ret = sizeof(uint64_t);

	if (region->spi_mode_enabled && lw_offset == 0) {
		ret = dpu_spi_read(pdev->banks[DPU_SPI_BAR_NUMBER].addr, buf,
				   8);
	} else {
		err = read_register64(buf, lw_offset, pdev);
		if (err < 0) {
			ret = -EFAULT;
			goto out;
		}
	}

	pr_debug("Control interface register read  : 0x%llx\n", *buf);

out:
	return ret;
}

ssize_t dpu_device_write_register(uint64_t *buf, uint32_t off,
				  struct pci_device_fpga *pdev,
				  struct dpu_region *region)
{
	uint32_t lw_offset = off >> 2;
	int err, ret = sizeof(uint64_t);

	if (region->spi_mode_enabled && lw_offset == 0) {
		ret = dpu_spi_write(pdev->banks[DPU_SPI_BAR_NUMBER].addr, buf,
				    8);
	} else {
		err = write_register64(buf, lw_offset, pdev);
		if (err < 0) {
			ret = -ENOMEM;
			goto out;
		}
	}

	pr_debug("Control interface register write : 0x%llx\n", *buf);

out:
	return ret;
}

static ssize_t reset_ila_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	return sprintf(buf, "0\n");
}

static ssize_t reset_ila_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	uint64_t off = DPU_HOST_CONTROLLER_BAR_OFFSET + DPU_ANALYZER_OFFSET +
		       ILA_RESET_OFFSET;
	uint64_t tmp = 0xFFFFFFFFFFFFFFFFULL;

	dpu_device_write_register(&tmp, off, pdev, region);

	return len;
}

static ssize_t activate_ila_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->activate_ila);
}

static ssize_t activate_ila_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	uint64_t tmp;
	int ret;

	ret = kstrtou64(buf, 10, &tmp);
	if (ret)
		return ret;

	if (tmp != 0 && tmp != 1)
		return -EINVAL;

	if (tmp != region->activate_ila) {
		uint64_t off = DPU_HOST_CONTROLLER_BAR_OFFSET +
			       DPU_ANALYZER_OFFSET + ILA_TRIGGER_OFFSET;

		tmp = ((tmp << TRIGGER_ENABLE_SHIFT) |
		       (ISTATE_TRIGGER_SELECTION << TRIGGER_SELECTION_SHIFT) |
		       (ISTATE_BOOT_STATE_VALUE << TRIGGER_VALUE_SHIFT));

		dpu_device_write_register(&tmp, off, pdev, region);

		region->activate_ila = (uint8_t)tmp;
	}

	return len;
}

static ssize_t activate_filtering_ila_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->activate_filtering_ila);
}

static ssize_t activate_filtering_ila_store(struct device *dev,
					    struct device_attribute *attr,
					    const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	uint64_t tmp;
	int ret;

	ret = kstrtou64(buf, 10, &tmp);
	if (ret)
		return ret;

	if (tmp != 0 && tmp != 1)
		return -EINVAL;

	if (tmp != region->activate_filtering_ila) {
		uint64_t off = DPU_HOST_CONTROLLER_BAR_OFFSET +
			       DPU_ANALYZER_OFFSET + ILA_FILTER_OFFSET;

		dpu_device_write_register(&tmp, off, pdev, region);

		region->activate_filtering_ila = (uint8_t)tmp;
	}

	return len;
}

static ssize_t activate_mram_bypass_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->activate_mram_bypass);
}

static ssize_t activate_mram_bypass_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	uint64_t tmp;
	int ret;

	ret = kstrtou64(buf, 10, &tmp);
	if (ret)
		return ret;

	if (tmp != 0 && tmp != 1)
		return -EINVAL;

	if (tmp != region->activate_mram_bypass) {
		uint64_t off = DPU_HOST_CONTROLLER_BAR_OFFSET +
			       DPU_ANALYZER_OFFSET + MRAM_BYPASS_OFFSET;

		dpu_device_write_register(&tmp, off, pdev, region);

		region->activate_mram_bypass = (uint8_t)tmp;
	}

	return len;
}

static ssize_t mram_refresh_emulation_period_show(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->mram_refresh_emulation_period);
}

static ssize_t
mram_refresh_emulation_period_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	uint64_t tmp;
	int ret;

	ret = kstrtou64(buf, 10, &tmp);
	if (ret)
		return ret;

	if (tmp != region->mram_refresh_emulation_period) {
		uint64_t off = DPU_HOST_CONTROLLER_BAR_OFFSET +
			       DPU_ANALYZER_OFFSET + ILA_RESET_OFFSET;

		tmp = 1ULL | ((tmp & 0xFFFFFFFFULL) << 1);

		dpu_device_write_register(&tmp, off, pdev, region);

		region->mram_refresh_emulation_period = (uint32_t)tmp;
	}

	return len;
}

static ssize_t inject_faults_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "0\n");
}

static ssize_t inject_faults_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	uint64_t off = DPU_HOST_CONTROLLER_BAR_OFFSET + DPU_ANALYZER_OFFSET;
	// Iram
	uint64_t addr0 = 0;
	uint64_t mask0 = 0x0000FFFFFFFFFFFFL;
	uint64_t data0 = 0x0000000000000000L;
	uint64_t addr1 = 0;
	uint64_t mask1 = 0x0000FFFFFFFFFFFFL;
	uint64_t data1 = 0x0000000000000000L;
	uint64_t addr2 = 0;
	uint64_t mask2 = 0x0000FFFFFFFFFFFFL;
	uint64_t data2 = 0x0000000000000000L;
	uint64_t addr3 = 0;
	uint64_t mask3 = 0x0000FFFFFFFFFFFFL;
	uint64_t data3 = 0x0000000000000000L;

	dpu_device_write_register(&addr0, off + 0x280, pdev, region);
	dpu_device_write_register(&mask0, off + 0x288, pdev, region);
	dpu_device_write_register(&data0, off + 0x290, pdev, region);
	dpu_device_write_register(&addr1, off + 0x298, pdev, region);
	dpu_device_write_register(&mask1, off + 0x2A0, pdev, region);
	dpu_device_write_register(&data1, off + 0x2A8, pdev, region);
	dpu_device_write_register(&addr2, off + 0x2B0, pdev, region);
	dpu_device_write_register(&mask2, off + 0x2B8, pdev, region);
	dpu_device_write_register(&data2, off + 0x2C0, pdev, region);
	dpu_device_write_register(&addr3, off + 0x2C8, pdev, region);
	dpu_device_write_register(&mask3, off + 0x2D0, pdev, region);
	dpu_device_write_register(&data3, off + 0x2D8, pdev, region);

	// Wram Bank 0
	addr0 = 0x0;
	mask0 = 0x00000000FFFFFFFFL;
	data0 = 0x0000000000000000L;
	addr1 = 0x0;
	mask1 = 0x00000000FFFFFFFFL;
	data1 = 0x0000000000000000L;
	addr2 = 0x0;
	mask2 = 0x00000000FFFFFFFFL;
	data2 = 0x0000000000000000L;
	addr3 = 0x0;
	mask3 = 0x00000000FFFFFFFFL;
	data3 = 0x0000000000000000L;

	dpu_device_write_register(&addr0, off + 0x080, pdev, region);
	dpu_device_write_register(&mask0, off + 0x088, pdev, region);
	dpu_device_write_register(&data0, off + 0x090, pdev, region);
	dpu_device_write_register(&addr1, off + 0x098, pdev, region);
	dpu_device_write_register(&mask1, off + 0x0A0, pdev, region);
	dpu_device_write_register(&data1, off + 0x0A8, pdev, region);
	dpu_device_write_register(&addr2, off + 0x0B0, pdev, region);
	dpu_device_write_register(&mask2, off + 0x0B8, pdev, region);
	dpu_device_write_register(&data2, off + 0x0C0, pdev, region);
	dpu_device_write_register(&addr3, off + 0x0C8, pdev, region);
	dpu_device_write_register(&mask3, off + 0x0D0, pdev, region);
	dpu_device_write_register(&data3, off + 0x0D8, pdev, region);

	// Wram Bank 1
	addr0 = 0x0;
	mask0 = 0x00000000FFFFFFFFL;
	data0 = 0x0000000000000000L;
	addr1 = 0x0;
	mask1 = 0x00000000FFFFFFFFL;
	data1 = 0x0000000000000000L;
	addr2 = 0x0;
	mask2 = 0x00000000FFFFFFFFL;
	data2 = 0x0000000000000000L;
	addr3 = 0x0;
	mask3 = 0x00000000FFFFFFFFL;
	data3 = 0x0000000000000000L;

	dpu_device_write_register(&addr0, off + 0x100, pdev, region);
	dpu_device_write_register(&mask0, off + 0x108, pdev, region);
	dpu_device_write_register(&data0, off + 0x110, pdev, region);
	dpu_device_write_register(&addr1, off + 0x118, pdev, region);
	dpu_device_write_register(&mask1, off + 0x120, pdev, region);
	dpu_device_write_register(&data1, off + 0x128, pdev, region);
	dpu_device_write_register(&addr2, off + 0x130, pdev, region);
	dpu_device_write_register(&mask2, off + 0x138, pdev, region);
	dpu_device_write_register(&data2, off + 0x140, pdev, region);
	dpu_device_write_register(&addr3, off + 0x148, pdev, region);
	dpu_device_write_register(&mask3, off + 0x150, pdev, region);
	dpu_device_write_register(&data3, off + 0x158, pdev, region);

	// Wram Bank 2
	addr0 = 0x0;
	mask0 = 0x00000000FFFFFFFFL;
	data0 = 0x0000000000000000L;
	addr1 = 0x0;
	mask1 = 0x00000000FFFFFFFFL;
	data1 = 0x0000000000000000L;
	addr2 = 0x0;
	mask2 = 0x00000000FFFFFFFFL;
	data2 = 0x0000000000000000L;
	addr3 = 0x0;
	mask3 = 0x00000000FFFFFFFFL;
	data3 = 0x0000000000000000L;

	dpu_device_write_register(&addr0, off + 0x180, pdev, region);
	dpu_device_write_register(&mask0, off + 0x188, pdev, region);
	dpu_device_write_register(&data0, off + 0x190, pdev, region);
	dpu_device_write_register(&addr1, off + 0x198, pdev, region);
	dpu_device_write_register(&mask1, off + 0x1A0, pdev, region);
	dpu_device_write_register(&data1, off + 0x1A8, pdev, region);
	dpu_device_write_register(&addr2, off + 0x1B0, pdev, region);
	dpu_device_write_register(&mask2, off + 0x1B8, pdev, region);
	dpu_device_write_register(&data2, off + 0x1C0, pdev, region);
	dpu_device_write_register(&addr3, off + 0x1C8, pdev, region);
	dpu_device_write_register(&mask3, off + 0x1D0, pdev, region);
	dpu_device_write_register(&data3, off + 0x1D8, pdev, region);

	// Wram Bank 3
	addr0 = 0x0;
	mask0 = 0x00000000FFFFFFFFL;
	data0 = 0x0000000000000000L;
	addr1 = 0x0;
	mask1 = 0x00000000FFFFFFFFL;
	data1 = 0x0000000000000000L;
	addr2 = 0x0;
	mask2 = 0x00000000FFFFFFFFL;
	data2 = 0x0000000000000000L;
	addr3 = 0x0;
	mask3 = 0x00000000FFFFFFFFL;
	data3 = 0x0000000000000000L;

	dpu_device_write_register(&addr0, off + 0x200, pdev, region);
	dpu_device_write_register(&mask0, off + 0x208, pdev, region);
	dpu_device_write_register(&data0, off + 0x210, pdev, region);
	dpu_device_write_register(&addr1, off + 0x218, pdev, region);
	dpu_device_write_register(&mask1, off + 0x220, pdev, region);
	dpu_device_write_register(&data1, off + 0x228, pdev, region);
	dpu_device_write_register(&addr2, off + 0x230, pdev, region);
	dpu_device_write_register(&mask2, off + 0x238, pdev, region);
	dpu_device_write_register(&data2, off + 0x240, pdev, region);
	dpu_device_write_register(&addr3, off + 0x248, pdev, region);
	dpu_device_write_register(&mask3, off + 0x250, pdev, region);
	dpu_device_write_register(&data3, off + 0x258, pdev, region);

	return len;
}

static ssize_t spi_mode_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->spi_mode_enabled);
}

static ssize_t spi_mode_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct pci_device_fpga *pdev = region->pdata->addr_translate->private;
	int ret;
	uint8_t tmp;

	ret = kstrtou8(buf, 10, &tmp);
	if (ret)
		return ret;

	if (tmp && !region->spi_mode_enabled) {
		dpu_spi_reset(pdev->banks[0].addr);
	} else if (!tmp && region->spi_mode_enabled) {
		uint8_t i;

		for (i = 0; i < 9; ++i)
			dpu_spi_write_read_byte(pdev->banks[0].addr, 0);
	}

	region->spi_mode_enabled = tmp;

	return len;
}

#define ILADUMP_SIZE (ILA_FIFO_DEPTH * ILA_OUTPUT_ENTRY_LENGTH)

static ssize_t iladump_show(struct file *filp, char __user *buf, size_t sz,
			    loff_t *loff)
{
	struct pci_device_fpga *pdev = filp->f_inode->i_private;
	uint32_t timeout = 1000000;
	u64 temp = 0;
	bool fifo_empty = false;
	bool fifo_full = false;
	u8 *kbuffer;
	u8 *current_kbuffer;
	uint8_t thread_id;
	uint16_t thread_pc;
	uint8_t thread_cf;
	uint8_t thread_zf;
	uint8_t wram_bank_again;
	uint8_t thread_istate;
	uint16_t thread_rstate;
	uint64_t thread_resx;
	uint64_t thread_instr;
	uint32_t nb_of_entries = 0;

	kbuffer = vmalloc((ILADUMP_SIZE + 1) * sizeof(uint8_t));
	if (kbuffer == NULL)
		return -ENOMEM;

	current_kbuffer = kbuffer;

	while (!fifo_full && ((timeout--) != 0)) {
		read_register64(&temp, (0x40000 + 0x8000 + 0x10) / 4, pdev);
		fifo_full = (temp & 1) != 0;
	}

	if (timeout == 0) {
		vfree(kbuffer);
		return -EFAULT;
	}

	pr_info("reading fifos");
	temp = 0L;

	while (!fifo_empty &&
	       ((current_kbuffer + 79) <= (kbuffer + ILADUMP_SIZE))) {
		read_register64(&temp, (0x40000 + 0x8000 + 0x40) / 4, pdev);
		thread_id = (uint8_t)(temp & 0x1F);
		thread_pc = (uint16_t)((temp >> 8) & 0xFFF);
		thread_cf = (uint8_t)((temp >> 24) & 0x1);
		thread_zf = (uint8_t)((temp >> 25) & 0x1);
		wram_bank_again = (uint8_t)((temp >> 26) & 0x1);
		thread_istate = (uint8_t)((temp >> 32) & 0x3L);
		thread_rstate = (uint16_t)((temp >> 48) & 0xFF);

		read_register64(&thread_resx, (0x40000 + 0x8000 + 0x50) / 4,
				pdev);
		read_register64(&thread_instr, (0x40000 + 0x8000 + 0x60) / 4,
				pdev);

		snprintf(current_kbuffer, 80,
			 "0x%02x, 0x%04x, 0x%01x, 0x%01x, "
			 "0x%01x, 0x%01x, 0x%02x, 0x%16llx, 0x%16llx\n",
			 thread_id, thread_pc, thread_cf, thread_zf,
			 wram_bank_again, thread_istate, thread_rstate,
			 thread_resx, thread_instr);
		current_kbuffer = current_kbuffer + 79;

		read_register64(&temp, (0x40000 + 0x8000 + 0x8) / 4, pdev);
		fifo_empty = (temp & 1) != 0;
		nb_of_entries++;
	}

	if (copy_to_user(buf, kbuffer, ILADUMP_SIZE)) {
		vfree(kbuffer);
		return -EFAULT;
	}

	vfree(kbuffer);

	return nb_of_entries;
}

static const struct file_operations iladump_fops = {
	.owner = THIS_MODULE,
	.read = iladump_show,
};

static DEVICE_ATTR_RW(reset_ila);
static DEVICE_ATTR_RW(activate_ila);
static DEVICE_ATTR_RW(activate_filtering_ila);
static DEVICE_ATTR_RW(activate_mram_bypass);
static DEVICE_ATTR_RW(mram_refresh_emulation_period);
static DEVICE_ATTR_RW(inject_faults);
static DEVICE_ATTR_RW(spi_mode);

static struct attribute *fpga_kc705_attrs[] = {
	&dev_attr_reset_ila.attr,
	&dev_attr_activate_ila.attr,
	&dev_attr_activate_filtering_ila.attr,
	&dev_attr_activate_mram_bypass.attr,
	&dev_attr_mram_refresh_emulation_period.attr,
	&dev_attr_inject_faults.attr,
	&dev_attr_spi_mode.attr,
	NULL,
};

static const struct attribute_group fpga_kc705_attrs_group = {
	.attrs = fpga_kc705_attrs,
};

void fpga_kc705_write_to_rank(struct dpu_region_address_translation *tr,
			      void *base_region_addr, uint8_t channel_id,
			      uint8_t rank_id,
			      struct dpu_transfer_mram *xfer_matrix)
{
	struct pci_device_fpga *pdev = tr->private;
	struct xfer_page *xferp;
	uint64_t rank_size;
	uint64_t len_xfer_remaining, len_xfer_done;
	int ret;
	uint32_t ptr_dpu;
	uint8_t nb_cis, nb_dpus_per_ci;
	uint8_t dpu_id, ci_id;
	int idx;

	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;
	rank_size = nb_cis * nb_dpus_per_ci * tr->interleave->mram_size;

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		uint32_t page;
		uint32_t len_xfer_in_page;
		uint32_t off_in_page;

		xferp = xfer_matrix[idx].ptr;
		if (!xferp)
			continue;

		len_xfer_remaining = xfer_matrix[idx].size;
		len_xfer_done = 0;

		ptr_dpu = dpu_id * tr->interleave->mram_size * 2 +
			  xfer_matrix[idx].mram_number *
				  tr->interleave->mram_size +
			  xfer_matrix[idx].offset_in_mram;

		for (page = 0; page < xferp->nb_pages; ++page) {
			off_in_page = !page ? xferp->off_first_page : 0;

			len_xfer_in_page =
				min((uint32_t)(PAGE_SIZE - off_in_page),
				    (uint32_t)len_xfer_remaining);

			ret = sg_block(
				pdev, PCI_DMA_TODEVICE,
				page_to_virt(xferp->pages[page]) + off_in_page,
				len_xfer_in_page, ptr_dpu + len_xfer_done);
			if (ret) {
				printk(KERN_ERR "Error while transmitting data,"
						" stopping transfer at ci %d "
						"and dpu %d\n",
				       ci_id, dpu_id);
				return;
			}

			len_xfer_remaining -= len_xfer_in_page;
			len_xfer_done += len_xfer_in_page;
		}
	}
}

void fpga_kc705_read_from_rank(struct dpu_region_address_translation *tr,
			       void *base_region_addr, uint8_t channel_id,
			       uint8_t rank_id,
			       struct dpu_transfer_mram *xfer_matrix)
{
	struct pci_device_fpga *pdev = tr->private;
	struct xfer_page *xferp;
	uint64_t rank_size;
	uint64_t len_xfer_remaining, len_xfer_done;
	int ret;
	uint32_t ptr_dpu;
	uint8_t nb_cis, nb_dpus_per_ci;
	uint8_t dpu_id, ci_id;
	int idx;

	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;
	rank_size = nb_cis * nb_dpus_per_ci * tr->interleave->mram_size;

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		uint32_t page;
		uint32_t len_xfer_in_page;
		uint32_t off_in_page;

		xferp = xfer_matrix[idx].ptr;
		if (!xferp)
			continue;

		len_xfer_remaining = xfer_matrix[idx].size;
		len_xfer_done = 0;

		ptr_dpu = dpu_id * tr->interleave->mram_size * 2 +
			  xfer_matrix[idx].mram_number *
				  tr->interleave->mram_size +
			  xfer_matrix[idx].offset_in_mram;

		for (page = 0; page < xferp->nb_pages; ++page) {
			off_in_page = !page ? xferp->off_first_page : 0;

			len_xfer_in_page =
				min((uint32_t)(PAGE_SIZE - off_in_page),
				    (uint32_t)len_xfer_remaining);

			ret = sg_block(
				pdev, PCI_DMA_FROMDEVICE,
				page_to_virt(xferp->pages[page]) + off_in_page,
				len_xfer_in_page, ptr_dpu + len_xfer_done);
			if (ret) {
				printk(KERN_ERR "Error while transmitting data,"
						" stopping transfer at ci %d "
						"and dpu %d\n",
				       ci_id, dpu_id);
				return;
			}

			len_xfer_remaining -= len_xfer_in_page;
			len_xfer_done += len_xfer_in_page;
		}
	}
}

void fpga_kc705_write_to_cis(struct dpu_region_address_translation *tr,
			     void *base_region_addr, uint8_t channel_id,
			     uint8_t rank_id, void *block_data,
			     uint32_t block_size)
{
	struct pci_device_fpga *pdev = tr->private;
	struct dpu_region *region =
		container_of(pdev, struct dpu_region, dpu_fpga_kc705_dev);

	dpu_device_write_register(block_data, DPU_HOST_CONTROLLER_BAR_OFFSET,
				  pdev, region);
}

void fpga_kc705_read_from_cis(struct dpu_region_address_translation *tr,
			      void *base_region_addr, uint8_t channel_id,
			      uint8_t rank_id, void *block_data,
			      uint32_t block_size)
{
	struct pci_device_fpga *pdev = tr->private;
	struct dpu_region *region =
		container_of(pdev, struct dpu_region, dpu_fpga_kc705_dev);

	dpu_device_read_register(block_data, DPU_HOST_CONTROLLER_BAR_OFFSET,
				 pdev, region);
}

int fpga_kc705_init_region(struct dpu_region_address_translation *tr)
{
	struct pci_device_fpga *pdev = tr->private;
	struct dpu_region *region =
		container_of(pdev, struct dpu_region, dpu_fpga_kc705_dev);
	struct device *dev = &pdev->dev->dev;
	int ret;

	region->iladump = debugfs_create_file(
		"iladump", S_IRUGO, region->dpu_debugfs, pdev, &iladump_fops);
	if (region->iladump == 0)
		return -EINVAL;

	ret = sysfs_create_group(&dev->kobj, &fpga_kc705_attrs_group);
	if (ret) {
		debugfs_remove(region->iladump);
		return ret;
	}

	return 0;
}

void fpga_kc705_destroy_region(struct dpu_region_address_translation *tr)
{
	struct pci_device_fpga *pdev = tr->private;
	struct dpu_region *region =
		container_of(pdev, struct dpu_region, dpu_fpga_kc705_dev);
	struct device *dev = &pdev->dev->dev;

	debugfs_remove(region->iladump);
	sysfs_remove_group(&dev->kobj, &fpga_kc705_attrs_group);
}

void fpga_kc705_destroy_rank(struct dpu_region_address_translation *tr,
			     uint8_t channel_id, uint8_t rank_id)
{
	pr_info("%s\n", __func__);
}

int fpga_kc705_init_rank(struct dpu_region_address_translation *tr,
			 uint8_t channel_id, uint8_t rank_id)
{
	pr_info("%s\n", __func__);

	return 0;
}

struct dpu_region_interleaving fpga_kc705_interleave_8dpu = {
	.nb_channels = 1,
	.nb_dimms_per_channel = 1,
	.nb_ranks_per_dimm = 1,
	.nb_ci = 1,
	.nb_real_ci = 1,
	.nb_dpus_per_ci = 8,
	.mram_size = 64 * 1024 * 1024,
	.channel_line_size = 128,
	.rank_line_size = 64,
};

struct dpu_region_interleaving fpga_kc705_interleave_1dpu = {
	.nb_channels = 1,
	.nb_dimms_per_channel = 1,
	.nb_ranks_per_dimm = 1,
	.nb_ci = 1,
	.nb_real_ci = 1,
	.nb_dpus_per_ci = 1,
	.mram_size = 64 * 1024 * 1024,
	.channel_line_size = 128,
	.rank_line_size = 64,
};

struct dpu_region_address_translation fpga_kc705_translate_1dpu = {
	.interleave = &fpga_kc705_interleave_1dpu,
	.backend_id = DPU_BACKEND_FPGA_KC705,
	.capabilities = CAP_SAFE,
	.init_rank = fpga_kc705_init_rank,
	.destroy_rank = fpga_kc705_destroy_rank,
	.init_region = fpga_kc705_init_region,
	.destroy_region = fpga_kc705_destroy_region,
	.write_to_rank = fpga_kc705_write_to_rank,
	.read_from_rank = fpga_kc705_read_from_rank,
	.write_to_cis = fpga_kc705_write_to_cis,
	.read_from_cis = fpga_kc705_read_from_cis,
};

struct dpu_region_address_translation fpga_kc705_translate_8dpu = {
	.interleave = &fpga_kc705_interleave_8dpu,
	.backend_id = DPU_BACKEND_FPGA_KC705,
	.capabilities = CAP_SAFE,
	.init_rank = fpga_kc705_init_rank,
	.destroy_rank = fpga_kc705_destroy_rank,
	.init_region = fpga_kc705_init_region,
	.destroy_region = fpga_kc705_destroy_region,
	.write_to_rank = fpga_kc705_write_to_rank,
	.read_from_rank = fpga_kc705_read_from_rank,
	.write_to_cis = fpga_kc705_write_to_cis,
	.read_from_cis = fpga_kc705_read_from_cis,
};
