/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
#include <linux/pfn_t.h>
#include <linux/version.h>

/* Fpga kc705 driver */
#include "dpu_device.h"
#include "dpu_dma_op.h"
/* Fpga aws driver */
#include "libxdma_api.h"
#include "libxdma.h"

#include "dpu_region.h"
#include "dpu_rank.h"
#include "dpu_acpi.h"
#include "dpu_control_interface.h"

static uint32_t static_config_acpi = 0;

static DEFINE_IDA(dpu_region_ida);

struct dpu_region_pdev {
	struct list_head list;
	struct platform_device *pdev;
};
static LIST_HEAD(region_pdev);

int dpu_region_mem_add(u64 addr, u64 size, int index)
{
	struct platform_device *pdev;
	struct dpu_region_pdev *reg;
	struct resource res = DEFINE_RES_MEM(addr, size);

	pr_info("MEM DPU region%d: %016llx->%016llx %lld GB\n", index, addr,
		addr + size, size / SZ_1G);
	pdev = platform_device_register_simple("dpu_region_mem", index, &res,
					       1);
	if (IS_ERR(pdev)) {
		pr_warn("Cannot register region%d (%016llx->%016llx)\n", index,
			addr, addr + size);
		return 0;
	}
	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(reg)) {
		platform_device_unregister(pdev);
		return 0;
	}
	reg->pdev = pdev;
	list_add(&reg->list, &region_pdev);
	return 1;
}

void dpu_region_mem_exit(void)
{
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &region_pdev) {
		struct dpu_region_pdev *reg =
			list_entry(pos, struct dpu_region_pdev, list);
		/* remove from the list BEFORE the 'devm' structure is freed */
		list_del(pos);
		platform_device_unregister(reg->pdev);
		kfree(reg);
	}
}

#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) ||                          \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static struct class *dpu_region_mem_class;

#ifdef __x86_64__
static int mdd_dax_pud_huge_fault(struct vm_fault *vmf, void *vaddr)
{
	struct file *filp = vmf->vma->vm_file;
	struct dpu_region *region = filp->private_data;
	phys_addr_t paddr;
	unsigned long pud_addr = (unsigned long)vaddr & PUD_MASK;
	unsigned long pgoff;
	pfn_t pfn;

	pgoff = linear_page_index(vmf->vma, pud_addr);
	paddr = ((phys_addr_t)__pa(region->base) + pgoff * PAGE_SIZE) &
		PUD_MASK;
	pfn = phys_to_pfn_t(paddr, PFN_DEV | PFN_MAP);

#if LINUX_VERSION_CODE == KERNEL_VERSION(4, 15, 18) ||                         \
	LINUX_VERSION_CODE > KERNEL_VERSION(4, 19, 37)
	return vmf_insert_pfn_pud(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
#else
	return vmf_insert_pfn_pud(vmf->vma, (unsigned long)vaddr, vmf->pud, pfn,
				  vmf->flags & FAULT_FLAG_WRITE);
#endif
}
#endif

static int mdd_dax_pmd_huge_fault(struct vm_fault *vmf, void *vaddr)
{
	struct file *filp = vmf->vma->vm_file;
	struct dpu_region *region = filp->private_data;
	phys_addr_t paddr;
	unsigned long pmd_addr = (unsigned long)vaddr & PMD_MASK;
	unsigned long pgoff;
	pfn_t pfn;

	pgoff = linear_page_index(vmf->vma, pmd_addr);
	paddr = ((phys_addr_t)__pa(region->base) + pgoff * PAGE_SIZE) &
		PMD_MASK;
	pfn = phys_to_pfn_t(paddr, PFN_DEV | PFN_MAP);

	pr_info("Mapping pages of size %lx at @v=%llx to @p=%llx\n", PMD_SIZE,
		(uint64_t)vaddr, paddr);

#if LINUX_VERSION_CODE == KERNEL_VERSION(4, 15, 18) ||                         \
	LINUX_VERSION_CODE > KERNEL_VERSION(4, 19, 37)
	return vmf_insert_pfn_pmd(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
#else
	return vmf_insert_pfn_pmd(vmf->vma, (unsigned long)vaddr, vmf->pmd, pfn,
				  vmf->flags & FAULT_FLAG_WRITE);
#endif
}

static int mdd_dax_pte_huge_fault(struct vm_fault *vmf, void *vaddr)
{
	struct file *filp = vmf->vma->vm_file;
	struct dpu_region *region = filp->private_data;
	phys_addr_t paddr;
	unsigned long pte_addr = (unsigned long)vaddr & PAGE_MASK;
	unsigned long pgoff;
	pfn_t pfn;

	pgoff = linear_page_index(vmf->vma, pte_addr);
	paddr = ((phys_addr_t)__pa(region->base) + pgoff * PAGE_SIZE) &
		PAGE_MASK;
	pfn = phys_to_pfn_t(paddr, PFN_DEV | PFN_MAP);

	pr_info("Mapping pages of size %lx at @v=%llx to @p=%llx\n", PAGE_SIZE,
		(uint64_t)vaddr, paddr);

#if LINUX_VERSION_CODE == KERNEL_VERSION(4, 15, 18) ||                         \
	LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
	return vm_insert_mixed(vmf->vma, (unsigned long)vaddr, pfn);
#else
	return vmf_insert_mixed(vmf->vma, (unsigned long)vaddr, pfn);
#endif
}

static int mdd_dax_huge_fault(struct vm_fault *vmf,
			      enum page_entry_size pe_size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	void *vaddr = (void *)vmf->address;
#else
	void *vaddr = vmf->virtual_address;
#endif

	pr_info("%s: %s (%#lx - %#lx) size = %d\n", current->comm,
		(vmf->flags & FAULT_FLAG_WRITE) ? "write" : "read",
		vmf->vma->vm_start, vmf->vma->vm_end, pe_size);

	switch (pe_size) {
	case PE_SIZE_PTE:
		return mdd_dax_pte_huge_fault(vmf, vaddr);
	case PE_SIZE_PMD:
		return mdd_dax_pmd_huge_fault(vmf, vaddr);
	case PE_SIZE_PUD:
#ifdef __x86_64__
		return mdd_dax_pud_huge_fault(vmf, vaddr);
#elif defined __powerpc64__
		return VM_FAULT_FALLBACK;
#endif
	}

	return VM_FAULT_SIGBUS;
}

static int mdd_dax_fault(
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
	struct vm_area_struct *vma,
#endif
	struct vm_fault *vmf)
{
	return mdd_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct mdd_dax_vm_ops = {
	.huge_fault = mdd_dax_huge_fault,
	.fault = mdd_dax_fault,
};

static int mdd_dax_open(struct inode *inode, struct file *filp)
{
	struct dpu_region *region =
		container_of(inode->i_cdev, struct dpu_region, cdev_dax);

	filp->private_data = region;
	inode->i_flags = S_DAX;

	return 0;
}

static int mdd_dax_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct dpu_region *region = filp->private_data;
	struct dpu_region_address_translation *tr;
	int ret = 0;

	tr = region->pdata->addr_translate;

	spin_lock(&region->lock);

	switch (region->pdata->mode) {
	case DPU_REGION_MODE_UNDEFINED:
		if ((tr->capabilities & CAP_PERF) == 0) {
			ret = -EINVAL;
			goto unlock_spin;
		}

		region->pdata->mode = DPU_REGION_MODE_PERF;

		if (tr->init_region) {
			ret = tr->init_region(tr);
			if (ret)
				goto unlock_spin;
		}

		break;
	case DPU_REGION_MODE_HYBRID:
	case DPU_REGION_MODE_SAFE:
		/* TODO: Can we return a value that is not correct
			 * regarding man mmap ?
			 */
		pr_err("device is in safe mode, can't open"
		       " it in perf mode.\n");
		ret = -EPERM;
		goto unlock_spin;
	case DPU_REGION_MODE_PERF:
		break;
	}

	vma->vm_ops = &mdd_dax_vm_ops;
	/* Caller must set VM_MIXEDMAP on vma if it wants to call this
	 * function [vm_insert_page] from other places, for example from page-fault handler
	 */
	vma->vm_flags |= VM_HUGEPAGE | VM_MIXEDMAP;
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
	vma->vm_flags2 |= VM_PFN_MKWRITE | VM_HUGE_FAULT;
#endif

unlock_spin:
	spin_unlock(&region->lock);

	return ret;
}

/* Always aligned on 1G page */
static unsigned long mdd_dax_get_unmapped_area(struct file *filp,
					       unsigned long addr,
					       unsigned long len,
					       unsigned long pgoff,
					       unsigned long flags)
{
	unsigned long addr_align = 0;

	pr_info("%s: Looking for region of size %lu", __func__, len);

	addr_align = current->mm->get_unmapped_area(filp, addr, len + SZ_1G,
						    pgoff, flags);
	if (!IS_ERR_VALUE(addr_align)) {
		/* If the address is already aligned on 1G */
		if (!(addr_align & (SZ_1G - 1)))
			return addr_align;
		return (addr_align + SZ_1G) & ~(SZ_1G - 1);
	}

	pr_err("%s: Failed to align mmap region on 1G, perf will be degraded\n",
	       __func__);

	return current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
}

static const struct file_operations mdd_dax_fops = {
	.owner = THIS_MODULE,
	.open = mdd_dax_open,
	.mmap = mdd_dax_mmap,
	.get_unmapped_area = mdd_dax_get_unmapped_area,
};

static ssize_t size_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%llu\n", region->size);
}

static DEVICE_ATTR_RO(size);

static struct attribute *dpu_region_mem_attrs[] = {
	&dev_attr_size.attr,
	NULL,
};

static struct attribute_group dpu_region_mem_attrs_group = {
	.attrs = dpu_region_mem_attrs,
};

const struct attribute_group *dpu_region_mem_attrs_groups[] = {
	&dpu_region_mem_attrs_group, NULL
};

static void dpu_region_percpu_exit(void *data)
{
	struct percpu_ref *ref = data;
	struct dpu_dax_device *dpu_dax_dev =
		container_of(ref, struct dpu_dax_device, ref);

	wait_for_completion(&dpu_dax_dev->cmp);
	percpu_ref_exit(ref);
}

static void dpu_region_percpu_release(struct percpu_ref *ref)
{
	struct dpu_dax_device *dpu_dax_dev =
		container_of(ref, struct dpu_dax_device, ref);

	complete(&dpu_dax_dev->cmp);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 37)
static void dpu_region_percpu_kill(struct percpu_ref *ref)
#else
static void dpu_region_percpu_kill(void *data)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 37)
	struct percpu_ref *ref = data;
#endif

	percpu_ref_kill(ref);
}

static int dpu_region_init_dax(struct platform_device *pdev,
			       struct dpu_region *region)
{
	struct resource *res;
	struct dpu_dax_device *dpu_dax_dev = &region->dpu_dax_dev;
	struct device *dev = &pdev->dev;
	void *addr;
	int ret;

	res = devm_request_mem_region(dev, pdev->resource->start,
				      resource_size(pdev->resource),
				      "dpu_region");
	if (!res) {
		dev_err(&pdev->dev, "unable to request DPU memory region.\n");
		ret = -EBUSY;
		goto error;
	}

	init_completion(&dpu_dax_dev->cmp);

	memset(&dpu_dax_dev->ref, 0, sizeof(struct percpu_ref));
	ret = percpu_ref_init(&dpu_dax_dev->ref, dpu_region_percpu_release, 0,
			      GFP_KERNEL);
	if (ret)
		goto error;

	ret = devm_add_action_or_reset(dev, dpu_region_percpu_exit,
				       &dpu_dax_dev->ref);
	if (ret)
		goto ref_error;

	/* vmem_altmap is used only if memmap must be stored in our
         * memory region, which we clearly do NOT want.
         * The function returns __va(pdev->resource->start) (which is kernel
         * logical address :)
         */
	dpu_dax_dev->pgmap.ref = &dpu_dax_dev->ref;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 37)
	dpu_dax_dev->pgmap.kill = dpu_region_percpu_kill;
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) ||                          \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	memcpy(&dpu_dax_dev->pgmap.res, pdev->resource,
	       sizeof(struct resource));
	dpu_dax_dev->pgmap.type = MEMORY_DEVICE_FS_DAX;
	addr = devm_memremap_pages(dev, &dpu_dax_dev->pgmap);
#else
	dpu_dax_dev->pgmap.res = pdev->resource;
	addr = devm_memremap_pages(dev, pdev->resource, &dpu_dax_dev->ref,
				   NULL);
#endif
	if (IS_ERR(addr)) {
		dev_err(&pdev->dev, "%s: devm_memremap_pages failed\n",
			__func__);
		ret = PTR_ERR(addr);
		goto ref_error;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 37)
	ret = devm_add_action_or_reset(dev, dpu_region_percpu_kill,
				       &dpu_dax_dev->ref);
	if (ret)
		goto ref_error;
#endif

	ret = alloc_chrdev_region(&region->devt_dax, 0, 1, "dax");
	if (ret)
		goto ref_error;

	cdev_init(&region->cdev_dax, &mdd_dax_fops);
	region->cdev_dax.owner = THIS_MODULE;

	memset(&region->dev_dax, 0, sizeof(struct device));
	device_initialize(&region->dev_dax);

	region->dev_dax.devt = region->devt_dax;
	region->dev_dax.class = dpu_region_mem_class;
	region->dev_dax.parent = &pdev->dev;
	dev_set_drvdata(&region->dev_dax, region);
	region->id = ida_simple_get(&dpu_region_ida, 0, 0, GFP_KERNEL);
	dev_set_name(&region->dev_dax, "dax%d.%d", region->id, region->id);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	ret = cdev_device_add(&region->cdev_dax, &region->dev_dax);
	if (ret)
		goto cdev_error;
#else
	ret = cdev_add(&region->cdev_dax, region->dev_dax.devt, 1);
	if (ret)
		goto cdev_error;

	ret = device_add(&region->dev_dax);
	if (ret)
		goto free_cdev;
#endif

	region->size = resource_size(pdev->resource);
	region->base = addr;

	dev_dbg(&pdev->dev, "dax_region and device allocated\n");

	return 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
free_cdev:
	cdev_del(&region->cdev_dax);
#endif
cdev_error:
	unregister_chrdev_region(region->devt_dax, 1);
ref_error:
	percpu_ref_kill(&dpu_dax_dev->ref);
error:
	pr_err("%s failed\n", __func__);
	return ret;
}

static int dpu_region_mem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct dpu_region *region;
	struct dpu_region_data *pdata;
	int ret;

	dev_dbg(dev, "device probed\n");

	region = devm_kzalloc(dev, sizeof(struct dpu_region), GFP_KERNEL);
	if (!region) {
		ret = -ENOMEM;
		goto err;
	}

	/* 1/ Init dax device */
	ret = dpu_region_init_dax(pdev, region);
	if (ret)
		goto err;

	/* 2/ Init dpu_ranks devices associated to that dax device */
	pdata = dpu_region_get_data(
		dpu_get_translation_config(dev, static_config_acpi), 0);
	if (!pdata) {
		dev_dbg(dev, "dpu_region device does not contain"
			     " necessary information.\n");
		ret = -EINVAL;
		goto free_dev_dax;
	}

	dev_set_drvdata(&pdev->dev, region);
	region->pdata = pdata;
	region->pdata->addr_translate->private = region;

	/* For now, we use platform devices, and I didn't find a way to add
	 * sysfs attributes to *each device* handled by this driver while
	 * avoiding userspace race conditions as described here:
	 * http://kroah.com/log/blog/2013/06/26/how-to-create-a-sysfs-file-correctly/
	 * Setting group attributes for device_driver is not okay.
	 * Creating a new bus would mitigate this issue.
	 */
	ret = dpu_region_sysfs_create(dev);
	if (ret) {
		dev_dbg(dev, "dpu_region device sysfs can't be created\n");
		ret = -ENODEV;
		goto free_region_data;
	}

	spin_lock_init(&region->lock);
	ida_init(&region->rank_ida);

	ret = dpu_rank_create_devices(dev, region);
	if (ret) {
		dev_dbg(dev, "cannot create dpu rank devices\n");
		goto remove_sysfs;
	}

	ret = dpu_control_interface_get_chip_id(&region->ranks[0]);
	if (ret) {
		dev_err(dev, "cannot get region chip id\n");
		goto destroy_rank_devices;
	}

	dev_dbg(dev, "device loaded.\n");

	return 0;

destroy_rank_devices:
	dpu_rank_release_devices(region);
remove_sysfs:
	ida_destroy(&region->rank_ida);
	dpu_region_sysfs_remove(dev);
free_region_data:
	dpu_region_free_data(region->pdata);
free_dev_dax:
	cdev_del(&region->cdev_dax);
	device_del(&region->dev_dax);
	unregister_chrdev_region(region->devt_dax, 1);
err:
	return ret;
}

static int dpu_region_mem_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct dpu_region *region;

	dev_dbg(dev, "removing dpu region device (and their ranks)\n");

	region = dev_get_drvdata(dev);
	if (!region)
		return -EINVAL;

	cdev_del(&region->cdev_dax);
	device_del(&region->dev_dax);
	unregister_chrdev_region(region->devt_dax, 1);

	/* Release dpu_rank devices */
	dpu_rank_release_devices(region);
	dpu_region_sysfs_remove(dev);
	ida_destroy(&region->rank_ida);
	dpu_region_free_data(region->pdata);

	return 0;
}

/* Memory driver */
static struct platform_driver dpu_region_mem_driver = {
	.driver = { .name = DPU_REGION_NAME "_mem", .owner = THIS_MODULE },
	.probe = dpu_region_mem_probe,
	.remove = dpu_region_mem_remove,
};
#endif /* LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) || LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0) */

/* Default value for bank_map structure */
static const struct bank_map init_banks[] = {
	/* Pack all the register banks of BAR0 within a mixed bunch. */
	{ "ctrl", 0, 0x0, (1 << 19), NULL, 0 },
};

static int dpu_region_init_fpga_kc705(struct pci_dev *pci_dev,
				      struct dpu_region *region)
{
	struct pci_device_fpga *pdev;
	char *debugfs_region;
	int err, i;

	/* Init pci device */

	// Set Bus Master Enable (BME) bit
	pci_set_master(pci_dev);

	err = pci_enable_device(pci_dev);
	if (err) {
		pr_err("[PCI-FPGA] Could not enable PCI device: %d\n", err);
		goto error;
	}

	// Set DMA Mask
	err = pci_set_dma_mask(pci_dev, 0x7FFFFFFFFFFFFFFF);
	if (err) {
		pr_err("[PCI-FPGA] Init: DMA not supported\n");
		goto error;
	}
	pci_set_consistent_dma_mask(pci_dev, 0x7FFFFFFFFFFFFFFF);

	err = pci_request_regions(pci_dev, "dpu_region");
	if (err) {
		pr_err("[PCI-FPGA] Failed to setup DPU-FPGA device: %d\n", err);
		goto error_request_regions_failed;
	}

	/* Add the new device to the list of pci device fpga */
	pdev = &region->dpu_fpga_kc705_dev;

	for (i = 0; i < BANKS_NUM; ++i)
		memcpy(&pdev->banks[i], &init_banks[i],
		       sizeof(struct bank_map));

	region->id = ida_simple_get(&dpu_region_ida, 0, 0, GFP_KERNEL);

	dev_set_drvdata(&pci_dev->dev, region);
	pdev->dev = pci_dev;
	pdev->id_dev = region->id;

	pdev->banks[0].phys = pci_resource_start(pci_dev, 0);
	pdev->banks[0].addr = ioremap(pdev->banks[0].phys, pdev->banks[0].len);

	region->activate_ila = 0;
	region->activate_filtering_ila = 0;
	region->activate_mram_bypass = 0;
	region->mram_refresh_emulation_period = 0;
	region->spi_mode_enabled = 0;

	err = xpdma_init(pdev);
	if (err)
		goto error_pdev;

	debugfs_region = devm_kzalloc(&pdev->dev->dev, 32, GFP_KERNEL);
	if (!debugfs_region) {
		err = -ENOMEM;
		goto error_xpdma;
	}

	sprintf(debugfs_region, "dpu_region%d", region->id);

	region->dpu_debugfs = debugfs_create_dir(debugfs_region, NULL);
	if (region->dpu_debugfs == 0) {
		err = -1;
		goto error_debugfs_region;
	} else if (region->dpu_debugfs == (struct dentry *)-ENODEV)
		dev_info(&pci_dev->dev, "debugfs is not present\n");

	return 0;

error_debugfs_region:
	kfree(debugfs_region);
error_xpdma:
	xpdma_exit(pdev);
error_pdev:
	pci_release_regions(pci_dev);
error_request_regions_failed:
	pci_disable_device(pci_dev);
error:
	return err;
}

static int dpu_region_fpga_kc705_probe(struct pci_dev *pci_dev,
				       const struct pci_device_id *id)
{
	struct dpu_region_address_translation *translate;
	struct device *dev = &pci_dev->dev;
	struct dpu_region *region;
	struct dpu_region_data *pdata;
	uint64_t chip_id;
	int ret;

	dev_dbg(dev, "fpga kc705 device probed\n");

	region = kzalloc(sizeof(struct dpu_region), GFP_KERNEL);
	if (!region) {
		ret = -ENOMEM;
		goto err;
	}

	/* 1/ Init fpga kc705 device */
	ret = dpu_region_init_fpga_kc705(pci_dev, region);
	if (ret)
		goto free_region;

	/* 2/ Init dpu_ranks devices associated to that dax device with
	 * default chip id being 6 (fpga8) */
	pdata = dpu_region_get_data(DPU_BACKEND_FPGA_KC705, 6);
	if (!pdata) {
		dev_err(dev, "dpu_region device does not contain"
			     " necessary information.\n");
		ret = -EINVAL;
		goto free_fpga;
	}

	dev_set_drvdata(dev, region);
	region->pdata = pdata;
	/* Finally, store pdev also into dpu_region_address_translation
	 * private member since the current implementation requires this
	 * structure to work, kind of a hack yes.
	 */
	region->pdata->addr_translate->private = &region->dpu_fpga_kc705_dev;
	translate = region->pdata->addr_translate;

	if (translate->init_region) {
		ret = translate->init_region(translate);
		if (ret)
			goto free_region_data;
	}

	spin_lock_init(&region->lock);
	ida_init(&region->rank_ida);

	ret = dpu_rank_create_devices(dev, region);
	if (ret) {
		dev_err(dev, "cannot create dpu rank devices\n");
		goto destroy_region;
	}

	ret = dpu_control_interface_get_chip_id(&region->ranks[0]);
	if (ret) {
		dev_err(dev, "cannot get region chip id\n");
		goto destroy_rank_devices;
	}

	/* This is a hack for this backend only: we need the chip id to know
	 * the number of DPUs implemented to initialize dpu_rank correctly, but
	 * we need dpu_rank initialized to be able to retrieve the chip id...
	 * Make it simple and nasty, the default chip id is the one with 8 dpus
	 * so that initialization of dpu_rank will be ok for config with 1 dpu.
	 */
	chip_id = region->pdata->dpu_chip_id;
	dpu_region_free_data(region->pdata);

	pdata = dpu_region_get_data(DPU_BACKEND_FPGA_KC705, chip_id);
	if (!pdata) {
		dev_err(dev, "dpu_region device does not contain"
			     " necessary information.\n");
		ret = -EINVAL;
		goto free_fpga;
	}

	region->pdata = pdata;
	region->pdata->addr_translate->private = &region->dpu_fpga_kc705_dev;

	/* For now, we use platform devices, and I didn't find a way to add
	 * sysfs attributes to *each device* handled by this driver while
	 * avoiding userspace race conditions as described here:
	 * http://kroah.com/log/blog/2013/06/26/how-to-create-a-sysfs-file-correctly/
	 * Setting group attributes for device_driver is not okay.
	 * Creating a new bus would mitigate this issue.
	 *
	 * Note: we must wait for chip id (and then rank device creation)
	 * before exposing region sysfs (since chip id is in there).
	 */
	ret = dpu_region_sysfs_create(dev);
	if (ret) {
		dev_err(dev, "dpu_region device sysfs can't be created\n");
		ret = -ENODEV;
		goto destroy_rank_devices;
	}

	dev_dbg(dev, "device loaded.\n");

	return 0;

destroy_rank_devices:
	dpu_rank_release_devices(region);
destroy_region:
	ida_destroy(&region->rank_ida);
	if (translate->destroy_region)
		translate->destroy_region(translate);
free_region_data:
	dpu_region_free_data(region->pdata);
free_fpga:
	pci_release_regions(pci_dev);
	pci_disable_device(pci_dev);
	debugfs_remove(region->dpu_debugfs);
	xpdma_exit(&region->dpu_fpga_kc705_dev);
free_region:
	kfree(region);
err:
	return ret;
}

static void dpu_region_fpga_kc705_remove(struct pci_dev *pci_dev)
{
	struct dpu_region_address_translation *translate;
	struct device *dev = &pci_dev->dev;
	struct dpu_region *region;

	dev_dbg(dev, "removing dpu region device (and their ranks)\n");

	pci_release_regions(pci_dev);
	pci_disable_device(pci_dev);

	region = dev_get_drvdata(dev);
	if (!region)
		return;

	iounmap(region->dpu_fpga_kc705_dev.banks[0].addr);

	xpdma_exit(region->pdata->addr_translate->private);

	translate = region->pdata->addr_translate;

	if (translate->destroy_region)
		translate->destroy_region(translate);

	debugfs_remove_recursive(region->dpu_debugfs);

	/* Release dpu_rank devices */
	dpu_rank_release_devices(region);
	dpu_region_sysfs_remove(dev);
	ida_destroy(&region->rank_ida);
	dpu_region_free_data(region->pdata);
	kfree(region);
}

/* FPGA kc705 driver */
#define VENDOR_ID 0x10EE /* Xilinx Vendor ID */
#define DEVICE_ID 0x7024

static struct pci_device_id dpu_region_fpga_kc705_ids[] = {
	{
		PCI_DEVICE(VENDOR_ID, DEVICE_ID),
	},
	{
		0,
	}
};

MODULE_DEVICE_TABLE(pci, dpu_region_fpga_kc705_ids);

static struct pci_driver dpu_region_fpga_kc705_driver = {
	.name = DPU_REGION_NAME "_fpga_kc705",
	.id_table = dpu_region_fpga_kc705_ids,
	.probe = dpu_region_fpga_kc705_probe,
	.remove = dpu_region_fpga_kc705_remove,
};

static int dpu_region_init_fpga_aws(struct pci_dev *pci_dev,
				    kernel_ulong_t mem_bar_index,
				    struct dpu_region *region)
{
	struct xdma_dev *xdev;
	char *xdev_name;
	int user_max, c2h_channel_max, h2c_channel_max;
	int err;

	/* Init pci device */
	user_max = MAX_USER_IRQ;
	h2c_channel_max = XDMA_CHANNEL_NUM_MAX;
	c2h_channel_max = XDMA_CHANNEL_NUM_MAX;

	xdev_name = devm_kzalloc(&pci_dev->dev, 32, GFP_KERNEL);
	if (!xdev_name)
		return -ENOMEM;

	region->id = ida_simple_get(&dpu_region_ida, 0, 0, GFP_KERNEL);
	sprintf(xdev_name, "dpu_region_xdev%d", region->id);

	xdev = xdma_device_open(xdev_name, pci_dev, &user_max, &h2c_channel_max,
				&c2h_channel_max);
	if (!xdev) {
		err = -EINVAL;
		goto error;
	}

	if ((user_max > MAX_USER_IRQ) ||
	    (h2c_channel_max > XDMA_CHANNEL_NUM_MAX) ||
	    (c2h_channel_max > XDMA_CHANNEL_NUM_MAX)) {
		err = -EINVAL;
		goto error;
	}

	if (!h2c_channel_max && !c2h_channel_max)
		pr_warn("NO engine found!\n");

	if (user_max) {
		u32 mask = (1 << (user_max + 1)) - 1;

		err = xdma_user_isr_enable(xdev, mask);
		if (err)
			goto error;
	}

	region->base = xdev->bar[mem_bar_index];
	region->dpu_fpga_aws_dev = xdev;

	return 0;
error:
	kfree(xdev_name);
	ida_simple_remove(&dpu_region_ida, region->id);

	return err;
}

static int dpu_region_fpga_aws_probe(struct pci_dev *pci_dev,
				     const struct pci_device_id *id)
{
	struct dpu_region_address_translation *translate;
	struct device *dev = &pci_dev->dev;
	struct dpu_region *region;
	struct dpu_region_data *pdata;
	int ret;

	dev_dbg(dev, "fpga aws device probed\n");

	region = kzalloc(sizeof(struct dpu_region), GFP_KERNEL);
	if (!region) {
		ret = -ENOMEM;
		goto err;
	}

	/* 1/ Init fpga aws device */
	ret = dpu_region_init_fpga_aws(pci_dev, id->driver_data, region);
	if (ret)
		goto free_region;

	/* 2/ Init dpu_ranks devices associated to that dax device with
	 * default chip id being 6 (fpga8) */
	pdata = dpu_region_get_data(DPU_BACKEND_FPGA_AWS, 6);
	if (!pdata) {
		dev_err(dev, "dpu_region device does not contain"
			     " necessary information.\n");
		ret = -EINVAL;
		goto free_fpga;
	}

	dev_set_drvdata(dev, region);
	region->pdata = pdata;
	region->pdata->addr_translate->private = region;
	translate = region->pdata->addr_translate;

	if (translate->init_region) {
		ret = translate->init_region(translate);
		if (ret)
			goto free_region_data;
	}

	spin_lock_init(&region->lock);
	ida_init(&region->rank_ida);

	region->must_init_mram = 1;

	ret = dpu_rank_create_devices(dev, region);
	if (ret) {
		dev_err(dev, "cannot create dpu rank devices\n");
		goto destroy_region;
	}

	ret = dpu_control_interface_get_chip_id(&region->ranks[0]);
	if (ret) {
		dev_err(dev, "cannot get region chip id\n");
		goto destroy_rank_devices;
	}

	/* Note: we must wait for chip id (and then rank device creation)
	 * before exposing region sysfs (since chip id is in there).
	 */
	ret = dpu_region_sysfs_create(dev);
	if (ret) {
		dev_err(dev, "dpu_region device sysfs can't be created\n");
		ret = -ENODEV;
		goto destroy_rank_devices;
	}

	dev_dbg(dev, "device loaded.\n");

	return 0;

destroy_rank_devices:
	dpu_rank_release_devices(region);
destroy_region:
	ida_destroy(&region->rank_ida);
	if (translate->destroy_region)
		translate->destroy_region(translate);
free_region_data:
	dpu_region_free_data(region->pdata);
free_fpga:
	xdma_device_close(pci_dev, region->dpu_fpga_aws_dev);
free_region:
	kfree(region);
err:
	return ret;
}

static void dpu_region_fpga_aws_remove(struct pci_dev *pci_dev)
{
	struct dpu_region_address_translation *translate;
	struct device *dev = &pci_dev->dev;
	struct dpu_region *region;

	dev_dbg(dev, "removing dpu region device (and their ranks)\n");

	region = dev_get_drvdata(dev);
	if (!region)
		return;

	xdma_device_close(pci_dev, region->dpu_fpga_aws_dev);

	translate = region->pdata->addr_translate;
	if (translate->destroy_region)
		translate->destroy_region(translate);

	/* Release dpu_rank devices */
	dpu_rank_release_devices(region);
	dpu_region_sysfs_remove(dev);
	ida_destroy(&region->rank_ida);
	dpu_region_free_data(region->pdata);
	kfree(region);
}

/* FPGA AWS driver */
#define CL_DRAM_DMA_VENDOR_ID 0x1D0F
#define CL_DRAM_DMA_DEVICE_ID 0xF001
#define AWS_DPU_VENDOR_ID 0x1D0F
#define AWS_DPU_DEVICE_ID 0xF010
#define BITTWARE_VENDOR_ID 0x12BA
#define BITTWARE_FPGA_PCIE3_DEVICE_ID 0x0054

#define BAR_NUMBER(x) .driver_data = (kernel_ulong_t)(x)
static struct pci_device_id dpu_region_fpga_aws_ids[] = {
	{ PCI_DEVICE(CL_DRAM_DMA_VENDOR_ID, CL_DRAM_DMA_DEVICE_ID),
	  BAR_NUMBER(4) },
	{ PCI_DEVICE(AWS_DPU_VENDOR_ID, AWS_DPU_DEVICE_ID), BAR_NUMBER(4) },
	{ PCI_DEVICE(BITTWARE_VENDOR_ID, BITTWARE_FPGA_PCIE3_DEVICE_ID),
	  BAR_NUMBER(2) },
	{
		0,
	}
};

MODULE_DEVICE_TABLE(pci, dpu_region_fpga_aws_ids);

static struct pci_driver dpu_region_fpga_aws_driver = {
	.name = DPU_REGION_NAME "_fpga_aws",
	.id_table = dpu_region_fpga_aws_ids,
	.probe = dpu_region_fpga_aws_probe,
	.remove = dpu_region_fpga_aws_remove,
};

static int __init dpu_region_init(void)
{
	int ret;

	dpu_rank_class = class_create(THIS_MODULE, DPU_RANK_NAME);
	if (IS_ERR(dpu_rank_class)) {
		ret = PTR_ERR(dpu_rank_class);
		return ret;
	}

	dpu_rank_class->dev_groups = dpu_rank_attrs_groups;

#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) ||                          \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	dpu_region_mem_class =
		class_create(THIS_MODULE, DPU_REGION_NAME "_mem");
	if (IS_ERR(dpu_region_mem_class)) {
		ret = PTR_ERR(dpu_region_mem_class);
		return ret;
	}

	dpu_region_mem_class->dev_groups = dpu_region_mem_attrs_groups;

	pr_debug("dpu: initializing memory driver\n");
	ret = platform_driver_register(&dpu_region_mem_driver);
	if (ret) {
		class_destroy(dpu_region_mem_class);
		class_destroy(dpu_rank_class);
		return ret;
	}

	pr_debug("dpu: creating memory devices if available\n");
	ret = dpu_region_srat_probe();
	if (ret)
		ret = dpu_region_dev_probe();
	if (ret)
		pr_info("dpu: memory devices unavailable\n");
#endif

	pr_debug("dpu: initializing fpga kc705 driver\n");
	ret = pci_register_driver(&dpu_region_fpga_kc705_driver);
	if (ret)
		goto kc705_error;

	pr_debug("dpu: initializing fpga aws driver\n");
	ret = pci_register_driver(&dpu_region_fpga_aws_driver);
	if (ret)
		goto aws_error;

	return 0;

aws_error:
	pci_unregister_driver(&dpu_region_fpga_kc705_driver);
kc705_error:
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) ||                          \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	platform_driver_unregister(&dpu_region_mem_driver);
	class_destroy(dpu_region_mem_class);
	dpu_region_mem_exit();
#endif
	class_destroy(dpu_rank_class);

	return ret;
}

static void __exit dpu_region_exit(void)
{
	pr_info("dpu_region: unloading driver\n");

	pci_unregister_driver(&dpu_region_fpga_aws_driver);
	pci_unregister_driver(&dpu_region_fpga_kc705_driver);
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) ||                          \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	dpu_region_mem_exit();
	platform_driver_unregister(&dpu_region_mem_driver);
	class_destroy(dpu_region_mem_class);
#endif
	class_destroy(dpu_rank_class);
	ida_destroy(&dpu_region_ida);
}

module_init(dpu_region_init);
module_exit(dpu_region_exit);

module_param(static_config_acpi, uint, 0);
MODULE_PARM_DESC(static_config_acpi, "0: xeon_sp (default)");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexandre Ghiti - UPMEM");
MODULE_VERSION("1.0");
