/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

#include <linux/sched.h>

#include "dpu_rank.h"
#include "dpu_rank_ioctl.h"
#include "dpu_control_interface.h"
#include "dpu_utils.h"
#include "dpu_mcu_ci_commands.h"
#include "dpu_mcu_ci_protocol.h"
#define CREATE_TRACE_POINTS
#include "dpu_rank_tracepoints.h"

struct class *dpu_rank_class;

static struct page **get_page_array(struct dpu_rank *rank, int dpu_idx)
{
	uint32_t mram_size, nb_page_in_array;

	mram_size = rank->region->pdata->addr_translate->interleave->mram_size;
	nb_page_in_array = (mram_size / PAGE_SIZE);

	return &rank->xfer_dpu_page_array[dpu_idx * nb_page_in_array + dpu_idx];
}

/* Returns pages that must be put and free by calling function,
 * note that in case of success, the caller must release mmap_sem. */
static int pin_pages_for_xfer(struct device *dev, struct dpu_rank *rank,
			      struct dpu_transfer_mram *xfer,
			      unsigned int gup_flags, int dpu_idx)
{
	struct xfer_page *xferp;
	unsigned long nb_pages, nb_pages_expected;
	uint32_t off_page;
	int i;
	uint8_t *ptr_user = xfer->ptr; /* very important to keep this address,
					* since it will get overriden by
					* get_user_pages
					*/

	/* Allocation from userspace may not be aligned to
	 * page size, compute the offset of the base pointer
	 * to the previous page boundary.
	 */
	off_page = ((unsigned long)ptr_user & (PAGE_SIZE - 1));

	nb_pages_expected = ((xfer->size + off_page) / PAGE_SIZE);
	nb_pages_expected += (((xfer->size + off_page) % PAGE_SIZE) ? 1 : 0);

	xferp = kzalloc(sizeof(struct xfer_page), GFP_KERNEL);
	if (!xferp)
		return -ENOMEM;

	xferp->pages = get_page_array(rank, dpu_idx);
	xferp->off_first_page = off_page;
	xferp->nb_pages = nb_pages_expected;

	xfer->ptr = xferp;

	/* No page to pin or flush, bail early */
	if (nb_pages_expected == 0)
		return 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
	/* Note: If needed, PageTransHuge returns true in case of a huge page */
	nb_pages = get_user_pages((unsigned long)ptr_user, xferp->nb_pages,
				  gup_flags, xferp->pages, NULL);
#else
	nb_pages = get_user_pages(current, current->mm, (unsigned long)ptr_user,
				  xferp->nb_pages, gup_flags, 0, xferp->pages,
				  NULL);
#endif
	if (nb_pages <= 0 || nb_pages != nb_pages_expected) {
		dev_err(dev, "cannot pin pages: nb_pages %ld/expected %ld\n",
			nb_pages, nb_pages_expected);
		kfree(xferp);
		return -EFAULT;
	}

	for (i = 0; i < nb_pages; ++i)
		flush_dcache_page(xferp->pages[i]);

	return nb_pages;
}

/* Careful to release mmap_sem ! */
static int pin_pages_for_xfer_matrix(struct device *dev, struct dpu_rank *rank,
				     struct dpu_transfer_mram *xfer_matrix,
				     unsigned int gup_flags)
{
	struct dpu_region_address_translation *tr;
	uint8_t ci_id, dpu_id, nb_cis, nb_dpus_per_ci;
	int idx;
	int ret;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	down_read(&current->mm->mmap_sem);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		struct dpu_transfer_mram *user_xfer_dpu;

		/* Here we work 'in-place' in xfer_matrix by replacing pointers
		 * to userspace buffers in struct dpu_transfer_mram * by newly
		 * allocated struct page ** representing the userspace buffer.
		 */
		user_xfer_dpu = &xfer_matrix[idx];
		if (!user_xfer_dpu->ptr)
			continue;

		ret = pin_pages_for_xfer(dev, rank, user_xfer_dpu, gup_flags,
					 idx);
		if (ret < 0) {
			int i, j;

			for (i = idx - 1; i >= 0; --i) {
				if (xfer_matrix[i].ptr) {
					struct xfer_page *xferp;

					xferp = xfer_matrix[i].ptr;

					for (j = 0; j < xferp->nb_pages; ++j)
						put_page(xferp->pages[j]);

					kfree(xferp);
				}
			}

			up_read(&current->mm->mmap_sem);
			return ret;
		}
	}

	return 0;
}

static int dpu_rank_get_user_xfer_matrix(struct dpu_rank *rank,
					 struct dpu_transfer_mram **xfer_matrix,
					 unsigned long ptr)
{
	struct dpu_region_address_translation *tr;
	uint8_t nb_cis, nb_dpus_per_ci;
	int ret = 0;
	size_t matrix_size;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;
	matrix_size =
		sizeof(struct dpu_transfer_mram) * nb_cis * nb_dpus_per_ci;

	/* Retrieve matrix transfer from userspace */
	*xfer_matrix = kzalloc(matrix_size, GFP_KERNEL);
	if (!*xfer_matrix)
		return -ENOMEM;

	if (copy_from_user(*xfer_matrix, (void *)ptr, matrix_size)) {
		ret = -EFAULT;
		goto free_xfer_matrix;
	}

	return 0;

free_xfer_matrix:
	kfree(*xfer_matrix);

	return ret;
}

static void dpu_rank_xfer_matrix_free(struct dpu_rank *rank,
				      struct dpu_transfer_mram *xfer_matrix)
{
	kfree(xfer_matrix);
}

static int dpu_rank_write_to_rank(struct dpu_rank *rank, unsigned long ptr)
{
	struct device *dev = &rank->dev;
	struct dpu_transfer_mram *xfer_matrix;
	struct dpu_region_address_translation *tr;
	int i, ret = 0;
	uint8_t ci_id, dpu_id, nb_cis, nb_dpus_per_ci;
	int idx;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	ret = dpu_rank_get_user_xfer_matrix(rank, &xfer_matrix, ptr);
	if (ret)
		return ret;

	/* Pin pages of all the buffers in the transfer matrix, and start
	 * the transfer: from here we are committed to release mmap_sem.
	 */
	ret = pin_pages_for_xfer_matrix(dev, rank, xfer_matrix, 0);
	if (ret)
		goto free_matrix;

	/* Launch the transfer */
	tr->write_to_rank(tr, rank->region->base, rank->channel_id,
			  rank->id_in_region, xfer_matrix);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		if (xfer_matrix[idx].ptr) {
			struct xfer_page *xferp;

			xferp = xfer_matrix[idx].ptr;

			for (i = 0; i < xferp->nb_pages; ++i)
				put_page(xferp->pages[i]);

			kfree(xferp);
		}
	}

	up_read(&current->mm->mmap_sem);

free_matrix:
	dpu_rank_xfer_matrix_free(rank, xfer_matrix);

	return ret;
}

static int dpu_rank_read_from_rank(struct dpu_rank *rank, unsigned long ptr)
{
	struct device *dev = &rank->dev;
	struct dpu_transfer_mram *xfer_matrix;
	struct dpu_region_address_translation *tr;
	int i, ret = 0;
	uint8_t ci_id, dpu_id, nb_cis, nb_dpus_per_ci;
	int idx;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	ret = dpu_rank_get_user_xfer_matrix(rank, &xfer_matrix, ptr);
	if (ret)
		return ret;

		/* Pin pages of all the buffers in the transfer matrix, and start
	 * the transfer. Check if the buffer is writable and do not forget
	 * to fault in pages...
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
	ret = pin_pages_for_xfer_matrix(dev, rank, xfer_matrix,
					FOLL_WRITE | FOLL_POPULATE);
#else
	ret = pin_pages_for_xfer_matrix(dev, rank, xfer_matrix, FOLL_WRITE);
#endif
	if (ret)
		goto free_matrix;

	/* Launch the transfer */
	tr->read_from_rank(tr, rank->region->base, rank->channel_id,
			   rank->id_in_region, xfer_matrix);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		if (xfer_matrix[idx].ptr) {
			struct xfer_page *xferp;

			xferp = xfer_matrix[idx].ptr;

			for (i = 0; i < xferp->nb_pages; ++i)
				put_page(xferp->pages[i]);

			kfree(xferp);
		}
	}

	up_read(&current->mm->mmap_sem);

free_matrix:
	dpu_rank_xfer_matrix_free(rank, xfer_matrix);

	return ret;
}

static int dpu_rank_commit_commands(struct dpu_rank *rank, unsigned long ptr)
{
	struct dpu_region_address_translation *tr;
	uint32_t size_command;
	int ret = 0, i;
	uint8_t nb_cis;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	size_command = sizeof(uint64_t) * nb_cis;

	memset(rank->control_interface, 0, size_command);
	if (copy_from_user(rank->control_interface, (uint8_t *)ptr,
			   size_command))
		return -EFAULT;

	for (i = 0; i < nb_cis; ++i)
		trace_upmem_command_write(rank, i, rank->control_interface[i]);

	mutex_lock(&rank->ci_lock);
	tr->write_to_cis(tr, rank->region->base, rank->channel_id,
			 rank->id_in_region, rank->control_interface,
			 size_command);
	mutex_unlock(&rank->ci_lock);

	return ret;
}

static int dpu_rank_update_commands(struct dpu_rank *rank, unsigned long ptr)
{
	struct dpu_region_address_translation *tr;
	uint32_t size_command;
	int i;
	uint8_t nb_cis;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	size_command = sizeof(uint64_t) * nb_cis;

	memset(rank->control_interface, 0, size_command);
	if (copy_from_user(rank->control_interface, (uint8_t *)ptr,
			   size_command))
		return -EFAULT;

	mutex_lock(&rank->ci_lock);
	tr->read_from_cis(tr, rank->region->base, rank->channel_id,
			  rank->id_in_region, rank->control_interface,
			  size_command);
	mutex_unlock(&rank->ci_lock);

	for (i = 0; i < nb_cis; ++i)
		trace_upmem_command_read(rank, i, rank->control_interface[i]);

	if (copy_to_user((uint8_t *)ptr, rank->control_interface, size_command))
		return -EFAULT;

	return 0;
}

static int dpu_rank_free(struct file *filp)
{
	struct dpu_region_address_translation *tr;
	struct dpu_rank *rank = filp->private_data;
	uint8_t rank_mode;

	if (!rank)
		return 0;

	spin_lock(&rank->region->lock);

	rank->owner.usage_count--;
	if (!rank->owner.usage_count) {
		rank->owner.is_owned = 0;
		rank->trace_command_mask = 0;
		rank->init_done = 0;
		filp->private_data = NULL;
		/* Stops all the DPUs of the rank by injecting a fault bkp */
		dpu_control_interface_set_fault_bkp(rank);
		rank_mode = rank->region->pdata->mode;
		if (rank_mode == DPU_REGION_MODE_SAFE ||
		    rank_mode == DPU_REGION_MODE_HYBRID) {
			tr = rank->region->pdata->addr_translate;
			if (tr->destroy_rank)
				tr->destroy_rank(tr, rank->channel_id,
						 rank->id_in_region);
		}
	}

	rank->region->pdata->usage_count--;
	if (!rank->region->pdata->usage_count) {
		rank->region->pdata->mode = DPU_REGION_MODE_UNDEFINED;
		/* Make sure we do not leave the region open whereas all ranks
		 * were freed.
		 */
		rank->region->debug_mode = 0;
	}

	spin_unlock(&rank->region->lock);

	return 0;
}

static int dpu_rank_open(struct inode *inode, struct file *filp)
{
	struct dpu_rank *rank =
		container_of(inode->i_cdev, struct dpu_rank, cdev);
	int ret = 0;

	dev_info(&rank->dev, "opened region_id %u, rank_id %u\n",
		 rank->region->id, rank->id_in_region);

	filp->private_data = rank;

	spin_lock(&rank->region->lock);

	if (rank->owner.is_owned) {
		if (!rank->region->debug_mode) {
			ret = -EBUSY;
			goto unlock_spin;
		}
	} else
		rank->owner.is_owned = 1;

	rank->owner.usage_count++;
	rank->region->pdata->usage_count++;

unlock_spin:
	spin_unlock(&rank->region->lock);

	return ret;
}

static int dpu_rank_release(struct inode *inode, struct file *filp)
{
	struct dpu_rank *rank = filp->private_data;

	if (!rank)
		return 0;

	dev_info(&rank->dev, "closed region_id %u, rank_id %u\n",
		 rank->region->id, rank->id_in_region);

	dpu_rank_free(filp);

	return 0;
}

static int dpu_rank_debug_mode(struct dpu_rank *rank, unsigned long mode)
{
	spin_lock(&rank->region->lock);

	rank->region->debug_mode = mode;

	spin_unlock(&rank->region->lock);

	return 0;
}

static long dpu_rank_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	struct dpu_rank *rank = filp->private_data;
	int ret = -EINVAL;

	if (!rank)
		return 0;

	dev_dbg(&rank->dev, "ioctl region_id %u, rank_id %u\n",
		rank->region->id, rank->id_in_region);

	switch (cmd) {
	case DPU_RANK_IOCTL_WRITE_TO_RANK:
		ret = dpu_rank_write_to_rank(rank, arg);

		break;
	case DPU_RANK_IOCTL_READ_FROM_RANK:
		ret = dpu_rank_read_from_rank(rank, arg);

		break;
	case DPU_RANK_IOCTL_COMMIT_COMMANDS:
		ret = dpu_rank_commit_commands(rank, arg);

		break;
	case DPU_RANK_IOCTL_UPDATE_COMMANDS:
		ret = dpu_rank_update_commands(rank, arg);

		break;
	case DPU_RANK_IOCTL_DEBUG_MODE:
		ret = dpu_rank_debug_mode(rank, arg);

		break;
	default:
		break;
	}

	return ret;
}

/* This operation is backend specific, some will allow the mapping of
 * control interfaces and/or MRAMs.
 */
static int dpu_rank_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct dpu_rank *rank = filp->private_data;
	struct dpu_region_address_translation *tr;
	int ret = 0;

	tr = rank->region->pdata->addr_translate;

	spin_lock(&rank->region->lock);

	switch (rank->region->pdata->mode) {
	case DPU_REGION_MODE_UNDEFINED:
		if ((tr->capabilities & CAP_HYBRID) == 0) {
			ret = -EINVAL;
			goto unlock_spin;
		}

		rank->region->pdata->mode = DPU_REGION_MODE_HYBRID;

		break;
	case DPU_REGION_MODE_SAFE:
	case DPU_REGION_MODE_PERF:
		/* TODO: Can we return a value that is not correct
                         * regarding man mmap ?
                         */
		dev_err(&rank->dev, "device already open"
				    " in perf or safe mode\n");
		ret = -EPERM;
		goto unlock_spin;
	case DPU_REGION_MODE_HYBRID:
		break;
	}

	if (rank->init_done == 0) {
		if (tr->init_rank) {
			ret = tr->init_rank(tr, rank->channel_id,
					    rank->id_in_region);
			if (ret)
				goto unlock_spin;
		}
		rank->init_done = 1;
	}

unlock_spin:
	spin_unlock(&rank->region->lock);

	return ret ? ret : tr->mmap_hybrid(tr, rank->id_in_region, filp, vma);
}

static struct file_operations dpu_rank_fops = { .owner = THIS_MODULE,
						.open = dpu_rank_open,
						.release = dpu_rank_release,
						.unlocked_ioctl =
							dpu_rank_ioctl,
						.mmap = dpu_rank_mmap };

static void dpu_rank_dev_release(struct device *dev)
{
	// TODO lacks attribute into dpu_rank_device to be update here,
	// mainly is_allocated ?
	// WARNING: here it is when the device is removed, not when userspace
	// releases fd.
}

static int dpu_init_ddr(struct dpu_region *region, struct dpu_rank *rank)
{
	struct dpu_region_address_translation *tr =
		region->pdata->addr_translate;
	struct page *page;
	struct dpu_transfer_mram *xfer_matrix;
	struct xfer_page *xferp;
	uint32_t nb_pages_per_mram, mram_size;
	int ret = 0, idx, i;
	uint8_t dpu_id, ci_id;
	uint8_t nb_cis, nb_dpus_per_ci;

	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;
	nb_cis = tr->interleave->nb_ci;
	mram_size = tr->interleave->mram_size;
	nb_pages_per_mram = mram_size / PAGE_SIZE;

	xfer_matrix = kzalloc(nb_dpus_per_ci * nb_cis *
				      sizeof(struct dpu_transfer_mram),
			      GFP_KERNEL);
	if (!xfer_matrix)
		return -ENOMEM;

	/* GFP_ZERO is not necessary actually, but init with zero is cleaner */
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		ret = -ENOMEM;
		goto free_matrix;
	}

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		xferp = kzalloc(sizeof(struct xfer_page), GFP_KERNEL);
		if (!xferp) {
			for (idx--; idx >= 0; --idx) {
				xferp = xfer_matrix[idx].ptr;
				kfree(xferp);
			}
			ret = -ENOMEM;
			goto free_page;
		}

		xferp->pages = get_page_array(rank, idx);
		for (i = 0; i < nb_pages_per_mram; ++i)
			xferp->pages[i] = page;

		xferp->nb_pages = nb_pages_per_mram;

		xfer_matrix[idx].mram_number = 0;
		xfer_matrix[idx].offset_in_mram = 0;
		xfer_matrix[idx].size = mram_size;
		xfer_matrix[idx].ptr = xferp;
	}

	tr->write_to_rank(tr, region->base, rank->channel_id, rank->id,
			  xfer_matrix);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
		xfer_matrix[idx]
			.mram_number = 1;

	tr->write_to_rank(tr, region->base, rank->channel_id, rank->id,
			  xfer_matrix);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		xferp = xfer_matrix[idx].ptr;
		kfree(xferp);
	}

	pr_info("ddr rank init done.\n");

free_page:
	__free_pages(page, 0);
free_matrix:
	kfree(xfer_matrix);

	return ret;
}

static int dpu_rank_create_device(struct device *dev_parent,
				  struct dpu_region *region,
				  struct dpu_rank *rank)
{
	dev_t devt_rank;
	int ret;
	uint32_t mram_size, dpu_size_page_array;
	uint8_t nb_cis, nb_dpus_per_ci;

	cdev_init(&rank->cdev, &dpu_rank_fops);

	devt_rank = MKDEV(MAJOR(region->devt),
			  MINOR(region->devt) + rank->id_in_region);
	rank->cdev.owner = THIS_MODULE;
	rank->devt = devt_rank;

	memset(&rank->dev, 0, sizeof(struct device));
	device_initialize(&rank->dev);

	mutex_init(&rank->ci_lock);

	nb_cis = region->pdata->addr_translate->interleave->nb_ci;
	nb_dpus_per_ci =
		region->pdata->addr_translate->interleave->nb_dpus_per_ci;
	mram_size = region->pdata->addr_translate->interleave->mram_size;
	/* Userspace buffer is likely unaligned and need 1 more page */
	dpu_size_page_array =
		((mram_size / PAGE_SIZE) + 1) * sizeof(struct page *);

	rank->control_interface =
		kzalloc(nb_cis * sizeof(uint64_t), GFP_KERNEL);
	if (!rank->control_interface)
		return -ENOMEM;

	rank->xfer_dpu_page_array =
		vmalloc(nb_cis * nb_dpus_per_ci * dpu_size_page_array);
	if (!rank->xfer_dpu_page_array) {
		ret = -ENOMEM;
		goto err;
	}

	rank->owner.is_owned = 0;
	rank->owner.usage_count = 0;

	rank->region = region;

	rank->kobj_ci = kzalloc(nb_cis * sizeof(struct kobject), GFP_KERNEL);
	if (!rank->kobj_ci) {
		ret = -ENOMEM;
		goto err_vmalloc;
	}

	rank->dev.devt = devt_rank;
	rank->dev.class = dpu_rank_class;
	rank->dev.parent = dev_parent;
	dev_set_drvdata(&rank->dev, rank);
	rank->dev.release = dpu_rank_dev_release;
	dev_set_name(&rank->dev, DPU_RANK_PATH, region->id, rank->id_in_region);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	ret = cdev_device_add(&rank->cdev, &rank->dev);
	if (ret)
		goto err_kobj;
#else
	ret = cdev_add(&rank->cdev, rank->dev.devt, 1);
	if (ret)
		goto err_kobj;

	ret = device_add(&rank->dev);
	if (ret)
		goto free_cdev;
#endif

	ret = dpu_rank_sysfs_create(&rank->dev, rank);
	if (ret) {
		ret = -EINVAL;
		goto free_cdev_dev;
	}

	if (region->must_init_mram) {
		ret = dpu_init_ddr(region, rank);
		if (ret)
			goto free_cdev_dev;
	}

	return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
free_cdev_dev:
	cdev_device_del(&rank->cdev, &rank->dev);
#else
free_cdev_dev:
	device_del(&rank->dev);
free_cdev:
	cdev_del(&rank->cdev);
#endif
err_kobj:
	kfree(rank->kobj_ci);
err_vmalloc:
	vfree(rank->xfer_dpu_page_array);
err:
	kfree(rank->control_interface);

	return ret;
}

int dpu_rank_create_devices(struct device *dev, struct dpu_region *region)
{
	struct dpu_region_address_translation *translate;
	int ret;
	int i;
	uint8_t nb_ranks, nb_dimms, nb_ranks_per_dimm;
	uint8_t nb_ranks_per_channel;
	uint8_t nb_cis;

	translate = region->pdata->addr_translate;
	nb_dimms = translate->interleave->nb_channels *
		   translate->interleave->nb_dimms_per_channel;
	nb_ranks_per_dimm = translate->interleave->nb_ranks_per_dimm;
	nb_ranks = nb_dimms * nb_ranks_per_dimm;
	nb_ranks_per_channel =
		nb_ranks_per_dimm * translate->interleave->nb_dimms_per_channel;
	nb_cis = translate->interleave->nb_ci;

	region->nb_ranks = nb_ranks;

	ret = alloc_chrdev_region(&region->devt, 0, nb_ranks, DPU_RANK_NAME);
	if (ret)
		goto err;

	region->ranks = kzalloc(nb_ranks * sizeof(struct dpu_rank), GFP_KERNEL);
	if (!region->ranks) {
		ret = -ENOMEM;
		goto free_chrdev;
	}

	for (i = 0; i < nb_ranks; ++i) {
		struct dpu_rank *rank = &region->ranks[i];
		struct ec_params_osc p_osc = { .set_fck_mhz =
						       OSC_FREQ_DONT_SET };
		struct ec_response_osc r_osc;
		struct ec_params_dimm_id p_dimm;
		struct ec_response_dimm_id r_dimm;
		char ec_mcu_version[128];

		rank->id = ida_simple_get(&region->rank_ida, 0, 0, GFP_KERNEL);
		rank->id_in_region = i;
		/* Even if the channel_id does not correspond to physical
		 * channel id on which the rank, we don't care, we just need
		 * to remain consistent.
		 */
		rank->channel_id = i % nb_ranks_per_channel;
		rank->trace_command_mask = 0;
		rank->init_done = 0;
		ret = dpu_rank_create_device(dev, region, rank);
		if (ret) {
			i--;
			goto free_ranks;
		}

		if (translate->init_rank) {
			ret = translate->init_rank(translate, rank->channel_id,
						   rank->id_in_region);
			if (ret)
				goto free_ranks;
		}

		memset(rank->mcu_version, 0, sizeof(rank->mcu_version));
		ret = dpu_control_interface_mcu_command(
			rank, EC_CMD_GET_BUILD_INFO, 0, NULL, 0, ec_mcu_version,
			sizeof(ec_mcu_version));
		if (ret == 0) {
			dev_dbg(&rank->dev, "MCU version: %s\n",
				ec_mcu_version);

			strncpy(rank->mcu_version, ec_mcu_version,
				sizeof(rank->mcu_version) - 1);
		} else {
			dev_warn(&rank->dev, "cannot request MCU version\n");
		}

		rank->fck_frequency = 0;
		rank->clock_division_min = 0;
		rank->clock_division_max = 0;
		ret = dpu_control_interface_mcu_command(rank, EC_CMD_OSC_FREQ,
							0, &p_osc,
							sizeof(p_osc), &r_osc,
							sizeof(r_osc));
		if (ret == 0) {
			dev_dbg(&rank->dev,
				"FCK frequency %u MHz (min/max %u/%u MHz)\n",
				r_osc.fck_mhz, r_osc.fck_min_mhz,
				r_osc.fck_max_mhz);
			dev_dbg(&rank->dev,
				"Divider /%u = %u Mhz -> /%u = %u Mhz\n",
				r_osc.div_max, r_osc.fck_mhz / r_osc.div_max,
				r_osc.div_min, r_osc.fck_mhz / r_osc.div_min);

			rank->fck_frequency = r_osc.fck_mhz;
			rank->clock_division_min = r_osc.div_min;
			rank->clock_division_max = r_osc.div_max;
		} else {
			dev_warn(
				&rank->dev,
				"cannot request FCK frequency / Divider from MCU\n");
		}

		p_dimm.id_index = DIMM_ID_DEV_NAME;
		strncpy(p_dimm.id_string, dev_name(&rank->dev),
			sizeof(p_dimm.id_string) - 1);
		p_dimm.id_string[sizeof(p_dimm.id_string) - 1] = '\0';
		ret = dpu_control_interface_mcu_command(rank,
							EC_CMD_DIMM_SET_ID, 0,
							&p_dimm, sizeof(p_dimm),
							NULL, 0);
		if (ret < 0) {
			dev_warn(&rank->dev,
				 "cannot inform MCU about rank name\n");
		}

		memset(rank->part_number, 0, sizeof(rank->part_number));
		memset(rank->serial_number, 0, sizeof(rank->serial_number));
		ret = dpu_control_interface_mcu_command(rank, EC_CMD_DIMM_ID, 0,
							NULL, 0, &r_dimm,
							sizeof(r_dimm));
		if (ret == 0) {
			dev_dbg(&rank->dev,
				"Module part number: %20s  S/N:  %8s\n",
				r_dimm.part_number, r_dimm.serial_number);
			dev_dbg(&rank->dev,
				"Device name: %32s Sticker name %16s\n",
				r_dimm.dev_name, r_dimm.pretty_name);

			strncpy(rank->part_number, r_dimm.part_number,
				sizeof(rank->part_number) - 1);
			strncpy(rank->serial_number, r_dimm.serial_number,
				sizeof(rank->serial_number) - 1);
		} else {
			dev_warn(
				&rank->dev,
				"cannot request part number / serial number from MCU\n");
		}

		rank->init_done = 1;
	}

	return 0;

free_ranks:
	for (; i >= 0; --i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		cdev_device_del(&region->ranks[i].cdev, &region->ranks[i].dev);
#else
		device_del(&region->ranks[i].dev);
		cdev_del(&region->ranks[i].cdev);
#endif
		put_device(&region->ranks[i].dev);
		ida_simple_remove(&region->rank_ida, region->ranks[i].id);
	}
	kfree(region->ranks);
free_chrdev:
	unregister_chrdev_region(region->devt, nb_ranks);
err:
	return ret;
}

void dpu_rank_release_devices(struct dpu_region *region)
{
	struct dpu_region_address_translation *translate;
	uint8_t nb_ranks, nb_dimms, nb_ranks_per_dimm, nb_ci;
	int i, j;

	pr_info("dpu_rank: releasing rank\n");

	translate = region->pdata->addr_translate;
	nb_dimms = translate->interleave->nb_channels *
		   translate->interleave->nb_dimms_per_channel;
	nb_ranks_per_dimm = translate->interleave->nb_ranks_per_dimm;
	nb_ranks = nb_dimms * nb_ranks_per_dimm;
	nb_ci = translate->interleave->nb_ci;

	for (i = 0; i < nb_ranks; ++i) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		cdev_device_del(&region->ranks[i].cdev, &region->ranks[i].dev);
#else
		device_del(&region->ranks[i].dev);
		cdev_del(&region->ranks[i].cdev);
#endif
		for (j = 0; j < nb_ci; ++j)
			kobject_put(&region->ranks[i].kobj_ci[j]);
		kfree(region->ranks[i].kobj_ci);
		vfree(region->ranks[i].xfer_dpu_page_array);
		kfree(region->ranks[i].control_interface);
		put_device(&region->ranks[i].dev);
		ida_simple_remove(&region->rank_ida, region->ranks[i].id);
	}

	kfree(region->ranks);
	unregister_chrdev_region(region->devt, nb_ranks);
}
