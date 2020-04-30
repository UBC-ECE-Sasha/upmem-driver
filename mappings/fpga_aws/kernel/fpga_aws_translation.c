/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/kernel.h>
#include <linux/version.h>
#include <asm/cacheflush.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <asm/io.h>

#include "dpu_region_address_translation.h"
#include "dpu_region.h"
#include "dpu_rank.h"
#include "dpu_utils.h"

#include "libxdma.h"
#include "libxdma_api.h"
#include "xdma_mod.h"

void fpga_aws_write_to_rank(struct dpu_region_address_translation *tr,
			    void *base_region_addr, uint8_t channel_id,
			    uint8_t rank_id,
			    struct dpu_transfer_mram *xfer_matrix)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	struct xdma_dev *xdev = region->dpu_fpga_aws_dev;
	struct xdma_io_cb cb;
	struct xfer_page *xferp;
	struct dpu_transfer_mram *ptr_xfer_matrix = xfer_matrix;
	uint64_t ptr_dpu;
	uint64_t rank_size;
	uint64_t len_xfer_remaining, len_xfer_done;
	int ret;
	int idx;
	uint8_t nb_cis, nb_real_cis, nb_dpus_per_ci;
	uint8_t dpu_id, ci_id;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;
	rank_size = nb_real_cis * nb_dpus_per_ci * tr->interleave->mram_size;

	if (nb_real_cis != nb_cis)
		ptr_xfer_matrix = expand_transfer_matrix(tr, rank, xfer_matrix,
							 nb_real_cis, nb_cis,
							 nb_dpus_per_ci);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_real_cis, nb_dpus_per_ci)
	{
		struct scatterlist *sg;
		uint32_t page;
		uint32_t len_xfer_in_page;
		uint32_t off_in_page;
		uint8_t physical_channel_id = ci_id % 4;

		xferp = ptr_xfer_matrix[idx].ptr;
		if (!xferp)
			continue;

		pr_debug("dpu_region%d!dpu_rank%d: xfer from (%hhu, %hhu)\n",
			 region->id, rank_id, ci_id, dpu_id);

		len_xfer_remaining = ptr_xfer_matrix[idx].size;
		len_xfer_done = 0;

		ptr_dpu = physical_channel_id * 0x400000000ULL +
			  dpu_id * tr->interleave->mram_size * 2 +
			  ptr_xfer_matrix[idx].mram_number *
				  tr->interleave->mram_size +
			  ptr_xfer_matrix[idx].offset_in_mram;

		ret = sg_alloc_table(&cb.sgt, xferp->nb_pages, GFP_KERNEL);
		if (ret) {
			pr_err("Can't allocate sg table\n");
			return;
		}

		sg = cb.sgt.sgl;

		for (page = 0; page < xferp->nb_pages;
		     ++page, sg = sg_next(sg)) {
			off_in_page = !page ? xferp->off_first_page : 0;

			len_xfer_in_page =
				min((uint32_t)(PAGE_SIZE - off_in_page),
				    (uint32_t)len_xfer_remaining);

			sg_set_page(sg, xferp->pages[page], len_xfer_in_page,
				    off_in_page);

			len_xfer_remaining -= len_xfer_in_page;
			len_xfer_done += len_xfer_in_page;
		}

		ret = xdma_xfer_submit(xdev, physical_channel_id, 1, ptr_dpu,
				       &cb.sgt, 0, 10000);

		sg_free_table(&cb.sgt);

		if (ret != ptr_xfer_matrix[idx].size) {
			printk(KERN_ERR "Error while transmitting data,"
					" stopping transfer at ci %d "
					"and dpu %d\n",
			       ci_id, dpu_id);
			return;
		}
	}
}

void fpga_aws_read_from_rank(struct dpu_region_address_translation *tr,
			     void *base_region_addr, uint8_t channel_id,
			     uint8_t rank_id,
			     struct dpu_transfer_mram *xfer_matrix)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	struct xdma_dev *xdev = region->dpu_fpga_aws_dev;
	struct xdma_io_cb cb;
	struct xfer_page *xferp;
	struct dpu_transfer_mram *ptr_xfer_matrix = xfer_matrix;
	uint64_t rank_size;
	uint64_t len_xfer_remaining, len_xfer_done;
	uint64_t ptr_dpu;
	int ret;
	int idx;
	uint8_t nb_cis, nb_real_cis, nb_dpus_per_ci;
	uint8_t dpu_id, ci_id;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;
	rank_size = nb_real_cis * nb_dpus_per_ci * tr->interleave->mram_size;

	if (nb_real_cis != nb_cis)
		ptr_xfer_matrix = expand_transfer_matrix(tr, rank, xfer_matrix,
							 nb_real_cis, nb_cis,
							 nb_dpus_per_ci);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_real_cis, nb_dpus_per_ci)
	{
		struct scatterlist *sg;
		uint32_t page;
		uint32_t len_xfer_in_page;
		uint32_t off_in_page;
		uint8_t physical_channel_id = ci_id % 4;

		xferp = ptr_xfer_matrix[idx].ptr;
		if (!xferp)
			continue;

		pr_debug("dpu_region%d!dpu_rank%d: xfer from (%hhu, %hhu)\n",
			 region->id, rank_id, ci_id, dpu_id);

		len_xfer_remaining = ptr_xfer_matrix[idx].size;
		len_xfer_done = 0;

		ptr_dpu = physical_channel_id * 0x400000000ULL +
			  dpu_id * tr->interleave->mram_size * 2 +
			  ptr_xfer_matrix[idx].mram_number *
				  tr->interleave->mram_size +
			  ptr_xfer_matrix[idx].offset_in_mram;

		ret = sg_alloc_table(&cb.sgt, xferp->nb_pages, GFP_KERNEL);
		if (ret) {
			pr_err("Can't allocate sg table\n");
			return;
		}

		sg = cb.sgt.sgl;

		for (page = 0; page < xferp->nb_pages;
		     ++page, sg = sg_next(sg)) {
			off_in_page = !page ? xferp->off_first_page : 0;

			len_xfer_in_page =
				min((uint32_t)(PAGE_SIZE - off_in_page),
				    (uint32_t)len_xfer_remaining);

			sg_set_page(sg, xferp->pages[page], len_xfer_in_page,
				    off_in_page);

			len_xfer_remaining -= len_xfer_in_page;
			len_xfer_done += len_xfer_in_page;
		}

		ret = xdma_xfer_submit(xdev, physical_channel_id, 0, ptr_dpu,
				       &cb.sgt, 0, 10000);

		sg_free_table(&cb.sgt);

		if (ret != ptr_xfer_matrix[idx].size) {
			printk(KERN_ERR "Error while transmitting data,"
					" stopping transfer at ci %d "
					"and dpu %d\n",
			       ci_id, dpu_id);
			return;
		}
	}
}

void fpga_aws_write_to_cis(struct dpu_region_address_translation *tr,
			   void *base_region_addr, uint8_t channel_id,
			   uint8_t rank_id, void *block_data,
			   uint32_t block_size)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	uint64_t *command;
	void *ptr_block_data = block_data;
	uint8_t nb_cis, nb_real_cis;
	int i;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;

	if (nb_cis != nb_real_cis)
		ptr_block_data = get_real_control_interface_commands(
			tr, rank, block_data, nb_real_cis, nb_cis);

	for (i = 0; i < nb_real_cis; ++i) {
		uint64_t off_in_bar = i * 0x1000 + 0x1000000000ULL;

		command = &((uint64_t *)ptr_block_data)[i];

		pr_debug("dpu_region%d!dpu_rank%d: Writing %llx to %d %llx\n",
			 region->id, rank_id, *command, i, off_in_bar);

		if (*command == 0ULL)
			continue;

		writeq(*command,
		       (volatile uint8_t *)base_region_addr + off_in_bar);
	}
}

void fpga_aws_read_from_cis(struct dpu_region_address_translation *tr,
			    void *base_region_addr, uint8_t channel_id,
			    uint8_t rank_id, void *block_data,
			    uint32_t block_size)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	uint64_t *result;
	void *ptr_block_data = block_data;
	uint8_t nb_cis, nb_real_cis;
	int i;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;

	if (nb_cis != nb_real_cis)
		ptr_block_data = rank->real_control_interface;

	for (i = 0; i < nb_real_cis; ++i) {
		uint64_t result_tmp;
		uint64_t off_in_bar = i * 0x1000 + 0x1000000000ULL;

		result = &((uint64_t *)ptr_block_data)[i];
		if (*result == 0ULL)
			continue;

		result_tmp = readq((volatile uint8_t *)base_region_addr +
				   off_in_bar);

		if (result_tmp == 0ULL)
			continue;

		*result = result_tmp;

		pr_debug("dpu_region%d!dpu_rank%d: Reading %llx from %d %llx\n",
			 region->id, rank_id, *(uint64_t *)result, i,
			 (uint64_t)base_region_addr);
	}

	if (nb_cis != nb_real_cis)
		get_control_interface_results(tr, ptr_block_data, block_data,
					      nb_real_cis, nb_cis);
}

int fpga_aws_mmap_hybrid(struct dpu_region_address_translation *tr,
			 uint8_t rank_id, struct file *filp,
			 struct vm_area_struct *vma)
{
	struct dpu_region *region = tr->private;
	struct xdma_dev *xdev = region->dpu_fpga_aws_dev;
	uint64_t vm_size;
	int ret;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vm_size = vma->vm_end - vma->vm_start;

	if (vm_size < tr->hybrid_mmap_size)
		return -EINVAL;

	vma->vm_flags |= VM_IO;
	vma->vm_pgoff +=
		(pci_resource_start(xdev->pdev, 4) + 0x1000000000ULL) >>
		PAGE_SHIFT;

	ret = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, vm_size,
			      vma->vm_page_prot);
	if (ret) {
		pr_debug("dpu_region%d!dpu_rank%d: remap_pfn_range failed.\n.",
			 region->id, rank_id);
		return ret;
	}

	return 0;
}

int fpga_aws_init_region(struct dpu_region_address_translation *tr)
{
	return 0;
}

void fpga_aws_destroy_region(struct dpu_region_address_translation *tr)
{
}

void fpga_aws_destroy_rank(struct dpu_region_address_translation *tr,
			   uint8_t channel_id, uint8_t rank_id)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	uint8_t nb_cis, nb_real_cis;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;

	if (nb_real_cis != nb_cis) {
		kfree(rank->real_control_interface);
		kfree(rank->real_xfer_matrix);
	}
}

int fpga_aws_init_rank(struct dpu_region_address_translation *tr,
		       uint8_t channel_id, uint8_t rank_id)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	uint8_t nb_cis, nb_real_cis, nb_dpus_per_ci;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	if (nb_real_cis != nb_cis) {
		rank->real_control_interface =
			kzalloc(nb_real_cis * sizeof(uint64_t), GFP_KERNEL);
		if (!rank->real_control_interface)
			return -ENOMEM;

		rank->real_xfer_matrix =
			kzalloc(nb_real_cis * nb_dpus_per_ci *
					sizeof(struct dpu_transfer_mram),
				GFP_KERNEL);
		if (!rank->real_xfer_matrix) {
			kfree(rank->real_control_interface);
			return -ENOMEM;
		}
	}

	return 0;
}

uint8_t fpga_aws_ci_mapping[2] = {
	1, // 0 -> 1
	3 // 1 -> 3
};

struct dpu_region_interleaving fpga_aws_interleave = {
	.nb_channels = 1,
	.nb_dimms_per_channel = 1,
	.nb_ranks_per_dimm = 1,
	.nb_ci = 4,
	.nb_real_ci = 4,
	.nb_dpus_per_ci = 8,
	.mram_size = 64 * 1024 * 1024,
	.channel_line_size = 128,
	.rank_line_size = 64,
	.ci_mapping = fpga_aws_ci_mapping,
};

struct dpu_region_address_translation fpga_aws_translate = {
	.interleave = &fpga_aws_interleave,
	.backend_id = DPU_BACKEND_FPGA_AWS,
	.capabilities = CAP_HYBRID_CONTROL_INTERFACE | CAP_SAFE,
	.hybrid_mmap_size = 4 /* nb_cis */ * 4 * 1024,
	.init_rank = fpga_aws_init_rank,
	.destroy_rank = fpga_aws_destroy_rank,
	.init_region = fpga_aws_init_region,
	.destroy_region = fpga_aws_destroy_region,
	.write_to_rank = fpga_aws_write_to_rank,
	.read_from_rank = fpga_aws_read_from_rank,
	.write_to_cis = fpga_aws_write_to_cis,
	.read_from_cis = fpga_aws_read_from_cis,
	.mmap_hybrid = fpga_aws_mmap_hybrid
};
