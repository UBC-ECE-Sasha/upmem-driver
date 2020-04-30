/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/irqflags.h>
#include <linux/slab.h>

#include "dpu_region_address_translation.h"
#include "dpu_utils.h"

#define NB_ELEM_MATRIX 8
#define NB_WRQ_FIFO_ENTRIES 1024 // ??
#define WRQ_FIFO_ENTRY_SIZE 64 // TODO check that, cache line is 128B (?!)

#define for_each_dpu_in_rank(idx, ci, dpu, nb_cis, nb_dpus_per_ci)             \
	for (dpu = 0, idx = 0; dpu < nb_dpus_per_ci; ++dpu)                    \
		for (ci = 0; ci < nb_cis; ++ci, ++idx)

void byte_interleave(uint64_t *input, uint64_t *output)
{
	int i, j;

	for (i = 0; i < NB_ELEM_MATRIX; ++i)
		for (j = 0; j < sizeof(uint64_t); ++j)
			((uint8_t *)&output[i])[j] = ((uint8_t *)&input[j])[i];
}

/* Write NB_WRQ_FIFO_ENTRIES of 0 right after the CI */
// TODO check with Fabrice that it is not a problem to write 0 right
// after a command: will the first command be correctly sampled ?
void flush_mc_fifo(void *base_ci_address)
{
	uint64_t *next_ci_address = (uint64_t *)base_ci_address;
	int i, j;

	for (i = 0; i < NB_WRQ_FIFO_ENTRIES; ++i) {
		for (j = 0; j < WRQ_FIFO_ENTRY_SIZE / sizeof(uint64_t); ++j)
			next_ci_address[j] = (uint64_t)0ULL;

		mb();
		clflush(next_ci_address);
		mb();

		next_ci_address += 8;
	}
}

void flush_mc_fifo_read(void *base_ci_address)
{
	uint64_t *next_ci_address = (uint64_t *)base_ci_address;
	volatile uint64_t tmp;
	int i, j;

	for (i = 0; i < NB_WRQ_FIFO_ENTRIES; ++i) {
		for (j = 0; j < WRQ_FIFO_ENTRY_SIZE / sizeof(uint64_t); ++j)
			tmp = (uint64_t)next_ci_address[j];

		mb();

		next_ci_address += 8;
	}
}

void xeon_sp_write_to_cis(struct dpu_region_address_translation *tr,
			  void *base_region_addr, uint8_t channel_id,
			  uint8_t rank_id, void *block_data,
			  uint32_t block_size)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	uint64_t output[NB_ELEM_MATRIX];
	uint64_t *ci_address;
	void *ptr_block_data = block_data;
	uint8_t nb_cis, nb_real_cis;
	unsigned long flags;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;

	if (nb_cis != nb_real_cis)
		ptr_block_data = get_real_control_interface_commands(
			tr, rank, block_data, nb_real_cis, nb_cis);

	/* 0/ Find out CI address */
	// To discover address translation, base_region_addr will point to
	// whatever address
	ci_address = (uint64_t *)((uint8_t *)base_region_addr + 0x20000);

	//pr_info("command: %16llx\n", ((uint64_t *)ptr_block_data)[2]);

	/* 1/ Byte interleave the command */
	byte_interleave(ptr_block_data, output);

	/* Assume that disabling interrupts will prevent inopportune cache flushes */
	local_irq_save(flags);

	/* 2/ Write the command */
	__raw_writeq(output[0], ci_address + 0);
	__raw_writeq(output[1], ci_address + 1);
	__raw_writeq(output[2], ci_address + 2);
	__raw_writeq(output[3], ci_address + 3);
	__raw_writeq(output[4], ci_address + 4);
	__raw_writeq(output[5], ci_address + 5);
	__raw_writeq(output[6], ci_address + 6);

	mb();

	__raw_writeq(output[7], ci_address + 7);

	mb();
	clflush(ci_address);
	mb();

	local_irq_restore(flags);

	/* 3/ Flush the MC fifo */
	//flush_mc_fifo(base_region_addr);
}

void xeon_sp_read_from_cis(struct dpu_region_address_translation *tr,
			   void *base_region_addr, uint8_t channel_id,
			   uint8_t rank_id, void *block_data,
			   uint32_t block_size)
{
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	uint64_t input[NB_ELEM_MATRIX];
	uint64_t *ci_address;
	void *ptr_block_data = block_data;
	int i;
	uint8_t nb_cis, nb_real_cis;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;

	if (nb_cis != nb_real_cis)
		ptr_block_data = rank->real_control_interface;

	/* 0/ Find out CI address */
	// To discover address translation, base_region_addr will point to
	// whatever address
	ci_address = (uint64_t *)((uint8_t *)base_region_addr + 0x20000 +
				  32 * 1024); // + 0x80 * (count % 16);

	/* 1/ Read the result */
	// Write back only DIRTY cache lines and invalidates all.
	for (i = 0; i < 4; ++i) {
		mb();
		clflush(ci_address);
		mb();

		((volatile uint64_t *)input)[0] = __raw_readq(ci_address + 0);
		((volatile uint64_t *)input)[1] = __raw_readq(ci_address + 1);
		((volatile uint64_t *)input)[2] = __raw_readq(ci_address + 2);
		((volatile uint64_t *)input)[3] = __raw_readq(ci_address + 3);
		((volatile uint64_t *)input)[4] = __raw_readq(ci_address + 4);
		((volatile uint64_t *)input)[5] = __raw_readq(ci_address + 5);
		((volatile uint64_t *)input)[6] = __raw_readq(ci_address + 6);
		((volatile uint64_t *)input)[7] = __raw_readq(ci_address + 7);

		mb();

		/* 2/ Byte de-interleave the result */
		byte_interleave(input, ptr_block_data);

		//pr_info("result:  %16llx\n", ((uint64_t *)ptr_block_data)[2]);
	}

	if (nb_cis != nb_real_cis)
		get_control_interface_results(tr, ptr_block_data, block_data,
					      nb_real_cis, nb_cis);
}

#define BANK_START(dpu_id)                                                     \
	(0x40000 * ((dpu_id) % 4) + ((dpu_id >= 4) ? 0x40 : 0))
// For each 64bit word, you must jump 16 * 64bit (2 cache lines)
#define BANK_OFFSET_NEXT_DATA(i) (i * 16)
#define BANK_CHUNK_SIZE 0x20000
#define BANK_NEXT_CHUNK_OFFSET 0x100000

#define XFER_BLOCK_SIZE 8

static u32 apply_address_translation_on_mram_offset(u32 byte_offset)
{
	/* We have observed that, within the 26 address bits of the MRAM address, we need to apply an address translation:
	 *
	 * virtual[13: 0] = physical[13: 0]
	 * virtual[20:14] = physical[21:15]
	 * virtual[   21] = physical[   14]
	 * virtual[25:22] = physical[25:22]
	 *
	 * This function computes the "virtual" mram address based on the given "physical" mram address.
	 */

	u32 mask_21_to_15 = ((1 << (21 - 15 + 1)) - 1) << 15;
	u32 mask_21_to_14 = ((1 << (21 - 14 + 1)) - 1) << 14;
	u32 bits_21_to_15 = (byte_offset & mask_21_to_15) >> 15;
	u32 bit_14 = (byte_offset >> 14) & 1;
	u32 unchanged_bits = byte_offset & ~mask_21_to_14;

	return unchanged_bits | (bits_21_to_15 << 14) | (bit_14 << 21);
}

void xeon_sp_write_to_rank(struct dpu_region_address_translation *tr,
			   void *base_region_addr, uint8_t channel_id,
			   uint8_t rank_id,
			   struct dpu_transfer_mram *xfer_matrix)
{
	uint8_t idx, ci_id, dpu_id, nb_cis, nb_real_cis, nb_dpus_per_ci;
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	struct dpu_transfer_mram *ptr_xfer_matrix = xfer_matrix;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	if (nb_real_cis != nb_cis)
		ptr_xfer_matrix = expand_transfer_matrix(tr, rank, xfer_matrix,
							 nb_real_cis, nb_cis,
							 nb_dpus_per_ci);

	/* Works only for transfers of same size and same offset on the
	 * same line
	 */
	for (dpu_id = 0, idx = 0; dpu_id < nb_dpus_per_ci;
	     ++dpu_id, idx += nb_dpus_per_ci) {
		uint8_t *ptr_dest =
			(uint8_t *)base_region_addr + BANK_START(dpu_id);
		uint32_t size_transfer = 0;
		uint32_t offset_in_mram = 0;
		uint64_t cache_line[8], cache_line_interleave[8];
		uint32_t page[8];
		uint32_t off_in_page[8];
		uint32_t len_xfer_in_page[8];
		uint32_t len_xfer_done_in_page[8];
		struct xfer_page *xferp;
		struct page *cur_page[8];
		uint64_t len_xfer_done, len_xfer_remaining;

		for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
			if (ptr_xfer_matrix[idx + ci_id].ptr) {
				size_transfer =
					ptr_xfer_matrix[idx + ci_id].size;
				offset_in_mram = ptr_xfer_matrix[idx + ci_id]
							 .offset_in_mram;
				break;
			}
		}

		if (!size_transfer)
			continue;

		for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
			xferp = ptr_xfer_matrix[idx + ci_id].ptr;
			if (!xferp)
				continue;

			page[ci_id] = 0;
			cur_page[ci_id] = xferp->pages[0];
			len_xfer_in_page[ci_id] =
				min((uint32_t)PAGE_SIZE - xferp->off_first_page,
				    (uint32_t)size_transfer);
			off_in_page[ci_id] = xferp->off_first_page;
			len_xfer_done_in_page[ci_id] = 0;
		}

		/* Split transfer into 8B blocks */
		for (len_xfer_done = 0, len_xfer_remaining = size_transfer;
		     len_xfer_done < size_transfer;
		     len_xfer_done += XFER_BLOCK_SIZE) {
			uint32_t mram_64_bit_word_offset =
				apply_address_translation_on_mram_offset(
					len_xfer_done + offset_in_mram) /
				8;
			uint64_t next_data = BANK_OFFSET_NEXT_DATA(
				mram_64_bit_word_offset * sizeof(uint64_t));
			uint64_t offset = (next_data % BANK_CHUNK_SIZE) +
					  (next_data / BANK_CHUNK_SIZE) *
						  BANK_NEXT_CHUNK_OFFSET;

			for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
				if (xfer_matrix[idx + ci_id].ptr)
					cache_line[ci_id] = *(
						uint64_t
							*)((uint8_t *)page_to_virt(
								   cur_page[ci_id]) +
							   off_in_page[ci_id] +
							   len_xfer_done_in_page
								   [ci_id]);
			}

			byte_interleave(cache_line, cache_line_interleave);

			__raw_writeq(cache_line_interleave[0],
				     ptr_dest + offset + 0 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[1],
				     ptr_dest + offset + 1 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[2],
				     ptr_dest + offset + 2 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[3],
				     ptr_dest + offset + 3 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[4],
				     ptr_dest + offset + 4 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[5],
				     ptr_dest + offset + 5 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[6],
				     ptr_dest + offset + 6 * sizeof(uint64_t));
			__raw_writeq(cache_line_interleave[7],
				     ptr_dest + offset + 7 * sizeof(uint64_t));

			len_xfer_remaining -= XFER_BLOCK_SIZE;

			/* Check if we should switch to next page */
			for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
				xferp = ptr_xfer_matrix[idx + ci_id].ptr;
				if (!xferp)
					continue;

				len_xfer_done_in_page[ci_id] += XFER_BLOCK_SIZE;

				if ((page[ci_id] < xferp->nb_pages - 1) &&
				    (len_xfer_done_in_page[ci_id] >=
				     len_xfer_in_page[ci_id])) {
					page[ci_id]++;
					cur_page[ci_id] =
						xferp->pages[page[ci_id]];
					len_xfer_in_page[ci_id] = min(
						(uint32_t)PAGE_SIZE,
						(uint32_t)len_xfer_remaining);
					off_in_page[ci_id] = 0;
					len_xfer_done_in_page[ci_id] = 0;
				}
			}
		}

		mb();

		for (len_xfer_done = 0; len_xfer_done < size_transfer;
		     len_xfer_done += XFER_BLOCK_SIZE) {
			uint32_t mram_64_bit_word_offset =
				apply_address_translation_on_mram_offset(
					len_xfer_done + offset_in_mram) /
				8;
			uint64_t next_data = BANK_OFFSET_NEXT_DATA(
				mram_64_bit_word_offset * sizeof(uint64_t));
			uint64_t offset = (next_data % BANK_CHUNK_SIZE) +
					  (next_data / BANK_CHUNK_SIZE) *
						  BANK_NEXT_CHUNK_OFFSET;

			clflushopt(ptr_dest + offset);
		}

		mb();
	}

	flush_mc_fifo((uint8_t *)base_region_addr + 0x20000);
}

void xeon_sp_read_from_rank(struct dpu_region_address_translation *tr,
			    void *base_region_addr, uint8_t channel_id,
			    uint8_t rank_id,
			    struct dpu_transfer_mram *xfer_matrix)
{
	uint8_t idx, ci_id, dpu_id, nb_cis, nb_real_cis, nb_dpus_per_ci;
	struct dpu_region *region = tr->private;
	struct dpu_rank *rank = &region->ranks[rank_id];
	struct dpu_transfer_mram *ptr_xfer_matrix = xfer_matrix;

	nb_cis = tr->interleave->nb_ci;
	nb_real_cis = tr->interleave->nb_real_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	if (nb_real_cis != nb_cis)
		ptr_xfer_matrix = expand_transfer_matrix(tr, rank, xfer_matrix,
							 nb_real_cis, nb_cis,
							 nb_dpus_per_ci);

	/* Works only for transfers of same size and same offset on the
	 * same line
	 */
	for (dpu_id = 0, idx = 0; dpu_id < nb_dpus_per_ci;
	     ++dpu_id, idx += nb_dpus_per_ci) {
		uint8_t *ptr_dest =
			(uint8_t *)base_region_addr + BANK_START(dpu_id);
		uint32_t size_transfer = 0;
		uint32_t offset_in_mram = 0;
		uint64_t cache_line[8], cache_line_interleave[8];
		uint32_t page[8];
		uint32_t off_in_page[8];
		uint32_t len_xfer_in_page[8];
		uint32_t len_xfer_done_in_page[8];
		struct xfer_page *xferp;
		struct page *cur_page[8];
		uint64_t len_xfer_done, len_xfer_remaining;

		for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
			if (ptr_xfer_matrix[idx + ci_id].ptr) {
				size_transfer =
					ptr_xfer_matrix[idx + ci_id].size;
				offset_in_mram = ptr_xfer_matrix[idx + ci_id]
							 .offset_in_mram;
				break;
			}
		}

		if (!size_transfer)
			continue;

		for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
			xferp = ptr_xfer_matrix[idx + ci_id].ptr;
			if (!xferp)
				continue;

			page[ci_id] = 0;
			cur_page[ci_id] = xferp->pages[0];
			len_xfer_in_page[ci_id] =
				min((uint32_t)PAGE_SIZE - xferp->off_first_page,
				    (uint32_t)size_transfer);
			off_in_page[ci_id] = xferp->off_first_page;
			len_xfer_done_in_page[ci_id] = 0;
		}

		mb();

		for (len_xfer_done = 0; len_xfer_done < size_transfer;
		     len_xfer_done += XFER_BLOCK_SIZE) {
			uint32_t mram_64_bit_word_offset =
				apply_address_translation_on_mram_offset(
					len_xfer_done + offset_in_mram) /
				8;
			uint64_t next_data = BANK_OFFSET_NEXT_DATA(
				mram_64_bit_word_offset * sizeof(uint64_t));
			uint64_t offset = (next_data % BANK_CHUNK_SIZE) +
					  (next_data / BANK_CHUNK_SIZE) *
						  BANK_NEXT_CHUNK_OFFSET;
			clflushopt(ptr_dest + offset);
		}

		mb();

		/* Split transfer into 8B blocks */
		for (len_xfer_done = 0, len_xfer_remaining = size_transfer;
		     len_xfer_done < size_transfer;
		     len_xfer_done += XFER_BLOCK_SIZE) {
			uint32_t mram_64_bit_word_offset =
				apply_address_translation_on_mram_offset(
					len_xfer_done + offset_in_mram) /
				8;
			uint64_t next_data = BANK_OFFSET_NEXT_DATA(
				mram_64_bit_word_offset * sizeof(uint64_t));
			uint64_t offset = (next_data % BANK_CHUNK_SIZE) +
					  (next_data / BANK_CHUNK_SIZE) *
						  BANK_NEXT_CHUNK_OFFSET;

			cache_line[0] = __raw_readq(ptr_dest + offset +
						    0 * sizeof(uint64_t));
			cache_line[1] = __raw_readq(ptr_dest + offset +
						    1 * sizeof(uint64_t));
			cache_line[2] = __raw_readq(ptr_dest + offset +
						    2 * sizeof(uint64_t));
			cache_line[3] = __raw_readq(ptr_dest + offset +
						    3 * sizeof(uint64_t));
			cache_line[4] = __raw_readq(ptr_dest + offset +
						    4 * sizeof(uint64_t));
			cache_line[5] = __raw_readq(ptr_dest + offset +
						    5 * sizeof(uint64_t));
			cache_line[6] = __raw_readq(ptr_dest + offset +
						    6 * sizeof(uint64_t));
			cache_line[7] = __raw_readq(ptr_dest + offset +
						    7 * sizeof(uint64_t));

			byte_interleave(cache_line, cache_line_interleave);

			for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
				if (xfer_matrix[idx + ci_id].ptr)
					*(uint64_t *)((uint8_t *)page_to_virt(
							      cur_page[ci_id]) +
						      off_in_page[ci_id] +
						      len_xfer_done_in_page
							      [ci_id]) =
						cache_line_interleave[ci_id];
			}

			len_xfer_remaining -= XFER_BLOCK_SIZE;

			/* Check if we should switch to next page */
			for (ci_id = 0; ci_id < nb_real_cis; ++ci_id) {
				xferp = ptr_xfer_matrix[idx + ci_id].ptr;
				if (!xferp)
					continue;

				len_xfer_done_in_page[ci_id] += XFER_BLOCK_SIZE;

				if ((page[ci_id] < xferp->nb_pages - 1) &&
				    (len_xfer_done_in_page[ci_id] >=
				     len_xfer_in_page[ci_id])) {
					page[ci_id]++;
					cur_page[ci_id] =
						xferp->pages[page[ci_id]];
					len_xfer_in_page[ci_id] = min(
						(uint32_t)PAGE_SIZE,
						(uint32_t)len_xfer_remaining);
					off_in_page[ci_id] = 0;
					len_xfer_done_in_page[ci_id] = 0;
				}
			}
		}
	}
}

int xeon_sp_init_rank(struct dpu_region_address_translation *tr,
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

void xeon_sp_destroy_rank(struct dpu_region_address_translation *tr,
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

uint8_t xeon_sp_ci_mapping[4] = { 0, 1, 2, 3 };

struct dpu_region_interleaving xeon_sp_interleave = {
	.nb_channels = 1,
	.nb_dimms_per_channel = 1,
	.nb_ranks_per_dimm = 1,
	.nb_ci = 8,
	.nb_real_ci = 8,
	.nb_dpus_per_ci = 8,
	.mram_size = 64 * 1024 * 1024,
	.channel_line_size = 128,
	.rank_line_size = 64,
	.ci_mapping = xeon_sp_ci_mapping,
};

struct dpu_region_address_translation xeon_sp_translate = {
	.interleave = &xeon_sp_interleave,
	.backend_id = DPU_BACKEND_XEON_SP,
	.capabilities = CAP_PERF | CAP_SAFE,
	//.init_region            = xeon_sp_init_region,
	//.destroy_region         = xeon_sp_destroy_region,
	.init_rank = xeon_sp_init_rank,
	.destroy_rank = xeon_sp_destroy_rank,
	.write_to_rank = xeon_sp_write_to_rank,
	.read_from_rank = xeon_sp_read_from_rank,
	.write_to_cis = xeon_sp_write_to_cis,
	.read_from_cis = xeon_sp_read_from_cis,
};
