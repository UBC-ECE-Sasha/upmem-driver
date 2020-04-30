/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DPU_UTILS_INCLUDE_H
#define DPU_UTILS_INCLUDE_H

#ifdef __KERNEL__
#include "dpu_rank.h"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)
#define page_to_virt(page) phys_to_virt(page_to_phys(page))
#endif

struct xfer_page {
	struct page **pages;
	unsigned long nb_pages;
	int off_first_page; /* Because user allocation through malloc
                                 * can be unaligned to page size, we must
                                 * know the offset within the first page of
                                 * the buffer.
                                 */
};

#define for_each_dpu_in_rank(idx, ci, dpu, nb_cis, nb_dpus_per_ci)             \
	for (dpu = 0, idx = 0; dpu < nb_dpus_per_ci; ++dpu)                    \
		for (ci = 0; ci < nb_cis; ++ci, ++idx)

/* Half-a-dimm workaround */
static inline uint8_t get_slice_id(struct dpu_region_address_translation *tr,
				   uint8_t real_slice_id)
{
	uint8_t i, nb_cis;

	nb_cis = tr->interleave->nb_ci;

	for (i = 0; i < nb_cis; ++i)
		if (real_slice_id == tr->interleave->ci_mapping[i])
			return i;

	return nb_cis;
}

static inline uint8_t
get_real_slice_id(struct dpu_region_address_translation *tr, uint8_t slice_id)
{
	return tr->interleave->ci_mapping[slice_id];
}

static inline int
get_real_xfer_matrix_index(struct dpu_region_address_translation *tr,
			   uint8_t real_slice_id, uint8_t dpu_id)
{
	return dpu_id * tr->interleave->nb_real_ci + real_slice_id;
}

static inline struct dpu_transfer_mram *expand_transfer_matrix(
	struct dpu_region_address_translation *tr, struct dpu_rank *rank,
	struct dpu_transfer_mram *xfer_matrix, uint8_t nb_real_cis,
	uint8_t nb_cis, uint8_t nb_dpus_per_ci)
{
	int idx, real_idx;
	uint8_t dpu_id, ci_id;

	memset(rank->real_xfer_matrix, 0,
	       nb_real_cis * nb_dpus_per_ci * sizeof(struct dpu_transfer_mram));

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		if (xfer_matrix[idx].ptr == NULL)
			continue;

		real_idx = get_real_xfer_matrix_index(
			tr, get_real_slice_id(tr, ci_id), dpu_id);

		rank->real_xfer_matrix[real_idx].mram_number =
			xfer_matrix[idx].mram_number;
		rank->real_xfer_matrix[real_idx].size = xfer_matrix[idx].size;
		rank->real_xfer_matrix[real_idx].offset_in_mram =
			xfer_matrix[idx].offset_in_mram;
		rank->real_xfer_matrix[real_idx].ptr = xfer_matrix[idx].ptr;
	}

	return rank->real_xfer_matrix;
}

static inline void *
get_real_control_interface_commands(struct dpu_region_address_translation *tr,
				    struct dpu_rank *rank, void *block_data,
				    uint8_t nb_real_cis, uint8_t nb_cis)
{
	uint64_t *command;
	int i;

	memset(rank->real_control_interface, 0, nb_real_cis * sizeof(uint64_t));

	for (i = 0; i < nb_cis; ++i) {
		uint8_t real_id = get_real_slice_id(tr, i);

		command = &((uint64_t *)block_data)[i];
		rank->real_control_interface[real_id] = *command;
	}

	return rank->real_control_interface;
}

static inline void
get_control_interface_results(struct dpu_region_address_translation *tr,
			      void *real_block_data, void *block_data,
			      uint8_t nb_real_cis, uint8_t nb_cis)
{
	uint64_t *result;
	int i;

	for (i = 0; i < nb_real_cis; ++i) {
		uint8_t id = get_slice_id(tr, i);

		if (id >= nb_cis)
			continue;

		result = &((uint64_t *)real_block_data)[i];

		((uint64_t *)block_data)[id] = *result;
	}
}
#endif /* __KERNEL__ */

#endif /* DPU_UTILS_INCLUDE_H */
