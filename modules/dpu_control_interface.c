/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/delay.h>

#include "dpu_rank.h"
#include "dpu_region_address_translation.h"
#include "dpu_pcb_transformation.h"
#include "dpu_commands.h"
#include "dpu_utils.h"

#define BYTE_ORDER_EXPECTED 0x000103FF0F8FCFEFULL
#define BIT_ORDER_EXPECTED 0x0F884422

#define WAIT_TIMEOUT_MS 10

#define RESULT_VALUE_MASK 0xFFFFFFFF

#define commit_command_and_wait_for_completion(tr, region, rank, nb_cis,       \
					       slice_id, ret, label_err)       \
	tr->write_to_cis(tr, region->base, rank->channel_id,                   \
			 rank->id_in_region, rank->control_interface,          \
			 nb_cis * sizeof(uint64_t));                           \
	if (dpu_control_interface_wait_result(rank, rank->control_interface,   \
					      slice_id)) {                     \
		ret = -EIO;                                                    \
		goto label_err;                                                \
	}

static inline int dpu_control_interface_poll_all_dpus(struct dpu_rank *rank)
{
	return 0;
}

static int dpu_control_interface_wait_result(struct dpu_rank *rank,
					     uint64_t *control_interface,
					     uint8_t slice_id)
{
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	uint64_t command = control_interface[slice_id];
	uint64_t result_mask, expected_result;
	unsigned long timeout = jiffies + msecs_to_jiffies(WAIT_TIMEOUT_MS);
	uint8_t nb_cis;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	if ((CI_FRAME_DPU_OPERATION_NOP & command) ==
	    CI_FRAME_DPU_OPERATION_NOP) {
		result_mask = 0xFF00000000000000ULL;
		expected_result = 0xFF00000000000000ULL;
	} else {
		result_mask = 0xFF0000FF00000000ULL;
		expected_result = 0x000000FF00000000ULL;
	}

	do {
		tr->read_from_cis(tr, region->base, rank->channel_id,
				  rank->id_in_region, control_interface,
				  nb_cis * sizeof(uint64_t));

		if (time_after(jiffies, timeout)) {
			pr_err("waiting for command completion timed out.\n");
			return -EIO;
		}
	} while ((control_interface[slice_id] & result_mask) !=
		 expected_result);

	return 0;
}

/* Must be called with rank mutex locked */
static inline int dpu_control_interface_bit_order(struct dpu_rank *rank,
						  uint64_t *control_interface,
						  uint64_t byte_order)
{
	struct device *dev = &rank->dev;
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	uint64_t bit_order;
	int ret = 0;
	uint16_t c2d, d2c;
	uint8_t ne, stutter;
	uint8_t nb_cis;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	/* 1/ Bit order empty */
	control_interface[0] = CI_FRAME_DPU_OPERATION_BIT_ORDER(0, 0, 0, 0);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis, 0, ret,
					       err_io);

	bit_order = rank->control_interface[0];

	/* 2/ Compute necessary transformations for previous results */
	pcb_transformation_fill(byte_order, bit_order, &region->pdata->pcb);

	/* 3/ Bit order for configuration */
	c2d = pcb_transformation_dpu_to_cpu(&region->pdata->pcb,
					    region->pdata->pcb.cpu_to_dpu);
	d2c = pcb_transformation_cpu_to_dpu(&region->pdata->pcb,
					    region->pdata->pcb.dpu_to_cpu);
	ne = region->pdata->pcb.nibble_swap;
	stutter = 0;

	rank->control_interface[0] =
		CI_FRAME_DPU_OPERATION_BIT_ORDER(c2d, d2c, ne, stutter);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis, 0, ret,
					       err_io);

	bit_order = rank->control_interface[0];
	if ((bit_order & RESULT_VALUE_MASK) != 0x0F884422) {
		dev_err(dev, "bit order value result %llu != 0x0F884422\n",
			bit_order);
		ret = -EIO;
		goto err_io;
	}

err_io:
	return ret;
}

int dpu_control_interface_set_fault_bkp(struct dpu_rank *rank)
{
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	uint8_t nb_cis, nb_dpus_per_ci;
	uint8_t dpu_id, ci_id;
	int idx, ret = 0;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	nb_dpus_per_ci = tr->interleave->nb_dpus_per_ci;

	mutex_lock(&rank->ci_lock);

	for_each_dpu_in_rank(idx, ci_id, dpu_id, nb_cis, nb_dpus_per_ci)
	{
		memset(rank->control_interface, 0, nb_cis * sizeof(uint64_t));

		rank->control_interface[ci_id] =
			CI_FRAME_DPU_OPERATION_BKP_FAULT_SET_FOR_DPU_STRUCTURE(
				dpu_id);
		commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
						       ci_id, ret, err_unlock);

		rank->control_interface[ci_id] =
			CI_FRAME_DPU_OPERATION_BKP_FAULT_SET_FOR_DPU_FRAME(
				dpu_id);
		commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
						       ci_id, ret, err_unlock);
	}

err_unlock:
	mutex_unlock(&rank->ci_lock);

	return ret;
}

/* Access any rank of a region to determine the 'pcb transformation'.
 * For now, we assume that bit and byte orderings are the same on all CIs
 * belonging to a same REGION, that may not be true.
 */
int dpu_control_interface_get_chip_id(struct dpu_rank *rank)
{
	struct device *dev = &rank->dev;
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	uint64_t byte_order;
	uint8_t nb_cis;
	int ret = 0;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	mutex_lock(&rank->ci_lock);
	memset(rank->control_interface, 0, nb_cis * sizeof(uint64_t));

	/* 1/ Byte order */
	rank->control_interface[0] = CI_FRAME_DPU_OPERATION_BYTE_ORDER;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis, 0, ret,
					       err_unlock);

	byte_order = rank->control_interface[0];

	/* At the moment, no backend implements byte ordering translation,
	 * so in case there is any in HW, gracefully exits.
	 */
	if (byte_order != 0x000103FF0F8FCFEFULL) {
		ret = -EIO;
		dev_err(dev, "byte order not supported yet: %llx (%d)\n",
			byte_order, ret);
		goto err_unlock;
	}

	/* 2/ Bit order for reset */
	ret = dpu_control_interface_bit_order(rank, rank->control_interface,
					      byte_order);
	if (ret) {
		dev_err(dev, "bit order result error (%d)\n", ret);
		goto err_unlock;
	}

	/* 3/ Reset before configuring bit ordering */
	rank->control_interface[0] = CI_FRAME_DPU_OPERATION_SOFTWARE_RESET(8);
	tr->write_to_cis(tr, region->base, rank->channel_id, rank->id_in_region,
			 rank->control_interface, nb_cis * sizeof(uint64_t));

	usleep_range(100, 150);

	/* 4/ Bit order for chip id */
	ret = dpu_control_interface_bit_order(rank, rank->control_interface,
					      byte_order);
	if (ret) {
		dev_err(dev, "bit order result error (%d)\n", ret);
		goto err_unlock;
	}

	/* 5/ Chip id */
	rank->control_interface[0] = CI_FRAME_DPU_OPERATION_IDENTITY;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis, 0, ret,
					       err_unlock);

	region->pdata->dpu_chip_id =
		rank->control_interface[0] & RESULT_VALUE_MASK;

err_unlock:
	mutex_unlock(&rank->ci_lock);

	return ret;
}

int dpu_control_interface_read_wram(struct dpu_rank *rank, uint8_t dpu_id,
				    uint8_t slice_id, uint32_t wram_address,
				    uint32_t *buffer, uint32_t nb_words)
{
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	uint32_t cur_word = 0;
	int ret = 0;
	uint8_t nb_cis;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	mutex_lock(&rank->ci_lock);

	while ((buffer + cur_word) < (buffer + nb_words)) {
		rank->control_interface[slice_id] =
			CI_FRAME_DPU_OPERATION_WRAM_READ_WORD_FOR_DPU_STRUCTURE(
				dpu_id, wram_address + cur_word);
		commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
						       slice_id, ret, err_io);

		rank->control_interface[slice_id] =
			CI_FRAME_DPU_OPERATION_WRAM_READ_WORD_FOR_DPU_FRAME(
				dpu_id, wram_address + cur_word);
		commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
						       slice_id, ret, err_io);

		*(buffer + cur_word++) =
			rank->control_interface[slice_id] & RESULT_VALUE_MASK;
	}

err_io:
	mutex_unlock(&rank->ci_lock);

	return ret;
}

static int dpu_control_interface_x86_mram(struct dpu_rank *rank, uint8_t dpu_id,
					  uint8_t slice_id)
{
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	int ret = 0;
	uint8_t nb_cis;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 104, 96, 96, 96, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 104, 96, 96, 96, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 104, 98, 96, 96, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 104, 98, 96, 96, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 104, 100, 96, 96, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 104, 100, 96, 96, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_CLEAR_FOR_PREVIOUS_STRUCTURE;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_CLEAR_FOR_PREVIOUS_FRAME;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

err_io:
	return ret;
}

static int dpu_control_interface_dpu_mram(struct dpu_rank *rank, uint8_t dpu_id,
					  uint8_t slice_id)
{
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	int ret = 0;
	uint8_t nb_cis;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 104, 96, 96, 97, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 104, 96, 96, 97, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 104, 98, 96, 97, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 104, 98, 96, 97, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 104, 100, 96, 97, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 104, 100, 96, 97, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_CLEAR_FOR_PREVIOUS_STRUCTURE;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_CLEAR_FOR_PREVIOUS_FRAME;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

err_io:
	return ret;
}

int dpu_control_interface_check_mux(struct dpu_rank *rank, uint8_t dpu_id,
				    uint8_t slice_id)
{
	struct dpu_region_address_translation *tr;
	struct dpu_region *region;
	int ret;
	uint8_t nb_cis;

	region = rank->region;
	tr = region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_STRUCTURE(
			dpu_id, 111, 111, 96, 98, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_WRITE_FOR_DPU_FRAME(
			dpu_id, 111, 111, 96, 98, 96, 32);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_CLEAR_FOR_PREVIOUS_STRUCTURE;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_CLEAR_FOR_PREVIOUS_FRAME;
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_READ_FOR_DPU_STRUCTURE(dpu_id);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	rank->control_interface[slice_id] =
		CI_FRAME_DPU_OPERATION_DMA_CTRL_READ_FOR_DPU_FRAME(dpu_id);
	commit_command_and_wait_for_completion(tr, region, rank, nb_cis,
					       slice_id, ret, err_io);

	return rank->control_interface[slice_id] & RESULT_VALUE_MASK;

err_io:
	return ret;
}

int dpu_control_interface_get_access_to_mram(struct dpu_rank *rank,
					     uint8_t dpu_id, uint8_t slice_id)
{
	const int expected = 0x0;
	int ret;
	uint8_t target_dpu_id = dpu_id & 0xFE; // Clear parity bit.

	/* 1/ x86 must take control of the MRAM */
	dpu_control_interface_x86_mram(rank, target_dpu_id, slice_id);
	dpu_control_interface_x86_mram(rank, target_dpu_id + 1, slice_id);

	/* 2/ Check mux control */
	do {
		ret = dpu_control_interface_check_mux(rank, target_dpu_id,
						      slice_id);
	} while (ret != expected);

	do {
		ret = dpu_control_interface_check_mux(rank, target_dpu_id + 1,
						      slice_id);
	} while (ret != expected);

	return 0;
}

int dpu_control_interface_release_access_to_mram(struct dpu_rank *rank,
						 uint8_t dpu_id,
						 uint8_t slice_id)
{
	const int expected = 0x3;
	int ret;
	uint8_t target_dpu_id = dpu_id & 0xFE; // Clear parity bit.

	/* 1/ Release MRAM to dpu */
	dpu_control_interface_dpu_mram(rank, target_dpu_id, slice_id);
	dpu_control_interface_dpu_mram(rank, target_dpu_id + 1, slice_id);

	/* 2/ Check mux control */
	do {
		ret = dpu_control_interface_check_mux(rank, target_dpu_id,
						      slice_id);
	} while (ret != expected);

	do {
		ret = dpu_control_interface_check_mux(rank, target_dpu_id + 1,
						      slice_id);
	} while (ret != expected);

	return 0;
}

void dpu_control_interface_commit_command(struct dpu_rank *rank,
					  uint64_t *command)
{
	struct dpu_region_address_translation *tr;
	uint32_t size_command;
	uint8_t nb_cis;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	size_command = sizeof(uint64_t) * nb_cis;

	memcpy(rank->control_interface, command, size_command);

	mutex_lock(&rank->ci_lock);
	tr->write_to_cis(tr, rank->region->base, rank->channel_id,
			 rank->id_in_region, rank->control_interface,
			 size_command);
	mutex_unlock(&rank->ci_lock);
}

void dpu_control_interface_update_command(struct dpu_rank *rank,
					  uint64_t *result)
{
	struct dpu_region_address_translation *tr;
	uint32_t size_command;
	uint8_t nb_cis;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	size_command = sizeof(uint64_t) * nb_cis;

	mutex_lock(&rank->ci_lock);
	tr->read_from_cis(tr, rank->region->base, rank->channel_id,
			  rank->id_in_region, rank->control_interface,
			  size_command);
	mutex_unlock(&rank->ci_lock);

	memcpy(result, rank->control_interface, size_command);
}
