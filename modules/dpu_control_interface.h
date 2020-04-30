/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DPU_CONTROL_INTERFACE_INCLUDE_H
#define DPU_CONTROL_INTERFACE_INCLUDE_H

#include "dpu_rank.h"

int dpu_control_interface_get_chip_id(struct dpu_rank *rank);
int dpu_control_interface_set_fault_bkp(struct dpu_rank *rank);
int dpu_control_interface_read_wram(struct dpu_rank *rank, uint8_t dpu_id,
				    uint8_t slice_id, uint32_t wram_address,
				    uint32_t *buffer, uint32_t nb_words);

int dpu_control_interface_get_access_to_mram(struct dpu_rank *rank,
					     uint8_t dpu_id, uint8_t slice_id);
int dpu_control_interface_release_access_to_mram(struct dpu_rank *rank,
						 uint8_t dpu_id,
						 uint8_t slice_id);
int dpu_control_interface_check_mux(struct dpu_rank *rank, uint8_t dpu_id,
				    uint8_t slice_id);
void dpu_control_interface_commit_command(struct dpu_rank *rank,
					  uint64_t *command);
void dpu_control_interface_update_command(struct dpu_rank *rank,
					  uint64_t *result);

#endif
