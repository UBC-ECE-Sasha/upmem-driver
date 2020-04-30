/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DPU_PCB_TRANSFORMATION_INCLUDE_H
#define DPU_PCB_TRANSFORMATION_INCLUDE_H

#include <linux/kernel.h>

struct dpu_pcb_transformation {
	uint16_t cpu_to_dpu;
	uint16_t dpu_to_cpu;
	uint8_t nibble_swap;
};

void pcb_transformation_fill(uint64_t byte_order_result,
			     uint32_t bit_order_result,
			     struct dpu_pcb_transformation *pcb_transformation);

uint8_t pcb_transformation_get_reciprocal(uint8_t code);
uint32_t
pcb_transformation_dpu_to_cpu(struct dpu_pcb_transformation *pcb_transformation,
			      uint32_t dpu_value);
uint32_t
pcb_transformation_cpu_to_dpu(struct dpu_pcb_transformation *pcb_transformation,
			      uint32_t cpu_value);

#endif //DPU_PCB_TRANSFORMATION_H
