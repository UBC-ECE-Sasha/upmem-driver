/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include "dpu_pcb_transformation.h"

static uint8_t index_in_nibble[16] = {
	0, //  N/A  0000
	0, //       0001
	1, //       0010
	0, //  N/A  0011
	2, //       0100
	0, //  N/A  0101
	0, //  N/A  0110
	0, //  N/A  0111
	3, //       1000
	0, //  N/A  1001
	0, //  N/A  1010
	0, //  N/A  1011
	0, //  N/A  1100
	0, //  N/A  1101
	0, //  N/A  1110
	0 //  N/A  1111
};

/* Permits to transform m/l syndrome into its reciprocal
 * function mm/ll.
 */
uint8_t pcb_transformation_get_reciprocal(uint8_t code)
{
	int i, index;
	uint8_t reciproc = 0;

	for (i = 0; i < 4; i++) {
		index = code & 0b11;
		code = code >> 2;
		reciproc |= i << (index << 1);
	}

	return reciproc;
}

void pcb_transformation_fill(uint64_t byte_order_result,
			     uint32_t bit_order_result,
			     struct dpu_pcb_transformation *pcb_transformation)
{
	/* 0/ Byte order matrix */
	// TODO

	/* 1/ Determine nibble swap if any */

	/*  The "0F" part of the pattern's 32-lsb is used to determine if there is a nibble swapping or not */
	uint8_t nibble_swap = ((bit_order_result >> 28) & 0b1111) != 0;

	/* 2/ Determine the bit shufflingS */

	/* m_syndrome is the function that describes the shuffling from DPU to CPU of the MSB */
	uint8_t m_syndrome = // (0b00 << (index_in_nibble[ (bit_order_result >>   ) & 0b1111 ] << 1)) |  // see note *
		(0b01
		 << (index_in_nibble[(bit_order_result >> 4) & 0b1111] << 1)) |
		(0b10
		 << (index_in_nibble[(bit_order_result >> 12) & 0b1111] << 1)) |
		(0b11
		 << (index_in_nibble[(bit_order_result >> 20) & 0b1111] << 1));

	/* l_syndrome is the function that describes the shuffling from DPU to CPU of the LSB */
	uint8_t l_syndrome = // (0b00 << (index_in_nibble[ (bit_order_result >>   ) & 0b1111 ] << 1)) |  // see note *
		(0b01
		 << (index_in_nibble[(bit_order_result >> 0) & 0b1111] << 1)) |
		(0b10
		 << (index_in_nibble[(bit_order_result >> 8) & 0b1111] << 1)) |
		(0b11
		 << (index_in_nibble[(bit_order_result >> 16) & 0b1111] << 1));

	/* mm_syndrome and ll_syndrome are the inverse functions (ie from CPU to DPU) */
	uint8_t mm_syndrome =
		nibble_swap ? pcb_transformation_get_reciprocal(l_syndrome) :
			      pcb_transformation_get_reciprocal(m_syndrome);
	uint8_t ll_syndrome =
		nibble_swap ? pcb_transformation_get_reciprocal(m_syndrome) :
			      pcb_transformation_get_reciprocal(l_syndrome);

	/* 3/ Determine dpu to cpu bit shuffling */

	/* From the above syndromes, "compute" the bitfield for the BIT_ORDER command */
	uint8_t config_3124 =
		nibble_swap ? pcb_transformation_get_reciprocal(ll_syndrome) :
			      pcb_transformation_get_reciprocal(mm_syndrome);
	uint8_t config_2316 =
		nibble_swap ? pcb_transformation_get_reciprocal(mm_syndrome) :
			      pcb_transformation_get_reciprocal(ll_syndrome);

	uint8_t config_4740 =
		nibble_swap ? pcb_transformation_get_reciprocal(l_syndrome) :
			      pcb_transformation_get_reciprocal(m_syndrome);
	uint8_t config_3932 =
		nibble_swap ? pcb_transformation_get_reciprocal(m_syndrome) :
			      pcb_transformation_get_reciprocal(l_syndrome);

	pcb_transformation->nibble_swap = nibble_swap;
	pcb_transformation->cpu_to_dpu = config_2316 | (config_3124 << 8);
	pcb_transformation->dpu_to_cpu = config_3932 | (config_4740 << 8);
}

// TODO Not that sure about nibble_swap : should it done after computation or before computation (when retrieving nibble_value) ?
#define NR_NIBBLES_PER_BYTE 2
#define NR_BITS_PER_NIBBLE 4
uint32_t
pcb_transformation_dpu_to_cpu(struct dpu_pcb_transformation *pcb_transformation,
			      uint32_t dpu_value)
{
	uint32_t cpu_value = 0;
	uint8_t byte_id, nibble_id, transformation_id;

	for (byte_id = 0; byte_id < sizeof(uint32_t); ++byte_id) {
		uint8_t byte_value = (dpu_value >> (byte_id << 3)) & 0xFF;
		uint8_t byte_transformed = 0;

		for (nibble_id = 0; nibble_id < NR_NIBBLES_PER_BYTE;
		     ++nibble_id) {
			/* Get the nibble to 'transform' */
			uint8_t nibble_value =
				(byte_value >> (nibble_id << 2)) & 0xF;
			uint8_t nibble_transformed = 0;
			/* Get the nibble transformation to apply to nibble_value */
			uint8_t nibble_transformation =
				(pcb_transformation->dpu_to_cpu >>
				 (nibble_id << 3)) &
				0xFF;

			for (transformation_id = 0;
			     transformation_id < NR_BITS_PER_NIBBLE;
			     ++transformation_id) {
				/* Get the index of the bit 'transformation_id' into nibble_transformed */
				uint8_t id_bit = (nibble_transformation >>
						  (transformation_id << 1)) &
						 0x3;
				uint8_t bit_value =
					(nibble_value >> transformation_id) &
					0x1;

				nibble_transformed |= bit_value << id_bit;
			}

			byte_transformed |=
				nibble_transformed
				<< ((pcb_transformation->nibble_swap ?
					     ((nibble_id + 1) % 2) :
					     nibble_id)
				    << 2);
		}

		cpu_value |= byte_transformed << (byte_id << 3);
	}

	return cpu_value;
}

uint32_t
pcb_transformation_cpu_to_dpu(struct dpu_pcb_transformation *pcb_transformation,
			      uint32_t cpu_value)
{
	uint32_t dpu_value = 0;
	uint8_t byte_id, nibble_id, transformation_id;

	for (byte_id = 0; byte_id < sizeof(uint32_t); ++byte_id) {
		uint8_t byte_value = (cpu_value >> (byte_id << 3)) & 0xFF;
		uint8_t byte_transformed = 0;

		for (nibble_id = 0; nibble_id < NR_NIBBLES_PER_BYTE;
		     ++nibble_id) {
			/* Get the nibble to 'transform' */
			uint8_t nibble_value =
				(byte_value >> (nibble_id << 2)) & 0xF;
			uint8_t nibble_transformed = 0;
			/* Get the nibble transformation to apply to nibble_value */
			uint8_t nibble_transformation =
				(pcb_transformation->cpu_to_dpu >>
				 (nibble_id << 3)) &
				0xFF;

			for (transformation_id = 0;
			     transformation_id < NR_BITS_PER_NIBBLE;
			     ++transformation_id) {
				/* Get the index of the bit 'transformation_id' into nibble_transformed */
				uint8_t id_bit = (nibble_transformation >>
						  (transformation_id << 1)) &
						 0x3;
				uint8_t bit_value =
					(nibble_value >> transformation_id) &
					0x1;

				nibble_transformed |= bit_value << id_bit;
			}

			byte_transformed |=
				nibble_transformed
				<< ((pcb_transformation->nibble_swap ?
					     ((nibble_id + 1) % 2) :
					     nibble_id)
				    << 2);
		}

		dpu_value |= byte_transformed << (byte_id << 3);
	}

	return dpu_value;
}
