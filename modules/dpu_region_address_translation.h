/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright 2020 UPMEM. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 */
#ifndef DPU_REGION_ADDRESS_TRANSLATION_INCLUDE_H
#define DPU_REGION_ADDRESS_TRANSLATION_INCLUDE_H

#ifdef CONFIG_X86_64
extern struct dpu_region_address_translation xeon_sp_translate;
#endif
extern struct dpu_region_address_translation fpga_kc705_translate_1dpu;
extern struct dpu_region_address_translation fpga_kc705_translate_8dpu;
extern struct dpu_region_address_translation fpga_aws_translate;
#ifdef CONFIG_PPC64
extern struct dpu_region_address_translation power9_translate;
#endif

enum { DPU_BACKEND_XEON_SP = 0,
       DPU_BACKEND_FPGA_KC705,
       DPU_BACKEND_FPGA_AWS,
       DPU_BACKEND_POWER9,

       DPU_BACKEND_NUMBER };

int dpu_get_translation_config(struct device *dev, int default_backend);

#define CAP_SAFE (1 << 0)
#define CAP_PERF (1 << 1)
#define CAP_HYBRID_CONTROL_INTERFACE (1 << 2)
#define CAP_HYBRID_MRAM (1 << 3)
#define CAP_HYBRID (CAP_HYBRID_MRAM | CAP_HYBRID_CONTROL_INTERFACE)

extern struct dpu_region_address_translation *backend_translate[];

/* The following (strong) assumptions are made:
 *
 * 1/ This implements address translation for the following configuration:
 *   - Socket interleaving: disabled
 *   - Die interleaving: disabled
 *   - Channel interleaving: enabled
 * This configuration allows one NUMA node per die.
 *
 * 2/ Symmetrical topology:
 *   - Same dimms with same number of ranks
 *   - Each channel is populated with the same number of dimms
 */

/* How to optimize throughput:
 * To access one bank, one row must be *activated*: one row being 1kB long.
 * => Access to a bank must be 1kB contiguous into the bank.
 * It is possible to activate 4 banks into a DRAM.
 * *activate* means the load/store will go into DRAM buffer (called the row
 * buffer)
 * *precharge* will flush this buffer into the corresponding row
 */

struct dpu_region_interleaving {
	uint8_t nb_channels;
	uint8_t nb_dimms_per_channel;
	uint8_t nb_ranks_per_dimm;

	uint16_t channel_line_size; /* Contiguous line size sent to a channel */
	uint16_t rank_line_size; /* Should be a multiple of cache line size */

	/* Per-rank infos */
	uint8_t nb_ci;
	uint8_t nb_real_ci;
	uint8_t nb_dpus_per_ci;
	uint32_t mram_size;

	/* Control interface mapping: used for half-a-dimm workaround */
	uint8_t *ci_mapping;
};

#ifndef struct_dpu_transfer_mram_t
#define struct_dpu_transfer_mram_t
struct dpu_transfer_mram {
	void *ptr;
	uint32_t offset_in_mram : 30;
	uint32_t mram_number : 2;
	uint32_t size;
};
#endif

/* Backend description of the CPU/BIOS configuration address translation:
 * interleave: Describe the machine configuration, retrieved from ACPI table
 *		and dpu_chip_id_info: ACPI table gives info about physical
 *		topology (number of channels, number of dimms...etc)
 *		and the dpu_chip_id whose configuration is hardcoded
 *		into dpu_chip_id_info.h (number of dpus, size of MRAM...etc).
 * init_region: Init data structures/threads for the whole region
 * destroy_region: Destroys data structures/threads for the whole region
 * init_rank: Init data structures/threads for a single rank
 * destroy_rank: Destroys data structures/threads for a single rank
 * write_to_cis: Writes blocks of 64 bytes that targets all CIs. The
 *		 backend MUST:
 *			- interleave
 *			- byte order
 *			- nopify and send MSB
 *		 bit ordering must be done by upper software layer since only
 *		 a few commands require it, which is unknown at this level.
 * read_from_cis: Reads blocks of 64 bytes from all CIs, same comment as
 *		  write_block_to_ci.
 * write_to_rank: Writes to MRAMs using the matrix of descriptions of
 *		  transfers for each dpu.
 * read_from_rank: Reads from MRAMs using the matrix of descriptions of
 *		   transfers for each dpu.
 */
struct dpu_region_address_translation {
	/* Physical topology */
	struct dpu_region_interleaving *interleave;

	/* Id exposed through sysfs for userspace. */
	uint8_t backend_id;

	/* PERF, SAFE, HYBRID & MRAM, HYBRID & CTL IF, ... */
	uint64_t capabilities;

	/* In hybrid mode, userspace needs to know the size it needs to mmap */
	uint64_t hybrid_mmap_size;

	/* Pointer to private data for each backend implementation */
	void *private;

	/* Note that:
	 * - no check must be done on region size in those callbacks,
	 *   they will be done by caller (size of transfer...etc),
	 * - for DPU writing, 'blocking' writing from the host is done will
	 *   be done by caller.
	 */

	/* Returns -errno on error, 0 otherwise. */
	int (*init_region)(struct dpu_region_address_translation *tr);
	void (*destroy_region)(struct dpu_region_address_translation *tr);

	int (*init_rank)(struct dpu_region_address_translation *tr,
			 uint8_t channel_id, uint8_t rank_id);
	void (*destroy_rank)(struct dpu_region_address_translation *tr,
			     uint8_t channel_id, uint8_t rank_id);

	/* block_data points to differents objects depending on 'where' the
	 * backend is implemented:
	 * - in userspace, it points to a virtually contiguous buffer
	 * - in kernelspace, it points to an array of pages of size PAGE_SIZE.
	 */

	/* Returns the number of bytes written */
	void (*write_to_rank)(struct dpu_region_address_translation *tr,
			      void *base_region_addr, uint8_t channel_id,
			      uint8_t rank_id,
			      struct dpu_transfer_mram *transfer_matrix);
	/* Returns the number of bytes read */
	void (*read_from_rank)(struct dpu_region_address_translation *tr,
			       void *base_region_addr, uint8_t channel_id,
			       uint8_t rank_id,
			       struct dpu_transfer_mram *transfer_matrix);

	/* block_data points to an array of nb_ci uint64_t */

	/* Returns the number of bytes written */
	void (*write_to_cis)(struct dpu_region_address_translation *tr,
			     void *base_region_addr, uint8_t channel_id,
			     uint8_t rank_id, void *block_data,
			     uint32_t block_size);
	/* Returns the number of bytes read */
	void (*read_from_cis)(struct dpu_region_address_translation *tr,
			      void *base_region_addr, uint8_t channel_id,
			      uint8_t rank_id, void *block_data,
			      uint32_t block_size);
#ifdef __KERNEL__
	int (*mmap_hybrid)(struct dpu_region_address_translation *tr,
			   uint8_t rank_id, struct file *filp,
			   struct vm_area_struct *vma);
#endif
};

#endif /* DPU_REGION_ADDRESS_TRANSLATION_INCLUDE_H */
