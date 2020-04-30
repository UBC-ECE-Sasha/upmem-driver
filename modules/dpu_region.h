/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DPU_REGION_INCLUDE_H
#define DPU_REGION_INCLUDE_H

#include <linux/memremap.h>
#include <linux/idr.h>
#include <linux/version.h>
#include <linux/device.h>

#include "dpu_region_address_translation.h"
#include "dpu_region_constants.h"
#include "dpu_pcb_transformation.h"

/* Fpga kc705 */
#include "dpu_device.h"

#define DPU_REGION_NAME "dpu_region"
#define DPU_REGION_PATH DPU_REGION_NAME "%d"

struct dpu_dax_device {
	struct percpu_ref ref;
	struct dev_pagemap pgmap;
	struct completion cmp;
};

struct dpu_region_data {
	/* To a dpu_region is attached a chip id, we do not mix
	 * different versions of DPU
	 */
	uint64_t dpu_chip_id;

	/* Numa affinity */
	int numa_node_id;

	/* Address translation infos */
	struct dpu_region_address_translation *addr_translate;

	/* Describes bit and byte ordering */
	struct dpu_pcb_transformation pcb;

	/* Functional mode of the region: either in "perf mode",
	 * where EVERYTHING is handled in userspace, or "safe mode", where a
	 * group of applications is guaranteed exclusive access to a rank.
	 */
	uint8_t mode;
	uint32_t usage_count;
};

struct dpu_region {
	struct dpu_region_data *pdata;
	struct dpu_rank *ranks;
	struct ida rank_ida;

	uint8_t nb_ranks;

	dev_t devt;
	spinlock_t lock; // TODO Think more about what type of lock to use
	uint8_t debug_mode;

	uint8_t id;

	uint8_t must_init_mram;

	/* Memory driver */
	struct dpu_dax_device dpu_dax_dev;
	struct cdev cdev_dax;
	struct device dev_dax;
	dev_t devt_dax;
	void *base; /* linear address corresponding to the region resource */
	uint64_t size;

	/* Pci fpga kc705 driver */
	struct pci_device_fpga dpu_fpga_kc705_dev;
	uint8_t activate_ila;
	uint8_t activate_filtering_ila;
	uint8_t activate_mram_bypass;
	uint8_t spi_mode_enabled;
	uint32_t mram_refresh_emulation_period;
	struct dentry *iladump;
	struct dentry *dpu_debugfs;

	/* Pci fpga aws driver */
	struct xdma_dev *dpu_fpga_aws_dev;
};

int dpu_region_sysfs_create(struct device *dev);
void dpu_region_sysfs_remove(struct device *dev);

int dpu_region_dev_probe(void);
int dpu_region_srat_probe(void);

int dpu_region_mem_add(u64 addr, u64 size, int index);

#endif /* DPU_REGION_INCLUDE_H */
