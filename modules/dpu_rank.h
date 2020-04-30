/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DPU_RANK_INCLUDE_H
#define DPU_RANK_INCLUDE_H

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/sizes.h>

#include "dpu_region.h"

#define DPU_RANK_NAME "dpu_rank"
#define DPU_RANK_PATH DPU_REGION_PATH "/" DPU_RANK_NAME "%d"

/* Size in bytes of one rank of a DPU DIMM */
#define DPU_RANK_SIZE (8ULL * SZ_1G)

/* The granularity of access to a rank is a cache line, which is 64 bytes */
#define DPU_RANK_SIZE_ACCESS 64

struct dpu_rank_owner {
	uint8_t is_owned;
	unsigned int usage_count;
};

struct dpu_rank {
	struct dpu_region *region;

	struct dpu_rank_owner owner;

	struct cdev cdev;
	struct device dev;
	dev_t devt;
	struct kobject *kobj_ci;

	uint8_t channel_id;
	uint8_t id;
	uint8_t id_in_region;

	uint64_t *control_interface;
	/* Preallocates a huge array of struct page *
	 * pointers for get_user_pages.
	 */
	struct page **xfer_dpu_page_array;

	/* Used for half-a-dimm workaround */
	uint64_t *real_control_interface;
	struct dpu_transfer_mram *real_xfer_matrix;

	/* Locks in-kernel access to control interfaces: note that
	 * locking ALL control interface is not necessary, we will improve by
	 * using one lock by control interface and use different physical
	 * addresses to access them.
	 */
	struct mutex ci_lock;

	uint8_t trace_command_mask;
	uint8_t init_done;

	char mcu_version[128];

	uint32_t fck_frequency;
	uint32_t clock_division_min;
	uint32_t clock_division_max;

	char part_number[20]; /* e.g UPMEM-E19 */
	char serial_number[10];
};

extern struct class *dpu_rank_class;

int dpu_rank_create_devices(struct device *dev, struct dpu_region *region);
void dpu_rank_release_devices(struct dpu_region *region);

extern const struct attribute_group *dpu_rank_attrs_groups[];

int dpu_rank_sysfs_create(struct device *dev, struct dpu_rank *rank);

#endif /* DPU_RANK_INCLUDE_H */
