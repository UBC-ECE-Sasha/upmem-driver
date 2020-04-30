/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DPU_ACPI_INCLUDE_H
#define DPU_ACPI_INCLUDE_H

struct dpu_region_data *dpu_region_get_data(uint32_t config, uint32_t chip_id);
void dpu_region_free_data(struct dpu_region_data *data);

#endif /* DPU_ACPI_INCLUDE_H */
