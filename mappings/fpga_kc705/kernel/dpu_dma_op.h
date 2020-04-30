/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved.
 *
 * Includes portions of codes from https://github.com/strezh/XPDMA,
 * with the authorization of the author Iurii Strezhik <strezhik@gmail.com>.
 */

#ifndef DRIVER_DPU_DMA_OP_H
#define DRIVER_DPU_DMA_OP_H

#include "dpu_device.h"

int xpdma_init(struct pci_device_fpga *pdev);
void xpdma_exit(struct pci_device_fpga *pdev);
int sg_block(struct pci_device_fpga *pdev, int direction, void *data, size_t count, u32 addr);

#endif //DRIVER_DPU_DMA_OP_H
