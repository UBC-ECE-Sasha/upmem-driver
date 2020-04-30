/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#ifndef DEVDRIVER_DPU_DEVICE_H
#define DEVDRIVER_DPU_DEVICE_H

#include <linux/cdev.h>
#include <linux/kref.h>

#define DESCRIPTOR_SIZE 64 // 64-byte aligned Transfer Descriptor

// Scatter Gather Transfer descriptor
typedef struct {
	u32 nextDesc; /* 0x00 */
	u32 na1; /* 0x04 */
	u32 srcAddr; /* 0x08 */
	u32 na2; /* 0x0C */
	u32 destAddr; /* 0x10 */
	u32 na3; /* 0x14 */
	u32 control; /* 0x18 */
	u32 status; /* 0x1C */
} __aligned(DESCRIPTOR_SIZE) sg_desc_t;

/**
 * struct bank_map - Device mapping of the used register banks
 * @bar:    BAR containing the register bank
 * @offs:   offset of this bank within its BAR
 * @len:    bank size, in bytes
 * @addr:   set to the base virtual address of this bank
 */
struct bank_map {
	char name[9];
	unsigned char bar;
	unsigned int offs;
	unsigned int len;
	void *addr;
	unsigned long phys;
};

// TODO not pretty
// #define BANKS_NUM       (ARRAY_SIZE(init_banks))
#define BANKS_NUM 1

/* List head of all fpga pci devices */
struct pci_device_fpga_dma {
	unsigned long gBaseHdwr, gBaseLen;
	void *gBaseVirt;
	char *gReadBuffer, *gWriteBuffer;
	dma_addr_t gReadHWAddr, gWriteHWAddr, gDescChainHWAddr;
	sg_desc_t *gDescChain;
	size_t gDescChainLength;
};

struct pci_device_fpga {
	struct pci_dev *dev;
	int id_dev;
	struct bank_map banks[BANKS_NUM];
	struct pci_device_fpga_dma dma;
};

extern uint32_t nb_dpus_fpga;

#endif /* DEVDRIVER_DPU_DEVICE_H */
