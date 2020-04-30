# SPDX-License-Identifier: GPL-2.0
#
# Copyright 2020 UPMEM. All rights reserved.

obj-m += dpu.o

dpu-objs += dpu_region.o dpu_region_sysfs.o dpu_rank.o dpu_rank_sysfs.o
dpu-objs += dpu_pcb_transformation.o
dpu-objs += dpu_control_interface.o
dpu-objs += dpu_mcu_ci_protocol.o
dpu-objs += dpu_acpi.o
dpu-objs += dpu_region_dev.o dpu_region_srat.o
format-source  = modules/dpu_region.c modules/dpu_region_sysfs.c modules/dpu_rank.c modules/dpu_rank_sysfs.c
format-source += modules/dpu_pcb_transformation.c
format-source += modules/dpu_control_interface.c
format-source += modules/dpu_mcu_ci_protocol.c
format-source += modules/dpu_acpi.c
format-source += modules/dpu_region_dev.c modules/dpu_region_srat.c
format-source += modules/dpu_acpi.h modules/dpu_control_interface.h modules/dpu_pcb_transformation.h
format-source += modules/dpu_mcu_ci_protocol.h modules/dpu_mcu_ci_commands.h modules/dpu_mcu_ci_compat.h
format-source += modules/dpu_rank.h modules/dpu_rank_ioctl.h modules/dpu_rank_tracepoints.h
format-source += modules/dpu_region_address_translation.h
format-source += modules/dpu_region_constants.h modules/dpu_region_dev.h modules/dpu_region.h
format-source += modules/dpu_utils.h

# Backends
dpu-objs 	+= ../mappings/fpga_kc705/kernel/fpga_kc705_translation.o
dpu-objs 	+= ../mappings/fpga_kc705/kernel/dpu_dma_op.o
dpu-objs 	+= ../mappings/fpga_kc705/kernel/dpu_spi.o
format-source 	+= mappings/fpga_kc705/kernel/fpga_kc705_translation.c
format-source 	+= mappings/fpga_kc705/kernel/dpu_spi.c
format-source 	+= mappings/fpga_kc705/kernel/dpu_device.h
format-source 	+= mappings/fpga_kc705/kernel/dpu_spi.h

dpu-objs 	+= ../mappings/fpga_aws/kernel/fpga_aws_translation.o
dpu-objs 	+= ../mappings/fpga_aws/kernel/libxdma.o
format-source 	+= mappings/fpga_aws/kernel/fpga_aws_translation.c

ifeq (${CONFIG_X86_64},y)
dpu-objs	+= ../mappings/xeon_sp/kernel/xeon_sp_translation.o
endif
format-source	+= mappings/xeon_sp/kernel/xeon_sp_translation.c

ifeq (${CONFIG_PPC64},y)
dpu-objs	+= ../mappings/power9/kernel/power9_translation.o
endif
format-source	+= mappings/power9/kernel/power9_translation.c

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(dir $(mkfile_path))
KDIR ?= /lib/modules/$(shell uname -r)/build
SOURCE_KDIR ?= $(KDIR)

ccflags-y += -I$(SOURCE_KDIR)/drivers/dax
ccflags-y += -I$(KDIR)/drivers/dax
ccflags-y += -I$(current_dir)

ccflags-y += -I$(current_dir)/../mappings/fpga_kc705/ -I$(current_dir)/../mappings/fpga_kc705/kernel
ccflags-y += -I$(current_dir)/../mappings/fpga_aws/ -I$(current_dir)/../mappings/fpga_aws/kernel

all:
	$(MAKE) -C $(KDIR) M=$(current_dir) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(current_dir) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(current_dir) clean
	rm -f ../mappings/fpga_kc705/kernel/fpga_kc705_translation.o
	rm -f ../mappings/fpga_kc705/kernel/dpu_dma_op.o
	rm -f ../mappings/fpga_kc705/kernel/dpu_spi.o
	rm -f ../mappings/fpga_aws/kernel/fpga_aws_translation.o
	rm -f ../mappings/fpga_aws/kernel/libxdma.o
	rm -f ../mappings/xeon_sp/kernel/xeon_sp_translation.o

format:
	clang-format -style=file -i $(patsubst %,../%,$(format-source))

space := $(subst ,, )

print-format-source:
		@echo "$(subst $(space),|,$(format-source))"

sign: all
	/usr/src/kernels/$(shell uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der dpu.ko
