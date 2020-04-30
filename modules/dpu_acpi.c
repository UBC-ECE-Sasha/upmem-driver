/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/dmi.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>

#include "dpu_region.h"
#include "dpu_region_address_translation.h"

#ifdef CONFIG_DMI
/* Translation backends detected using the DMI system attributes */
static const struct dmi_system_id pim_platform_dmi_table[] = {
	{
		.ident = "Intel Xeon Scalable Platform",
		.matches =
			{
				DMI_MATCH(DMI_SYS_VENDOR, "UPMEM"),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
				DMI_MATCH(DMI_PRODUCT_FAMILY, "Xeon_Scalable"),
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) */
			},
		.driver_data = (void *)DPU_BACKEND_XEON_SP,
	},
};
#endif /* CONFIG_DMI */
/* Translation backends detected using the device-tree */
static const struct of_device_id pim_platform_of_table[] = {
	{
		.compatible = "ibm,powernv",
		.data = (void *)DPU_BACKEND_POWER9,
	},
};

int dpu_get_translation_config(struct device *dev, int default_backend)
{
	struct device_node *np;
	const struct of_device_id *of_id;
#ifdef CONFIG_DMI
	const struct dmi_system_id *dmi_id;
	dmi_id = dmi_first_match(pim_platform_dmi_table);
	if (dmi_id) {
		int backend = (uintptr_t)dmi_id->driver_data;
		dev_info(dev, "Translation backend: DMI matched '%s' (%d)\n",
			 dmi_id->ident, backend);
		return backend;
	}
#endif /* CONFIG_DMI */
	np = of_find_matching_node_and_match(NULL, pim_platform_of_table,
					     &of_id);
	if (np) {
		int backend = (uintptr_t)of_id->data;
		dev_info(dev, "Translation backend: OF matched '%s' (%d)\n",
			 of_id->compatible, backend);
		return backend;
	}

	return default_backend;
}

static int dpu_region_init_data(struct dpu_region_address_translation *tr,
				struct dpu_region_data **data, uint64_t chip_id)
{
	int ret;

	*data = kzalloc(sizeof(struct dpu_region_data), GFP_KERNEL);
	if (!*data)
		return -ENOMEM;

	(*data)->addr_translate = kzalloc(
		sizeof(struct dpu_region_address_translation), GFP_KERNEL);
	if (!(*data)->addr_translate) {
		ret = -ENOMEM;
		goto free_data;
	}

	(*data)->dpu_chip_id = chip_id;
	(*data)->mode = DPU_REGION_MODE_UNDEFINED;
	(*data)->usage_count = 0;
	memcpy((*data)->addr_translate, tr,
	       sizeof(struct dpu_region_address_translation));

	return 0;

free_data:
	kfree(*data);

	return ret;
}

struct dpu_region_data *dpu_region_get_data(uint32_t config, uint64_t chip_id)
{
	struct dpu_region_data *data;
	int ret;

	switch (config) {
	case DPU_BACKEND_FPGA_KC705:
		if (chip_id == 5) {
			pr_info("dpu_region: Using fpga kc705_1dpu config\n");

			ret = dpu_region_init_data(&fpga_kc705_translate_1dpu,
						   &data, chip_id);
			if (ret)
				return NULL;
		} else if (chip_id == 6) {
			pr_info("dpu_region: Using fpga kc705_8dpu config\n");

			ret = dpu_region_init_data(&fpga_kc705_translate_8dpu,
						   &data, chip_id);
			if (ret)
				return NULL;
		}
		break;
	case DPU_BACKEND_FPGA_AWS:
		pr_info("dpu_region: Using fpga aws config\n");
		ret = dpu_region_init_data(&fpga_aws_translate, &data, chip_id);
		if (ret)
			return NULL;

		break;
#ifdef CONFIG_X86_64
	case DPU_BACKEND_XEON_SP:
		pr_info("dpu_region: Using xeon sp config\n");

		ret = dpu_region_init_data(&xeon_sp_translate, &data, chip_id);
		if (ret)
			return NULL;

		break;
#endif
#ifdef CONFIG_PPC64
	case DPU_BACKEND_POWER9:
		pr_info("dpu_region: Using power9 config\n");

		ret = dpu_region_init_data(&power9_translate, &data, chip_id);
		if (ret)
			return NULL;

		break;
#endif
	default:
		pr_err("dpu_region: Unknown backend\n");
		return NULL;
	}

	return data;
}

void dpu_region_free_data(struct dpu_region_data *region_data)
{
	kfree(region_data->addr_translate);
	kfree(region_data);
}

MODULE_ALIAS("dmi:*:svnUPMEM:*");
