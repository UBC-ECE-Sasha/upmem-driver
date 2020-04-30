/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/kernel.h>
#include <linux/device.h>

#include "dpu_region.h"
#include "dpu_rank.h"

static ssize_t nb_ranks_per_dimm_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t nb_ranks_per_dimm;

	translate = region->pdata->addr_translate;
	nb_ranks_per_dimm = translate->interleave->nb_ranks_per_dimm;

	return sprintf(buf, "%d\n", nb_ranks_per_dimm);
}

static ssize_t nb_dimms_per_channel_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t nb_dimms_per_channel;

	translate = region->pdata->addr_translate;
	nb_dimms_per_channel = translate->interleave->nb_dimms_per_channel;

	return sprintf(buf, "%d\n", nb_dimms_per_channel);
}

static ssize_t nb_channels_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t nb_channels;

	translate = region->pdata->addr_translate;
	nb_channels = translate->interleave->nb_channels;

	return sprintf(buf, "%d\n", nb_channels);
}

static ssize_t nb_ci_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t nb_ci;

	translate = region->pdata->addr_translate;
	nb_ci = translate->interleave->nb_ci;

	return sprintf(buf, "%d\n", nb_ci);
}

static ssize_t ci_mapping_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	ssize_t ret = 0;
	int i;

	translate = region->pdata->addr_translate;

	for (i = 0; i < translate->interleave->nb_ci; ++i)
		ret += sprintf(buf + strlen(buf), "%d ",
			       translate->interleave->ci_mapping[i]);

	strcat(buf, "\n");

	return ret + 1;
}

static ssize_t nb_real_ci_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t nb_real_ci;

	translate = region->pdata->addr_translate;
	nb_real_ci = translate->interleave->nb_real_ci;

	return sprintf(buf, "%d\n", nb_real_ci);
}

static ssize_t nb_dpus_per_ci_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t nb_dpus_per_ci;

	translate = region->pdata->addr_translate;
	nb_dpus_per_ci = translate->interleave->nb_dpus_per_ci;

	return sprintf(buf, "%d\n", nb_dpus_per_ci);
}

static ssize_t mram_size_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint32_t mram_size;

	translate = region->pdata->addr_translate;
	mram_size = translate->interleave->mram_size;

	return sprintf(buf, "%d\n", mram_size);
}

static ssize_t channel_line_size_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t channel_line_size;

	translate = region->pdata->addr_translate;
	channel_line_size = translate->interleave->channel_line_size;

	return sprintf(buf, "%d\n", channel_line_size);
}

static ssize_t rank_line_size_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t rank_line_size;

	translate = region->pdata->addr_translate;
	rank_line_size = translate->interleave->rank_line_size;

	return sprintf(buf, "%d\n", rank_line_size);
}

static ssize_t dpu_chip_id_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%llu\n", region->pdata->dpu_chip_id);
}

static ssize_t backend_id_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint8_t backend_id;

	translate = region->pdata->addr_translate;
	backend_id = translate->backend_id;

	return sprintf(buf, "%hhu\n", backend_id);
}

static ssize_t mode_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->pdata->mode);
}

static ssize_t mode_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	int ret, i;
	uint8_t tmp, nb_ranks, nb_dimms, nb_ranks_per_dimm;

	ret = kstrtou8(buf, 10, &tmp);
	if (ret)
		return ret;

	if (tmp != DPU_REGION_MODE_PERF && tmp != DPU_REGION_MODE_SAFE) {
		dev_err(dev, "mode: value %u is undefined\n", tmp);
		return -EINVAL;
	}

	spin_lock(&region->lock);
	/* In perf mode, one can access rank through dpu_rank devices too:
	 * switch from safe to perf is possible iff no ranks is allocated.
	 * switch from perf to safe is possible iff see below
	 */

	translate = region->pdata->addr_translate;
	nb_dimms = translate->interleave->nb_channels *
		   translate->interleave->nb_dimms_per_channel;
	nb_ranks_per_dimm = translate->interleave->nb_ranks_per_dimm;

	if (region->pdata->mode == DPU_REGION_MODE_SAFE &&
	    tmp == DPU_REGION_MODE_PERF) {
		nb_ranks = nb_dimms * nb_ranks_per_dimm;
		for (i = 0; i < nb_ranks; ++i) {
			struct dpu_rank *rank = &region->ranks[i];

			if (rank->owner.is_owned) {
				dev_err(dev,
					"dpu_rank %u is allocated in safe "
					"mode, can't switch to perf mode.\n",
					i);
				spin_unlock(&region->lock);
				return -EBUSY;
			}
		}
	} else if (region->pdata->mode == DPU_REGION_MODE_PERF &&
		   tmp == DPU_REGION_MODE_SAFE) {
		// TODO
		// 1/ find a way to get a refcount on dax device
		// 2/ find a way to deny access to dax mmap...
	}

	region->pdata->mode = tmp;

	spin_unlock(&region->lock);

	return len;
}

static ssize_t debug_mode_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%hhu\n", region->debug_mode);
}

static ssize_t debug_mode_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t len)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	int ret;
	uint8_t tmp;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtou8(buf, 10, &tmp);
	if (ret)
		return ret;

	spin_lock(&region->lock);

	region->debug_mode = tmp;

	spin_unlock(&region->lock);

	return len;
}

static ssize_t numa_node_id_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->pdata->numa_node_id);
}

static ssize_t region_id_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", region->id);
}

static ssize_t capabilities_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct dpu_region *region = dev_get_drvdata(dev);
	struct dpu_region_address_translation *translate;
	uint64_t capabilities;

	translate = region->pdata->addr_translate;
	capabilities = translate->capabilities;

	return sprintf(buf, "%#llx\n", capabilities);
}

static DEVICE_ATTR_RO(ci_mapping);
static DEVICE_ATTR_RO(nb_real_ci);
static DEVICE_ATTR_RO(nb_ci);
static DEVICE_ATTR_RO(nb_dpus_per_ci);
static DEVICE_ATTR_RO(mram_size);
static DEVICE_ATTR_RO(rank_line_size);
static DEVICE_ATTR_RO(channel_line_size);
static DEVICE_ATTR_RO(nb_ranks_per_dimm);
static DEVICE_ATTR_RO(nb_dimms_per_channel);
static DEVICE_ATTR_RO(nb_channels);
static DEVICE_ATTR_RO(dpu_chip_id);
static DEVICE_ATTR_RO(backend_id);
static DEVICE_ATTR_RW(mode);
static DEVICE_ATTR_RW(debug_mode);
static DEVICE_ATTR_RO(numa_node_id);
static DEVICE_ATTR_RO(region_id);
static DEVICE_ATTR_RO(capabilities);

static struct attribute *dpu_region_data_attrs[] = {
	&dev_attr_ci_mapping.attr,
	&dev_attr_nb_real_ci.attr,
	&dev_attr_nb_ci.attr,
	&dev_attr_nb_dpus_per_ci.attr,
	&dev_attr_mram_size.attr,
	&dev_attr_rank_line_size.attr,
	&dev_attr_channel_line_size.attr,
	&dev_attr_nb_ranks_per_dimm.attr,
	&dev_attr_nb_dimms_per_channel.attr,
	&dev_attr_nb_channels.attr,
	&dev_attr_dpu_chip_id.attr,
	&dev_attr_backend_id.attr,
	&dev_attr_mode.attr,
	&dev_attr_debug_mode.attr,
	&dev_attr_numa_node_id.attr,
	&dev_attr_region_id.attr,
	&dev_attr_capabilities.attr,
	NULL,
};

static const struct attribute_group dpu_region_data_attrs_group = {
	.attrs = dpu_region_data_attrs,
};

int dpu_region_sysfs_create(struct device *dev)
{
	return sysfs_create_group(&dev->kobj, &dpu_region_data_attrs_group);
}

void dpu_region_sysfs_remove(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &dpu_region_data_attrs_group);
}
