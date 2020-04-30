/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>

#include "dpu_rank.h"
#include "dpu_control_interface.h"
#include "dpu_mcu_ci_commands.h"
#include "dpu_mcu_ci_protocol.h"

/* dpu_rank attributes */
static ssize_t is_owned_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rank->owner.is_owned);
}

static ssize_t usage_count_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rank->owner.usage_count);
}

static ssize_t id_in_region_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rank->id_in_region);
}

static ssize_t trace_command_mask_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", rank->trace_command_mask);
}

static ssize_t trace_command_mask_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t len)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);
	uint8_t tmp;
	int ret;

	ret = kstrtou8(buf, 10, &tmp);
	if (ret)
		return ret;

	rank->trace_command_mask = tmp;

	return len;
}

static ssize_t mcu_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", rank->mcu_version);
}

static ssize_t fck_frequency_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", rank->fck_frequency);
}

static ssize_t clock_division_min_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", rank->clock_division_min);
}

static ssize_t clock_division_max_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", rank->clock_division_max);
}

static ssize_t rank_index_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", rank->rank_index);
}

static ssize_t part_number_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", rank->part_number);
}

static ssize_t serial_number_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", rank->serial_number);
}

static ssize_t signal_led_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t len)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);
	struct ec_params_signal signal;
	int ret;

	ret = kstrtou8(buf, 10, &signal.on_off);
	if (ret)
		return ret;

	ret = dpu_control_interface_mcu_command(
		rank, EC_CMD_DIMM_SIGNAL, 0, &signal, sizeof(signal), NULL, 0);
	if (ret < 0) {
		dev_warn(&rank->dev, "fail to send signal command to MCU\n");
		return ret;
	}

	return len;
}

static DEVICE_ATTR_RO(is_owned);
static DEVICE_ATTR_RO(usage_count);
static DEVICE_ATTR_RO(id_in_region);
static DEVICE_ATTR_RW(trace_command_mask);
static DEVICE_ATTR_RO(mcu_version);
static DEVICE_ATTR_RO(fck_frequency);
static DEVICE_ATTR_RO(clock_division_min);
static DEVICE_ATTR_RO(clock_division_max);
static DEVICE_ATTR_RO(rank_index);
static DEVICE_ATTR_RO(part_number);
static DEVICE_ATTR_RO(serial_number);
static DEVICE_ATTR_WO(signal_led);

static struct attribute *dpu_rank_attrs[] = {
	&dev_attr_is_owned.attr,
	&dev_attr_usage_count.attr,
	&dev_attr_id_in_region.attr,
	&dev_attr_trace_command_mask.attr,
	&dev_attr_mcu_version.attr,
	&dev_attr_fck_frequency.attr,
	&dev_attr_clock_division_min.attr,
	&dev_attr_clock_division_max.attr,
	&dev_attr_rank_index.attr,
	&dev_attr_part_number.attr,
	&dev_attr_serial_number.attr,
	&dev_attr_signal_led.attr,
	NULL,
};

static struct attribute_group dpu_rank_attrs_group = {
	.attrs = dpu_rank_attrs,
};

const struct attribute_group *dpu_rank_attrs_groups[] = { &dpu_rank_attrs_group,
							  NULL };

/* Control interface attributes */
struct ci_attribute {
	struct attribute attr;
	uint8_t ci_id, dpu_id;
	ssize_t (*show)(struct device *codec, struct ci_attribute *attr,
			char *buf);
	ssize_t (*store)(struct device *codec, struct ci_attribute *attr,
			 const char *buf, size_t count);
};

static struct ci_attribute *
get_ci_attribute_from_attribute(struct device *dev, struct attribute *get_attr)
{
	struct ci_attribute *ci_attr =
		container_of(get_attr, struct ci_attribute, attr);

	return ci_attr;
}

static ssize_t command_store(struct device *dev, struct ci_attribute *ci_attr,
			     const char *buf, size_t len)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);
	struct dpu_region_address_translation *tr;
	uint64_t *command, tmp;
	uint32_t size_command;
	int ret = 0;
	uint8_t nb_cis;

	dev_info(dev, "command to region_id = %u, rank_id = %u, ci_id = %u\n",
		 rank->region->id, rank->id_in_region, ci_attr->ci_id);

	ret = kstrtou64(buf, 0, &tmp);
	if (ret)
		return ret;

	tr = rank->region->pdata->addr_translate;
	nb_cis = tr->interleave->nb_ci;
	size_command = sizeof(uint64_t) * nb_cis;

	command = kzalloc(size_command, GFP_KERNEL);
	if (!command)
		return -ENOMEM;

	command[ci_attr->ci_id] = tmp;

	mutex_lock(&rank->ci_lock);
	tr->write_to_cis(tr, rank->region->base, rank->channel_id,
			 rank->id_in_region, command, size_command);
	mutex_unlock(&rank->ci_lock);

	kfree(command);

	return len;
}

static ssize_t is_running_show(struct device *dev, struct ci_attribute *ci_attr,
			       char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);

	dev_info(dev,
		 "command to region_id = %u, rank_id = %u, ci_id = %u, "
		 "dpu_id = %u\n",
		 rank->region->id, rank->id_in_region, ci_attr->ci_id,
		 ci_attr->dpu_id);

	return sprintf(buf, "%d\n", 0);
}

static ssize_t x86_mram_access_show(struct device *dev,
				    struct ci_attribute *ci_attr, char *buf)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);
	int mux_mram;

	dev_info(dev,
		 "x86 mram show to region_id = %u, rank_id = %u, ci_id = %u, "
		 "dpu_id = %u\n",
		 rank->region->id, rank->id_in_region, ci_attr->ci_id,
		 ci_attr->dpu_id);

	mux_mram = dpu_control_interface_check_mux(rank, ci_attr->dpu_id,
						   ci_attr->dpu_id);

	return sprintf(buf, "%d\n", mux_mram == 0x0 ? 1 : 0);
}

static ssize_t x86_mram_access_store(struct device *dev,
				     struct ci_attribute *ci_attr,
				     const char *buf, size_t len)
{
	struct dpu_rank *rank = dev_get_drvdata(dev);
	uint8_t tmp;
	int ret;

	ret = kstrtou8(buf, 10, &tmp);
	if (ret)
		return ret;

	dev_info(
		dev,
		"x86 mram store %d to region_id = %u, rank_id = %u, ci_id = %u, "
		"dpu_id = %u\n",
		tmp, rank->region->id, rank->id_in_region, ci_attr->ci_id,
		ci_attr->dpu_id);

	if (tmp)
		dpu_control_interface_get_access_to_mram(rank, ci_attr->dpu_id,
							 ci_attr->ci_id);
	else
		dpu_control_interface_release_access_to_mram(
			rank, ci_attr->dpu_id, ci_attr->ci_id);

	return len;
}

static ssize_t ci_attr_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	struct ci_attribute *ci_attr;
	struct device *dev = container_of(kobj->parent, struct device, kobj);

	ci_attr = get_ci_attribute_from_attribute(dev, attr);

	if (!ci_attr->show)
		return -EIO;

	return ci_attr->show(dev, ci_attr, buf);
}

static ssize_t ci_attr_store(struct kobject *kobj, struct attribute *attr,
			     const char *buf, size_t count)
{
	struct ci_attribute *ci_attr;
	struct device *dev = container_of(kobj->parent, struct device, kobj);

	ci_attr = get_ci_attribute_from_attribute(dev, attr);

	if (!ci_attr->store)
		return -EIO;

	return ci_attr->store(dev, ci_attr, buf, count);
}

static const struct sysfs_ops ci_sysfs_ops = {
	.show = ci_attr_show,
	.store = ci_attr_store,
};

static int get_ci_attrs(struct device *dev, struct kobject *kobj, uint8_t ci_id,
			uint8_t nb_dpus)
{
	struct attribute_group *attrs_group;
	struct attribute **ci_attrs;
	struct ci_attribute *ci_attr;
	int ret, i;

	ci_attrs =
		devm_kzalloc(dev, 2 * sizeof(struct attribute *), GFP_KERNEL);
	if (!ci_attrs)
		return -ENOMEM;

	ci_attr = devm_kzalloc(dev, sizeof(struct ci_attribute), GFP_KERNEL);
	if (!ci_attr)
		return -ENOMEM;

	ci_attr->attr.name = "command";
	ci_attr->attr.mode = 0200;
	ci_attr->store = command_store;
	ci_attr->ci_id = ci_id;
	ci_attr->dpu_id = 0xFF;

	ci_attrs[0] = &ci_attr->attr;
	ci_attrs[1] = NULL;

	attrs_group =
		devm_kzalloc(dev, sizeof(struct attribute_group), GFP_KERNEL);
	if (!attrs_group)
		return -ENOMEM;

	attrs_group->attrs = ci_attrs;

	ret = sysfs_create_group(kobj, attrs_group);
	if (ret < 0) {
		kobject_put(kobj);
		return ret;
	}

	for (i = 0; i < nb_dpus; ++i) {
		ci_attr = devm_kzalloc(dev, 2 * sizeof(struct ci_attribute),
				       GFP_KERNEL);
		if (!ci_attr)
			return -ENOMEM;

		ci_attr[0].attr.name = "is_running";
		ci_attr[0].attr.mode = 0444;
		ci_attr[0].show = is_running_show;
		ci_attr[0].ci_id = ci_id;
		ci_attr[0].dpu_id = i;

		ci_attr[1].attr.name = "x86_mram_access";
		ci_attr[1].attr.mode = 0644;
		ci_attr[1].show = x86_mram_access_show;
		ci_attr[1].store = x86_mram_access_store;
		ci_attr[1].ci_id = ci_id;
		ci_attr[1].dpu_id = i;

		ci_attrs[0] = &ci_attr[0].attr;
		ci_attrs[1] = &ci_attr[1].attr;
		ci_attrs[2] = NULL;

		attrs_group = devm_kzalloc(dev, sizeof(struct attribute_group),
					   GFP_KERNEL);
		if (!attrs_group)
			return -ENOMEM;

		attrs_group->attrs = ci_attrs;
		attrs_group->name = devm_kzalloc(dev, 8, GFP_KERNEL);
		if (!attrs_group->name)
			return -ENOMEM;
		sprintf((char *)attrs_group->name, "dpu%hhu", i);

		ret = sysfs_create_group(kobj, attrs_group);
		if (ret < 0) {
			kobject_put(kobj);
			return ret;
		}
	}

	return 0;
}

void ci_sysfs_release(struct kobject *kobj)
{
}

struct kobj_type ci_ktype = { .release = ci_sysfs_release,
			      .sysfs_ops = &ci_sysfs_ops };

int dpu_rank_sysfs_create(struct device *dev, struct dpu_rank *rank)
{
	uint8_t nb_ci, nb_dpus_per_ci;
	uint8_t i;
	int ret;

	nb_ci = rank->region->pdata->addr_translate->interleave->nb_ci;
	nb_dpus_per_ci =
		rank->region->pdata->addr_translate->interleave->nb_dpus_per_ci;

	for (i = 0; i < nb_ci; ++i) {
		struct kobject *kobj_ci = &rank->kobj_ci[i];

		kobject_init(kobj_ci, &ci_ktype);
		ret = kobject_add(kobj_ci, &dev->kobj, "ci%hhu", i);
		if (ret < 0) {
			for (i--; i >= 0; --i)
				kobject_put(&rank->kobj_ci[i]);
			return ret;
		}

		ret = get_ci_attrs(dev, kobj_ci, i, nb_dpus_per_ci);
		if (ret) {
			for (; i >= 0; --i)
				kobject_put(&rank->kobj_ci[i]);
			return ret;
		}
	}

	return 0;
}
