/*
 * Copyright (c) 2018 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <kernel.h>
#include <device.h>
#include <init.h>
#include <soc.h>
#include <flash.h>
#include <string.h>

/* TODO: Get this config value here. */
#define FLASH_OFFSET 0x10200000
#define FLASH_SIZE   0x00800000

static int flash_musca_read(struct device *dev, off_t offset,
			    void *data, size_t len)
{
	if (offset + len < offset && offset + len > FLASH_SIZE) {
		return -EINVAL;
	}

	uint32_t addr = offset + FLASH_OFFSET;
	memcpy(data, (void *)addr, len);
	return 0;
}

#if defined(CONFIG_FLASH_PAGE_LAYOUT)
static const struct flash_pages_layout dev_layout = {
	/* TODO: These are unknown, just guessing. */
	.pages_count = FLASH_SIZE / 4096,
	.pages_size = 4096,
};

static void flash_musca_pages_layout (struct device *dev,
				      const struct flash_pages_layout **layout,
				      size_t *layout_size)
{
	*layout = &dev_layout;
	*layout_size = 1;
}
#endif

static const struct flash_driver_api flash_musca_qpsi_api = {
	.read = flash_musca_read,
#if defined(CONFIG_FLASH_PAGE_LAYOUT)
	.page_layout = flash_musca_pages_layout,
#endif
};

static int flash_musca_init(struct device *dev)
{
	return 0;
}

DEVICE_AND_API_INIT(flash_musca_qpsi, FLASH_DEV_NAME,
		    flash_musca_init, NULL, NULL, POST_KERNEL,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE, &flash_musca_qpsi_api);
