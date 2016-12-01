/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <zephyr.h>
#include <flash.h>
#include <device.h>
#include <misc/printk.h>
#include <asm_inline.h>

#include <boot_config.h>
#include <boot/update.h>
#include <boot/chain_boot.h>
#include <boot/flash_map.h>
#include <boot/loader.h>

/* TODO: Basic configuration for Carbon 96b flash.
 */
static const struct flash_area flash_areas[] = {
	{
		.fa_flash_id = FLASH_AREA_BOOTLOADER,
		.fa_off = 0,
		.fa_size = 128*1024,
	},
	{
		.fa_flash_id = FLASH_AREA_IMAGE_0,
		.fa_off = 128*1024,
		.fa_size = 128*1024,
	},
	{
		.fa_flash_id = FLASH_AREA_IMAGE_1,
		.fa_off = 2*128*1024,
		.fa_size = 128*1024,
	},
	{
		.fa_flash_id = FLASH_AREA_IMAGE_SCRATCH,
		.fa_off = 3*128*1024,
		.fa_size = 128*1024,
	},
	{
		.fa_size = 0,
	},
};

static const uint8_t slot_areas[] = { 1, 2, 3 };
static const struct boot_req carbon_req = {
	.br_area_descs = flash_areas,
	.br_slot_areas = slot_areas,
	.br_scratch_area_idx = 2,
	.br_img_sz = 128*1024,
};


void main(void)
{
	struct device *flash_dev;
	/* void *base; */
	struct boot_rsp rsp;
	int res;

	printk("------------------------------------------------------------\n");
	printk("Bootloader on %s\n", CONFIG_ARCH);

	flash_dev = device_get_binding(BOOT_FLASH_DEVICE);
	if (!flash_dev) {
		printk(BOOT_FLASH_DEVICE " flash device not found\n");
		while (1)
			;
	}

	res = boot_go(flash_dev, &carbon_req, &rsp);
	if (res) {
		printk("Failed to find bootable image\n");
		while (1)
			;
	}

	printk("Boot: 0x%x\n", rsp.br_image_addr);
	chain_boot((void *) (rsp.br_image_addr + BOOT_FLASH_BASE));

#if 0
	/*
	 * Determine if there is a bootable image.
	 */
	base = boot_find_image(flash_dev);
	printk("Boot: %p\n", base);
	chain_boot(base);
#endif
}
