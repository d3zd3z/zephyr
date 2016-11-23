/*
 * Copyright (C) 2016 Linaro Limited
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <zephyr.h>
#include <flash.h>
#include <device.h>
#include <misc/printk.h>
#include <boot_config.h>

#include <boot/update.h>
#include <boot/image_validate.h>

/*
 * This implementation uses a primary and an upgrade flash segment.
 * If a valid image is found in the upgrade segment, it will be moved
 * into the primary image.  In either case, we will try booting the
 * primary image, as long as it contains an image.
 */
void *boot_find_image(struct device *flash_dev)
{
	int primary_good;
	int upgrade_good;
	int rc;

	primary_good = bootutil_img_validate(FLASH_PRIMARY_BASE +
					     BOOT_FLASH_BASE);
	printk("primary good: %d\n", primary_good);

	upgrade_good = bootutil_img_validate(FLASH_UPGRADE_BASE +
					     BOOT_FLASH_BASE);
	printk("upgrade good: %d\n", upgrade_good);

	/*
	 * If there is a valid update image, start the process of
	 * loading it into the primary segment.  This step can be
	 * interrupted at any time, because we will not have erased
	 * the upgrade segment.
	 */
	if (upgrade_good == 0) {
		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return NO_BOOT_IMAGE;
		}

		/*
		 * TODO: Add support for small sectors.  Right now, we
		 * assume the entire segment is a single erasable
		 * region.  In the simple case, this should erase the
		 * entire region.
		 */
		printk("Upgrade: Erasing primary segment\n");
		rc = flash_erase(flash_dev, FLASH_PRIMARY_BASE,
				 FLASH_PRIMARY_SIZE);
		if (rc != 0) {
			printk("Error erasing primary segment\n");
			return NO_BOOT_IMAGE;
		}

		/*
		 * It is device specific whether it is possible to
		 * read from segments other than the one we are
		 * writing to.  For now, just support the simple case
		 * where that is possible.
		 */
		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return NO_BOOT_IMAGE;
		}

		printk("Upgrade: Writing code in primary segment\n");
		rc = flash_write(flash_dev, FLASH_PRIMARY_BASE,
				 (void *)(FLASH_UPGRADE_BASE + BOOT_FLASH_BASE),
				 FLASH_PRIMARY_SIZE);
		if (rc != 0) {
			printk("Error writing primary segment\n");
			return NO_BOOT_IMAGE;
		}

		/*
		 * Now that the primary segment has been written, it
		 * is safe to erase the upgrade segment.
		 *
		 * TODO: Perhaps we should verify the signature of the
		 * boot segment.
		 */
		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return NO_BOOT_IMAGE;
		}

		printk("Upgrade: Erasing upgrade\n");
		rc = flash_erase(flash_dev, FLASH_UPGRADE_BASE,
				 FLASH_UPGRADE_SIZE);
		if (rc != 0) {
			printk("Error erasing upgrade segment\n");
			return NO_BOOT_IMAGE;
		}

		/*
		 * Rescan the primary image.  If it is now corrupt, it
		 * means something went wrong with flashing, and we
		 * would need to initiate recovery.
		 */
		primary_good = bootutil_img_validate(FLASH_PRIMARY_BASE +
						     BOOT_FLASH_BASE);
		upgrade_good = -1;
	}

	if (primary_good == 0) {
		return (void *)(FLASH_PRIMARY_BASE + BOOT_FLASH_BASE);
	} else {
		return NO_BOOT_IMAGE;
	}
}
