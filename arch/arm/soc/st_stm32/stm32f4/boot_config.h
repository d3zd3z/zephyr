/*
 * Copyright (c) 2016 Linaro Limited.
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

#ifndef __BOOT_CONFIG_H__
#define __BOOT_CONFIG_H__

#include <misc/util.h>

/** The flash device on the STM32F4. */
#define BOOT_FLASH_DEVICE "STM32F4_FLASH"

/** The offset of the flash in memory, in the CPUs address space. */
#define BOOT_FLASH_BASE 0x08000000

/*
 * The offset and size, from the base of the flash, of the primary
 * flash code segment.
 */
#define FLASH_PRIMARY_BASE  0x00020000
#define FLASH_PRIMARY_SIZE  KB(128)

/* The offset and size of the upgrade flash segment. */
#define FLASH_UPGRADE_BASE  0x00040000
#define FLASH_UPGRADE_SIZE  KB(128)

/* The offset and size of the scratch segment.  This initial
 * implementation assumes the segments are erased and flashed in their
 * entirety. */
/* #define FLASH_SCRATCH_BASE 0x00060000 */
/* #define FLASH_SCRATCH_SIZE KB(128) */

#endif /* __BOOT_CONFIG_H__ */
