/*
 * Copyright (c) 2016 Linaro Limited
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

#ifndef __CHAIN_BOOT_H__
#define __CHAIN_BOOT_H__

/**
 * @brief chain boot to another bootable image
 *
 * Given specified image address, attempt to jump to this image as if
 * the system was just booted.  Currently, this does not disable
 * interrupts, or perform any chip-level reset.  If any of this needs
 * to be done to jump from the bootloader to another image, this code
 * should be enhanced.
 *
 * This function does not return.  If the image is invalid, it will
 * likely just crash.
 */
FUNC_NORETURN void chain_boot(void *image);

#endif /* __CHAIN_BOOT_H__ */
