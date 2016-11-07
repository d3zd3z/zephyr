/* Signed header definitions */

/*
 * Copyright (c) 2016, Linaro Limited
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

#ifndef __BOOT_SIGNATURE_HEADER_H__
#define __BOOT_SIGNATURE_HEADER_H__

#ifndef _ASMLANGUAGE

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Signature header
 *
 * Immediately follows the vector table, allowing the bootloader to
 * find an appended signature.
 */
struct signature_header {
	/** Magic numbers to identify the header. */
	uint32_t magic1;
	uint32_t magic2;

	uint32_t rom_start;
	uint32_t rom_end;
	uint32_t data_rom_start;
	uint32_t data_ram_start;
	uint32_t data_ram_end;
	uint32_t pad1;
};

#ifdef __cplusplus
}
#endif

#endif /* _ASMLANGUAGE */

/** First magic value for header. */
#define SIGNATURE_HEADER_MAGIC1 0xaac10398

/** Second magic value for header. */
#define SIGNATURE_HEADER_MAGIC2 0xceab962c

/** Offset of the signature header from the start of the image.
 * Should be the size of the boot header.
 */
#define SIGNATURE_HEADER_OFFSET 0x40

#endif /* __BOOT_SIGNATURE_HEADER_H__ */
