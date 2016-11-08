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
#include <misc/printk.h>
#include <asm_inline.h>

#include "image_validate.h"

/*
 * This matches the ARM vector table.
 */
struct vector_table {
	uint32_t msp;
	uint32_t reset;
};

void main(void)
{
	typedef void jump_fn(void);
	struct vector_table *vt;
	jump_fn *fn;

	printk("Bootloader on %s\n", CONFIG_ARCH);

	if (bootutil_img_validate(0x08020000)) {
		printk("Image doesn't validate\n");
		while (1)
			;
	}

	vt = (struct vector_table *)0x08020000;
	printk("Initial MSP: %p\n", (void *)vt->msp);
	printk("      Reset: %p\n", (void *)vt->reset);

	_MspSet(vt->msp);
	fn = (jump_fn *)vt->reset;
	fn();
}
