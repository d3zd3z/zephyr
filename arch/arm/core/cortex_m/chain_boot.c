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

#include <zephyr.h>
#include <asm_inline.h>

#include <boot/chain_boot.h>

/*
 * The beginning of the ARM vector table.
 */
struct vector_table {
	uint32_t msp;
	uint32_t reset;
};

FUNC_NORETURN void chain_boot(void *image)
{
	struct vector_table *vt;

	vt = (struct vector_table *)image;
	_MspSet(vt->msp);
	((void (*)(void))vt->reset)();

	/* If this somehow returns, just spin. */
	while (1)
		;
}
