/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

// Testing Rust entrypoint.
extern void foo(void);
extern uint32_t divide(uint32_t a, uint32_t b);

int main(void)
{
	printf("Hello World, from C! %s\n", CONFIG_BOARD);
	foo();
	printf("Division from rust: %d\n", divide(12345, 63));
	return 0;
}
