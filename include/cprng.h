/**
 * @file cprng.h
 *
 * @brief Public API for the Cryptographic Pseudo Random Number
 * Generator (CPRNG) API.
 */

/*
 * Copyright (c) 2018 Linaro Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_CPRNG_H_
#define ZEPHYR_INCLUDE_CPRNG_H_

/**
 * @brief Cryptographic Pseudo Random Number Generator (CPRNG)
 * Interface.
 * @defgroup cprng_interface CPRNG Interface
 * @ingroup io_interfaces
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr/types.h>
#include <device.h>

#error "No CPRNG backend selected"

/**
 * @brief Initialize the CPRNG structure.
 *
 * @param dev Pointer to cprng generator.
 * @retval 0 on success.
 * @retval -ERRNO errno code on error.
 */
int cprng_init(struct cprng_gen *gen);

/**
 * @brief Seed a CPRNG.
 *
 * Use the given entropy driver to seed this CPRNG.  Will use the
 * given entropy driver to seed this CPRNG with a sufficient amount of
 * entropy to begin producing pseudo-random data.
 *
 * @param dev Pointer to cprng device.
 * @param entropy Pointer to entropy device.
 * @retval 0 on success.
 * @retval -ERRNO errno code on error.
 */
int cprng_seed(struct cprng_gen *gen,
	       struct device *entropy);

/**
 * @brief Get pseudorandom data from the given CPRNG.
 *
 * Use the CPRNG to generate pseudorandom data.  This may return less
 * data than requested, depending on the underlying generator.
 *
 * @param dev Pointer to the cprng device.
 * @param buffer Buffer to fill with CPRNG data.
 * @param length Buffer length.
 * @retval number of bytes filled or -errno.
 */
int cprng_generate(struct cprng_gen *gen,
		   u8_t *buffer,
		   u16_t length);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_CPRNG_H_ */
