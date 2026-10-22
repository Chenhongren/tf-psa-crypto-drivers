/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IT51XXX_UTIL_H__
#define IT51XXX_UTIL_H__

#include <limits.h>
#include <stdint.h>

/** @brief Convert @p x from KiB to bytes using a 32-bit unsigned value. */
#ifndef KB
#define KB(x) ((uint32_t)(x) << 10U)
#endif

/**
 * @brief Create an unsigned long mask with bit @p n set.
 *
 * @param n Bit index, less than the number of bits in unsigned long.
 */
#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

/** @brief Number of bits in one byte. */
#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE CHAR_BIT
#endif

/**
 * @brief Get the number of elements in @p array.
 *
 * @note The argument must be an array, not a pointer.
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

/**
 * @brief Create an unsigned long mask covering bits @p h through @p l, inclusive.
 *
 * @param h Highest bit index, less than the number of bits in unsigned long.
 * @param l Lowest bit index, satisfying 0 <= l <= h.
 */
#ifndef GENMASK
#define GENMASK(h, l) \
	((~0UL << (l)) & \
	 (~0UL >> ((sizeof(unsigned long) * CHAR_BIT - 1U) - (h))))
#endif

/** @brief Extract the least significant set bit. */
#ifndef LSB_GET
#define LSB_GET(value) \
	((unsigned long)(value) & (0UL - (unsigned long)(value)))
#endif

/** @brief Extract a bitfield from value. */
#ifndef FIELD_GET
#define FIELD_GET(mask, value) \
	(((unsigned long)(value) & (unsigned long)(mask)) / LSB_GET(mask))
#endif

/** @brief Position a value within the specified bitfield. */
#ifndef FIELD_PREP
#define FIELD_PREP(mask, value) \
	(((unsigned long)(value) * LSB_GET(mask)) & (unsigned long)(mask))
#endif

#endif /* IT51XXX_UTIL_H__ */
