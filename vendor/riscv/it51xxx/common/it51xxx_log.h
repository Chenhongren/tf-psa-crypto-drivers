/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IT51XXX_LOG_H__
#define IT51XXX_LOG_H__

#include <stddef.h>
#include <stdio.h>

#ifndef IT51XXX_LOG_DBG
#define IT51XXX_LOG_DBG(...)                                                                           \
	do {                                                                                       \
		printf("[DBG] ");                                                                  \
		printf(__VA_ARGS__);                                                               \
		printf("\n");                                                                      \
	} while (0)
#endif /* IT51XXX_LOG_DBG */

#ifndef IT51XXX_LOG_ERR
#define IT51XXX_LOG_ERR(...)                                                                           \
	do {                                                                                       \
		printf("[ERR] ");                                                                  \
		printf(__VA_ARGS__);                                                               \
		printf("\n");                                                                      \
	} while (0)
#endif /* IT51XXX_LOG_ERR */

static inline void it51xxx_log_hexdump(const char *level, const void *data, size_t len,
				   const char *message)
{
	const unsigned char *bytes = (const unsigned char *)data;

	printf("[%s] %s (%zu bytes)\n", level, message ? message : "", len);

	for (size_t i = 0; i < len; ++i) {
		printf("%02X", (unsigned int)bytes[i]);

		if ((i + 1U) % 16U == 0U || i + 1U == len) {
			printf("\n");
		} else {
			printf(" ");
		}
	}
}

#ifndef IT51XXX_LOG_HEXDUMP_ERR
#define IT51XXX_LOG_HEXDUMP_ERR(data, len, message)                                                    \
	do {                                                                                       \
		it51xxx_log_hexdump("ERR", (data), (len), (message));                                  \
	} while (0)
#endif

#ifndef IT51XXX_LOG_HEXDUMP_DBG
#define IT51XXX_LOG_HEXDUMP_DBG(data, len, message)                                                    \
	do {                                                                                       \
		it51xxx_log_hexdump("DBG", (data), (len), (message));                                  \
	} while (0)
#endif

#endif /* IT51XXX_LOG_H__ */
