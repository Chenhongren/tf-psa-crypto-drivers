/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IT51XXX_CRYPTO_H
#define IT51XXX_CRYPTO_H

/**
 * @file it51xxx_crypto.h
 *
 * Public API for IT51XXX Crypto driver
 */

#include "it51xxx_log.h"
#include "it51xxx_util.h"
#include "psa/crypto.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Size of the shared hardware crypto DLM region in bytes. */
#define IT51XXX_HWCRYPTO_DLM_SIZE KB(4)

/** Minimum RSA operand length in bytes. */
#define IT51XXX_HWCRYPTO_RSA_MIN_BYTE_LEN 64
/** Maximum RSA operand length in bytes. */
#define IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN 512 /* 512 bytes (4096 bits) */

/**
 * @brief RSA DLM layout.
 *
 * Field offsets correspond to the hardware-defined layout within
 * the 4 KiB DLM region.
 */
struct it51xxx_rsa_dlm {
	/** Public key data at offsets 0x000–0x1FF. */
	uint8_t key_public[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
	/** Reserved region at offsets 0x200–0x3FF. */
	uint8_t reserved_1[512];
	/** Message data at offsets 0x400–0x5FF. */
	uint8_t messages[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
	/** Reserved region at offsets 0x600–0x9FF. */
	uint8_t reserved_2[1024];
	/** Private key data at offsets 0xA00–0xBFF. */
	uint8_t key_private[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
	/** Reserved region at offsets 0xC00–0xFFF. */
	uint8_t reserved_3[1024];
};

/**
 * @brief Shared DLM storage for it51xxx hardware crypto algorithms.
 *
 * SHA, RSA, and other crypto algorithms share the same 4 KiB DLM
 * memory region. Union members use the same underlying storage,
 * so access must be serialized.
 */
union hwcrypto_dlm_block {
	/** RSA DLM data. */
	struct it51xxx_rsa_dlm rsa;
	/** Raw access to the entire shared DLM region. */
	uint8_t raw_data[IT51XXX_HWCRYPTO_DLM_SIZE];
};

/**
 * @brief Shared DLM instance used by it51xxx hardware crypto algorithms.
 */
extern union hwcrypto_dlm_block hwcrypto_dlm;

/**
 *@brief Initialize shared hardware crypto resources.
 *
 * Call before starting any hardware crypto operation.
 *
 * @return  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t it51xxx_hwcrypto_init(void);

/**
 *@brief Release shared hardware crypto resources.
 *
 * Call only after all hardware crypto operations have completed.
 *
 * @return  PSA_SUCCESS on success. Error code from \ref psa_status_t on
 *          failure
 */
psa_status_t it51xxx_hwcrypto_free(void);

#ifdef __cplusplus
}
#endif

#endif /* IT51XXX_CRYPTO_H */
