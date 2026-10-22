/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "it51xxx_crypto.h"
#include "it51xxx_crypto_rsa.h"

union hwcrypto_dlm_block hwcrypto_dlm __attribute__((section(".__hwcrypto_dlm_block")));

psa_status_t it51xxx_hwcrypto_init(void)
{
	IT51XXX_LOG_DBG("%s ite debug %d", __func__, __LINE__);

	it51xxx_crypto_rsa_init();

	return PSA_SUCCESS;
}

psa_status_t it51xxx_hwcrypto_free(void)
{
	IT51XXX_LOG_DBG("%s ite debug %d", __func__, __LINE__);

	return PSA_SUCCESS;
}
