/*
 * Copyright (c) 2026 ITE Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "it51xxx_chipreg.h"
#include "it51xxx_crypto.h"
#include "it51xxx_crypto_rsa.h"

#include "tf-psa-crypto/build_info.h"
#include "psa_crypto_core.h"
#include "psa_crypto_rsa.h"
#include <mbedtls/private/error_common.h>
#include <mbedtls/private/rsa.h>
#include <mbedtls/platform.h>

#include "mbedtls/psa_util.h"

#include <stdbool.h>
#include <string.h>
#include <stddef.h>

#define rsa_dlm (hwcrypto_dlm.rsa)

#define RSA_ENABLE             BIT(7)
#define RSA_EXPONENT_MASK      GENMASK(5, 4)
#define RSA_EXPONENT_SELECT(n) FIELD_PREP(GENMASK(5, 4), n)
#define RSA_INTERRUPT_ENABLE   BIT(1)
#define RSA_CLOCK_ENABLE       BIT(0)

#define RSA_PUBLIC_MODULUS_LENGTH_DIVISOR 32U
#define PUBLIC_MODULUS_LENGTH(n)          (n / RSA_PUBLIC_MODULUS_LENGTH_DIVISOR)

#define RSA_CALCULATION_START BIT(7)
#define RSA_CALCULATION_DONE  BIT(1)
#define RSA_BUSY              BIT(0)

#define RSA_BASE_ADDR_LB(n) FIELD_PREP(GENMASK(7, 4), n)

#define RSA_BASE_ADDR_HB(n) FIELD_PREP(GENMASK(1, 0), n)

static const uint32_t it51xxx_rsa_supported_exponents[] = {3U, 65537U};

enum it51xxx_rsa_key_select {
	KEY_PUBLIC_EXP_65537 = 0,
	KEY_PUBLIC_EXP_3,
	KEY_PRIVATE,
	KEY_RESERVED,
};

extern int mbedtls_oid_get_oid_by_md(mbedtls_md_type_t md_alg, const char **oid, size_t *olen);

/* Decode the hash algorithm from alg and store the mbedtls encoding in
 * md_alg. Verify that the hash length is acceptable. */
psa_status_t psa_rsa_decode_md_type(psa_algorithm_t alg, size_t hash_length,
				    mbedtls_md_type_t *md_alg)
{
	psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
	*md_alg = mbedtls_md_type_from_psa_alg(hash_alg);

	/* The Mbed TLS RSA module uses an unsigned int for hash length
	 * parameters. Validate that it fits so that we don't risk an
	 * overflow later. */
#if SIZE_MAX > UINT_MAX
	if (hash_length > UINT_MAX) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
#endif

	/* For signatures using a hash, the hash length must be correct. */
	if (alg != PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
		if (*md_alg == MBEDTLS_MD_NONE) {
			return PSA_ERROR_NOT_SUPPORTED;
		}
		if (mbedtls_md_get_size_from_type(*md_alg) != hash_length) {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	return PSA_SUCCESS;
}

/* Construct a PKCS v1.5 encoding of a hashed message
 *
 * This is used both for signature generation and verification.
 *
 * Parameters:
 * - md_alg:  Identifies the hash algorithm used to generate the given hash;
 *            MBEDTLS_MD_NONE if raw data is signed.
 * - hashlen: Length of hash in case hashlen is MBEDTLS_MD_NONE.
 * - hash:    Buffer containing the hashed message or the raw data.
 * - dst_len: Length of the encoded message.
 * - dst:     Buffer to hold the encoded message.
 *
 * Assumptions:
 * - hash has size hashlen if md_alg == MBEDTLS_MD_NONE.
 * - hash has size corresponding to md_alg if md_alg != MBEDTLS_MD_NONE.
 * - dst points to a buffer of size at least dst_len.
 *
 */
int rsa_rsassa_pkcs1_v15_encode(mbedtls_md_type_t md_alg, unsigned int hashlen,
				const unsigned char *hash, size_t dst_len, unsigned char *dst)
{
	size_t oid_size = 0;
	size_t nb_pad = dst_len;
	unsigned char *p = dst;
	const char *oid = NULL;

	/* Are we signing hashed or raw data? */
	if (md_alg != MBEDTLS_MD_NONE) {
		unsigned char md_size = mbedtls_md_get_size_from_type(md_alg);
		if (md_size == 0) {
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
		}

		if (mbedtls_oid_get_oid_by_md(md_alg, &oid, &oid_size) != 0) {
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
		}

		if (hashlen != md_size) {
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
		}

		/* Double-check that 8 + hashlen + oid_size can be used as a
		 * 1-byte ASN.1 length encoding and that there's no overflow. */
		if (8 + hashlen + oid_size >= 0x80 || 10 + hashlen < hashlen ||
		    10 + hashlen + oid_size < 10 + hashlen) {
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
		}

		/*
		 * Static bounds check:
		 * - Need 10 bytes for five tag-length pairs.
		 *   (Insist on 1-byte length encodings to protect against variants of
		 *    Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
		 * - Need hashlen bytes for hash
		 * - Need oid_size bytes for hash alg OID.
		 */
		if (nb_pad < 10 + hashlen + oid_size) {
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
		}
		nb_pad -= 10 + hashlen + oid_size;
	} else {
		if (nb_pad < hashlen) {
			return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
		}

		nb_pad -= hashlen;
	}

	/* Need space for signature header and padding delimiter (3 bytes),
	 * and 8 bytes for the minimal padding */
	if (nb_pad < 3 + 8) {
		return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
	}
	nb_pad -= 3;

	/* Now nb_pad is the amount of memory to be filled
	 * with padding, and at least 8 bytes long. */

	/* Write signature header and padding */
	*p++ = 0;
	*p++ = MBEDTLS_RSA_SIGN;
	memset(p, 0xFF, nb_pad);
	p += nb_pad;
	*p++ = 0;

	/* Are we signing raw data? */
	if (md_alg == MBEDTLS_MD_NONE) {
		memcpy(p, hash, hashlen);
		return 0;
	}

	/* Signing hashed data, add corresponding ASN.1 structure
	 *
	 * DigestInfo ::= SEQUENCE {
	 *   digestAlgorithm DigestAlgorithmIdentifier,
	 *   digest Digest }
	 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	 * Digest ::= OCTET STRING
	 *
	 * Schematic:
	 * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
	 *                                 TAG-NULL + LEN [ NULL ] ]
	 *                 TAG-OCTET + LEN [ HASH ] ]
	 */
	*p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char)(0x08 + oid_size + hashlen);
	*p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char)(0x04 + oid_size);
	*p++ = MBEDTLS_ASN1_OID;
	*p++ = (unsigned char)oid_size;
	memcpy(p, oid, oid_size);
	p += oid_size;
	*p++ = MBEDTLS_ASN1_NULL;
	*p++ = 0x00;
	*p++ = MBEDTLS_ASN1_OCTET_STRING;
	*p++ = (unsigned char)hashlen;
	memcpy(p, hash, hashlen);
	p += hashlen;

	/* Just a sanity-check, should be automatic
	 * after the initial bounds check. */
	if (p != dst + dst_len) {
		mbedtls_platform_zeroize(dst, dst_len);
		return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
	}

	return 0;
}

static inline int it51xxx_crypto_rsa_exp_valid(const mbedtls_rsa_context *rsa)
{
	uint8_t exponent[4];
	int ret;

	for (size_t i = 0; i < ARRAY_SIZE(it51xxx_rsa_supported_exponents); i++) {
		if (mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(E),
					it51xxx_rsa_supported_exponents[i]) == 0) {
			return 0;
		}
	}

	ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(E), exponent, sizeof(exponent));
	if (ret) {
		IT51XXX_LOG_ERR("failed to export exponent (%zu bits), %d",
			    mbedtls_mpi_bitlen(&rsa->MBEDTLS_PRIVATE(E)), ret);
	} else {
		IT51XXX_LOG_HEXDUMP_ERR(exponent, sizeof(exponent), "unsupported exponent:");
	}

	return PSA_ERROR_NOT_SUPPORTED;
}

static inline int it51xxx_crypto_rsa_add_pkcs1_v15_padding(const mbedtls_rsa_context *rsa,
							   unsigned int hashlen,
							   const uint8_t *hash, uint8_t *encode)
{
	size_t sig_len = mbedtls_rsa_get_len(rsa);
	int ret = rsa_rsassa_pkcs1_v15_encode(mbedtls_rsa_get_md_alg(rsa), hashlen, hash, sig_len,
					      encode);

	if (ret) {
		return ret;
	}

	IT51XXX_LOG_HEXDUMP_DBG(encode, sig_len, "padding data:");

	return 0;
}

static void it51xxx_rsa_dlm_init(void)
{
	memset(rsa_dlm.messages, 0, sizeof(rsa_dlm.messages));
	memset(rsa_dlm.key_private, 0, sizeof(rsa_dlm.key_private));
	memset(rsa_dlm.key_public, 0, sizeof(rsa_dlm.key_public));
}

static int it51xxx_set_rsa_keys(mbedtls_rsa_context *rsa)
{
	volatile struct it51xxx_crypto_regs *const crypto_regs =
		(volatile struct it51xxx_crypto_regs *)(uintptr_t)IT51XXX_CRYPTO_BASE;
	int ret;
	struct {
		uint8_t public[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
		uint8_t private[IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN];
		size_t size;
	} keys;

	ret = it51xxx_crypto_rsa_exp_valid(rsa);
	if (ret) {
		return ret;
	}

	keys.size = mbedtls_rsa_get_len(rsa);
	ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(N), (unsigned char *)keys.public,
				       keys.size);
	if (ret) {
		return ret;
	}

	ret = mbedtls_mpi_write_binary(&rsa->MBEDTLS_PRIVATE(D), (unsigned char *)keys.private,
				       keys.size);
	if (ret) {
		return ret;
	}

	for (size_t i = 0; i < keys.size; i++) {
		rsa_dlm.key_private[i] = keys.private[keys.size - i - 1];
	}

	for (size_t i = 0; i < keys.size; i++) {
		rsa_dlm.key_public[i] = keys.public[keys.size - i - 1];
	}

	crypto_regs->rsa_ctrl2 = PUBLIC_MODULUS_LENGTH(keys.size * BITS_PER_BYTE);

	return 0;
}

static int it51xxx_start_rsa_calculation(void)
{
	volatile struct it51xxx_crypto_regs *const crypto_regs =
		(volatile struct it51xxx_crypto_regs *)(uintptr_t)IT51XXX_CRYPTO_BASE;

	crypto_regs->rsa_status = RSA_CALCULATION_START;

	/* wait for completion */
	while ((crypto_regs->rsa_status & RSA_BUSY))
		;

	crypto_regs->rsa_ctrl &= ~(RSA_ENABLE | RSA_CLOCK_ENABLE);

	return 0;
}

static int it51xxx_crypto_rsa_sign(mbedtls_md_type_t md_alg, mbedtls_rsa_context *rsa,
				   unsigned int hashlen, const uint8_t *hash, unsigned char *sig)
{
	volatile struct it51xxx_crypto_regs *const crypto_regs =
		(volatile struct it51xxx_crypto_regs *)(uintptr_t)IT51XXX_CRYPTO_BASE;
	int ret;
	size_t sig_len = mbedtls_rsa_get_len(rsa);
	uint8_t rsa_ctrl_val;
	uint8_t hash_with_padding[sig_len];

	// chip_block_idle();
	it51xxx_rsa_dlm_init();

	ret = it51xxx_set_rsa_keys(rsa);
	if (ret) {
		goto out;
	}

	ret = it51xxx_crypto_rsa_add_pkcs1_v15_padding(rsa, hashlen, hash, hash_with_padding);
	if (ret) {
		goto out;
	}

	for (size_t i = 0; i < sig_len; i++) {
		rsa_dlm.messages[i] = hash_with_padding[sig_len - i - 1];
	}

	crypto_regs->rsa_ctrl &= ~RSA_EXPONENT_MASK;
	crypto_regs->rsa_ctrl |= RSA_ENABLE | RSA_CLOCK_ENABLE | RSA_EXPONENT_SELECT(KEY_PRIVATE);

	ret = it51xxx_start_rsa_calculation();
	if (ret) {
		goto out;
	}

	for (size_t i = 0; i < sig_len; i++) {
		sig[sig_len - i - 1] = rsa_dlm.messages[i];
	}

	IT51XXX_LOG_HEXDUMP_DBG(sig, sig_len, "signature:");

out:
	// chip_permit_idle();

	return ret;
}

static int it51xxx_crypto_rsa_verify(mbedtls_rsa_context *rsa, unsigned int hashlen,
				     const uint8_t *hash, const unsigned char *sig)
{
	volatile struct it51xxx_crypto_regs *const crypto_regs =
		(volatile struct it51xxx_crypto_regs *)(uintptr_t)IT51XXX_CRYPTO_BASE;
	bool exponent_3 = !mbedtls_mpi_cmp_int(&rsa->MBEDTLS_PRIVATE(E), 3);
	int ret;
	size_t sig_len = mbedtls_rsa_get_len(rsa);
	uint8_t rsa_ctrl_val;
	uint8_t encoded[sig_len];
	uint8_t encoded_expected[sig_len];

	// chip_block_idle();
	it51xxx_rsa_dlm_init();

	ret = it51xxx_set_rsa_keys(rsa);
	if (ret) {
		goto out;
	}

	ret = it51xxx_crypto_rsa_add_pkcs1_v15_padding(rsa, hashlen, hash, encoded_expected);
	if (ret) {
		goto out;
	}

	for (size_t i = 0; i < sig_len; i++) {
		rsa_dlm.messages[i] = sig[sig_len - i - 1];
	}

	crypto_regs->rsa_ctrl &= ~RSA_EXPONENT_MASK;
	crypto_regs->rsa_ctrl |= RSA_ENABLE | RSA_CLOCK_ENABLE;
	crypto_regs->rsa_ctrl |= exponent_3 ? RSA_EXPONENT_SELECT(KEY_PUBLIC_EXP_3)
					    : RSA_EXPONENT_SELECT(KEY_PUBLIC_EXP_65537);

	ret = it51xxx_start_rsa_calculation();
	if (ret) {
		goto out;
	}

	for (size_t i = 0; i < sig_len; i++) {
		encoded[sig_len - i - 1] = rsa_dlm.messages[i];
	}

	IT51XXX_LOG_HEXDUMP_DBG(encoded, sig_len, "verify:");

	if (memcmp(encoded, encoded_expected, sig_len)) {
		ret = PSA_ERROR_INVALID_SIGNATURE;
	}

out:
	// chip_permit_idle();

	return ret;
}

static psa_status_t it51xxx_psa_rsa_sign_hash(const psa_key_attributes_t *attributes,
					      const uint8_t *key_buffer, size_t key_buffer_size,
					      psa_algorithm_t alg, const uint8_t *hash,
					      size_t hash_length, uint8_t *signature,
					      size_t signature_size, size_t *signature_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	int ret = PSA_ERROR_CORRUPTION_DETECTED;
	mbedtls_rsa_context *rsa = NULL;
	mbedtls_md_type_t md_alg;

	status = mbedtls_psa_rsa_load_representation(psa_get_key_type(attributes), key_buffer,
						     key_buffer_size, &rsa);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	status = psa_rsa_decode_md_type(alg, hash_length, &md_alg);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	if (signature_size < mbedtls_rsa_get_len(rsa)) {
		status = PSA_ERROR_BUFFER_TOO_SMALL;
		goto exit;
	}

	if (mbedtls_rsa_get_len(rsa) > IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN ||
	    mbedtls_rsa_get_len(rsa) < IT51XXX_HWCRYPTO_RSA_MIN_BYTE_LEN) {
		IT51XXX_LOG_ERR("unsupported rsa key size %zu (bytes)", mbedtls_rsa_get_len(rsa));
		status = PSA_ERROR_NOT_SUPPORTED;
		goto exit;
	}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
		ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, md_alg);
		if (ret == 0) {
			// (void)it51xxx_hwcrypto_mutex_lock(K_FOREVER);
			ret = it51xxx_crypto_rsa_sign(md_alg, rsa, (unsigned int)hash_length, hash,
						      signature);
			// it51xxx_hwcrypto_mutex_unlock();
		}
	} else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
	{
		status = PSA_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	if (ret == 0) {
		*signature_length = mbedtls_rsa_get_len(rsa);
	}
	status = mbedtls_to_psa_error(ret);

exit:
	mbedtls_rsa_free(rsa);
	mbedtls_free(rsa);

	return status;
}

static psa_status_t it51xxx_psa_rsa_verify_hash(const psa_key_attributes_t *attributes,
						const uint8_t *key_buffer, size_t key_buffer_size,
						psa_algorithm_t alg, const uint8_t *hash,
						size_t hash_length, const uint8_t *signature,
						size_t signature_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	int ret;
	mbedtls_rsa_context *rsa = NULL;
	mbedtls_md_type_t md_alg;

	status = mbedtls_psa_rsa_load_representation(psa_get_key_type(attributes), key_buffer,
						     key_buffer_size, &rsa);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	status = psa_rsa_decode_md_type(alg, hash_length, &md_alg);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	if (signature_length != mbedtls_rsa_get_len(rsa)) {
		status = PSA_ERROR_INVALID_SIGNATURE;
		goto exit;
	}

	if (mbedtls_rsa_get_len(rsa) > IT51XXX_HWCRYPTO_RSA_MAX_BYTE_LEN ||
	    mbedtls_rsa_get_len(rsa) < IT51XXX_HWCRYPTO_RSA_MIN_BYTE_LEN) {
		IT51XXX_LOG_ERR("unsupported rsa key size %zu (bytes)", mbedtls_rsa_get_len(rsa));
		status = PSA_ERROR_NOT_SUPPORTED;
		goto exit;
	}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
		ret = mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, md_alg);
		if (ret == 0) {
			// (void)it51xxx_hwcrypto_mutex_lock(K_FOREVER);
			ret = it51xxx_crypto_rsa_verify(rsa, (unsigned int)hash_length, hash,
							signature);
			// it51xxx_hwcrypto_mutex_unlock();
		}
	} else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN */
	{
		status = PSA_ERROR_INVALID_ARGUMENT;
		goto exit;
	}

	/* Mbed TLS distinguishes "invalid padding" from "valid padding but
	 * the rest of the signature is invalid". This has little use in
	 * practice and PSA doesn't report this distinction. */
	status = (ret == MBEDTLS_ERR_RSA_INVALID_PADDING) ? PSA_ERROR_INVALID_SIGNATURE
							  : mbedtls_to_psa_error(ret);

exit:
	mbedtls_rsa_free(rsa);
	mbedtls_free(rsa);

	return status;
}

psa_status_t ite_it51xxx_transparent_sign_hash(const psa_key_attributes_t *attributes,
					       const uint8_t *key_buffer, size_t key_buffer_size,
					       psa_algorithm_t alg, const uint8_t *hash,
					       size_t hash_length, uint8_t *signature,
					       size_t signature_size, size_t *signature_length)
{
	if (psa_get_key_type(attributes) == PSA_KEY_TYPE_RSA_KEY_PAIR) {
		if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
			return it51xxx_psa_rsa_sign_hash(attributes, key_buffer, key_buffer_size,
							 alg, hash, hash_length, signature,
							 signature_size, signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) */
		} else {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	(void)key_buffer;
	(void)key_buffer_size;
	(void)hash;
	(void)hash_length;
	(void)signature;
	(void)signature_size;
	(void)signature_length;

	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t ite_it51xxx_transparent_verify_hash(const psa_key_attributes_t *attributes,
						 const uint8_t *key_buffer, size_t key_buffer_size,
						 psa_algorithm_t alg, const uint8_t *hash,
						 size_t hash_length, const uint8_t *signature,
						 size_t signature_length)
{
	if (PSA_KEY_TYPE_IS_RSA(psa_get_key_type(attributes))) {
		if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN)
			return it51xxx_psa_rsa_verify_hash(attributes, key_buffer, key_buffer_size,
							   alg, hash, hash_length, signature,
							   signature_length);
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) */
		} else {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	(void)key_buffer;
	(void)key_buffer_size;
	(void)hash;
	(void)hash_length;
	(void)signature;
	(void)signature_length;

	return PSA_ERROR_NOT_SUPPORTED;
}

void it51xxx_crypto_rsa_init(void)
{
	volatile struct it51xxx_crypto_regs *const crypto_regs =
		(volatile struct it51xxx_crypto_regs *)(uintptr_t)IT51XXX_CRYPTO_BASE;

	IT51XXX_LOG_DBG("rsa dlm addr %#x(%zu)\n", (uint32_t)&rsa_dlm, sizeof(rsa_dlm));
	crypto_regs->rsa_base_addr_1 = FIELD_GET(GENMASK(15, 8), (uint32_t)&rsa_dlm);
	crypto_regs->rsa_base_addr_2 = FIELD_GET(GENMASK(17, 16), (uint32_t)&rsa_dlm);
	crypto_regs->rsa_ctrl = RSA_INTERRUPT_ENABLE;
}
