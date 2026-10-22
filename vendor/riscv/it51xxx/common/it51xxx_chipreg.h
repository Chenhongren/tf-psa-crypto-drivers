/*
 * Copyright (c) 2026 ITE Corporation. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CHIP_CHIPREGS_H
#define CHIP_CHIPREGS_H

#include <stdint.h>

#ifdef _ASMLANGUAGE
#define ECREG(x) x
#else

/*
 * Macros for hardware registers access.
 */
#define ECREG(x)     (*((volatile unsigned char *)(x)))
#define ECREG_u16(x) (*((volatile unsigned short *)(x)))
#define ECREG_u32(x) (*((volatile unsigned long *)(x)))

#endif /* _ASMLANGUAGE */

#define IT51XXX_CRYPTO_BASE 0xF03B00UL

#ifndef __ASSEMBLER__
struct it51xxx_crypto_regs {
	/* 0x00-0x3F: Reserved */
	volatile uint8_t reserved[0x40];
	/* 0x40: RSA Control Register */
	volatile uint8_t rsa_ctrl;
	/* 0x41: RSA Control 2 Register */
	volatile uint8_t rsa_ctrl2;
	/* 0x42: RSA Status Register */
	volatile uint8_t rsa_status;
	/* 0x44: RSA Base Address Byte 1 */
	volatile uint8_t rsa_base_addr_1;
	/* 0x45: RSA Base Address Byte 2 */
	volatile uint8_t rsa_base_addr_2;
};
#endif /* !__ASSEMBLER__ */

#endif /* CHIP_CHIPREGS_H */
