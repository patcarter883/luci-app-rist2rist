/* librist. Copyright © 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_CRYPTO_PRIVATE_H
#define RIST_CRYPTO_PRIVATE_H

#include "common/attributes.h"
#include <stdint.h>
#include <stddef.h>

/* Best-effort wipe of transient key material that a compiler will not elide.
 * Shared by the PSK and EAP v4 crypto paths. */
static inline void _librist_crypto_secure_zero(void *p, size_t n)
{
	volatile unsigned char *v = (volatile unsigned char *)p;
	while (n--)
		*v++ = 0;
}

RIST_PRIV uint64_t rist_siphash(uint64_t birthtime, uint32_t seq, const char *phrase);

/* prand_u32: wall-clock fallback on CSPRNG failure. Non-security only (SSRC, flow-id, peer-id). */
RIST_PRIV uint32_t prand_u32(void);

/* Fail-closed CSPRNG. Returns 0 on success with *out populated, non-zero error otherwise. */
RIST_PRIV int _librist_crypto_random_u32(uint32_t *out);

#endif
