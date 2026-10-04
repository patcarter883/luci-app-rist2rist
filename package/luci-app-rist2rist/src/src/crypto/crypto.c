/* librist. Copyright © 2019 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "crypto-private.h"
#include "proto/rist_time.h"
#include "udp-private.h"
#include "sha256.h"
#include "crypto/random.h"
#include <string.h>
#include <stdlib.h>
/*
// This is intended for verifying that the peer has the same passphrase
// Usecase: "reply attack protection"
uint64_t rist_siphash(uint64_t birthtime, uint32_t seq, const char *phrase)
{
	uint8_t tmp[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	uint64_t out;

	if (!birthtime) {
		// This is an expected scenario and
		//  happens until the peer receives the first ping/pong
		return 0;
	}

	_librist_SHA256_Init(&ctx);
	_librist_SHA256_Update(&ctx, (void *) &birthtime, sizeof(birthtime));
	_librist_SHA256_Update(&ctx, (void *) &seq, sizeof(seq));

	if ((phrase != NULL) && strlen(phrase)) {
		_librist_SHA256_Update(&ctx, (const void *) phrase, strlen(phrase));
	}

	_librist_SHA256_Final(&ctx, tmp);

	memcpy(&out, tmp, sizeof(out));

	return out;
}
*/

/* Non-security caller of the CSPRNG with a wall-clock fallback on failure.
 * Used by SSRC / flow-id / peer-id generation. Security-critical sites must
 * use _librist_crypto_random_u32 instead. */
uint32_t prand_u32(void) {
	uint32_t u32 = 0;
	if (_librist_crypto_ramdom_get_bytes((uint8_t *)&u32, sizeof(u32)) == 0)
		return u32;
	uint32_t fallback = (uint32_t)timestampNTP_u64();
	return fallback ? fallback : 0xa5a5a5a5u;
}

int _librist_crypto_random_u32(uint32_t *out) {
	uint32_t u32 = 0;
	int ret = _librist_crypto_ramdom_get_bytes((uint8_t *)&u32, sizeof(u32));
	if (ret != 0)
		return ret;
	*out = u32;
	return 0;
}

uint32_t rand_u32(void)
{
	uint32_t u32;
	uint8_t *u8 = (void *) &u32;

	for (size_t i = 0; i < sizeof(u32); i++) {
		u8[i] = rand() % 256;
	}

	return u32;
}
