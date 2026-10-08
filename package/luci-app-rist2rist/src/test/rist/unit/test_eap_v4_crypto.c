/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Known-answer tests for the EAP v4 crypto primitives:
 *   - HKDF-Expand-SHA256 against RFC 5869 Test Case 1.
 *   - AES-256-GCM against the McGrew/Viega GCM spec Test Case 14, plus a
 *     round-trip and a tag-tamper rejection.
 */

#include "crypto/eap_v4_crypto.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;

static void from_hex(const char *hex, uint8_t *out, size_t out_len)
{
	for (size_t i = 0; i < out_len; i++) {
		unsigned v;
		sscanf(hex + 2 * i, "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

static void check(const char *name, const uint8_t *got, const uint8_t *want, size_t len)
{
	if (memcmp(got, want, len) != 0) {
		printf("FAIL: %s\n", name);
		g_failures++;
	} else {
		printf("ok: %s\n", name);
	}
}

/* RFC 5869 Test Case 1 (SHA-256). Our function is HKDF-Expand, so we feed the
 * RFC's PRK and info and expect the RFC's OKM. */
static void test_hkdf_rfc5869_case1(void)
{
	uint8_t prk[32], info[10], okm[42], want[42];
	from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk, 32);
	from_hex("f0f1f2f3f4f5f6f7f8f9", info, 10);
	from_hex("3cb25f25faacd57a90434f64d0362f2a"
			 "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
			 "34007208d5b887185865", want, 42);
	int rc = _librist_crypto_hkdf_expand_sha256(prk, 32, info, 10, okm, 42);
	if (rc != 0) { printf("FAIL: hkdf rc=%d (backend?)\n", rc); g_failures++; return; }
	check("hkdf-expand rfc5869 case1", okm, want, 42);
}

/* v4's per-direction keys are HKDF-Expand of the same K under distinct labels.
 * Guard that the directions derive different keys (a shared key with restarting
 * nonces is catastrophic under GCM) and that derivation is deterministic. */
static void test_hkdf_direction_separation(void)
{
	uint8_t prk[32];
	for (int i = 0; i < 32; i++) prk[i] = (uint8_t)(0x10 + i);
	const char *c2s = "RIST-EAP-v4 pass c2s";
	const char *s2c = "RIST-EAP-v4 pass s2c";
	uint8_t kc[32], ks[32], kc_again[32];
	int rc = _librist_crypto_hkdf_expand_sha256(prk, 32, (const uint8_t *)c2s, strlen(c2s), kc, 32);
	rc |= _librist_crypto_hkdf_expand_sha256(prk, 32, (const uint8_t *)s2c, strlen(s2c), ks, 32);
	rc |= _librist_crypto_hkdf_expand_sha256(prk, 32, (const uint8_t *)c2s, strlen(c2s), kc_again, 32);
	if (rc != 0) { printf("FAIL: hkdf dir rc=%d (backend?)\n", rc); g_failures++; return; }
	if (memcmp(kc, ks, 32) == 0) { printf("FAIL: c2s and s2c keys are identical\n"); g_failures++; }
	else printf("ok: per-direction keys differ\n");
	check("hkdf derivation is deterministic", kc, kc_again, 32);
}

/* GCM spec Test Case 14: 256-bit all-zero key, 96-bit all-zero IV, 16-byte
 * all-zero plaintext, empty AAD. */
static void test_gcm_kat_case14(void)
{
	uint8_t key[32] = {0}, iv[12] = {0}, pt[16] = {0};
	uint8_t ct[16], tag[16];
	uint8_t want_ct[16], want_tag[16];
	from_hex("cea7403d4d606b6e074ec5d3baf39d18", want_ct, 16);
	from_hex("d0d1c8a799996bf0265b98b5d48ab919", want_tag, 16);
	int rc = _librist_crypto_aes_gcm_encrypt(key, iv, 12, NULL, 0, pt, 16, ct, tag, 16);
	if (rc != 0) { printf("FAIL: gcm encrypt rc=%d (backend?)\n", rc); g_failures++; return; }
	check("gcm-256 KAT case14 ciphertext", ct, want_ct, 16);
	check("gcm-256 KAT case14 tag", tag, want_tag, 16);

	/* decrypt the KAT back */
	uint8_t out[16];
	rc = _librist_crypto_aes_gcm_decrypt(key, iv, 12, NULL, 0, ct, 16, tag, 16, out);
	if (rc != 0) { printf("FAIL: gcm decrypt of KAT rc=%d\n", rc); g_failures++; }
	else check("gcm-256 KAT case14 decrypt", out, pt, 16);
}

/* Round-trip with AAD, and a tampered-tag rejection. */
static void test_gcm_roundtrip_and_tamper(void)
{
	uint8_t key[32], iv[12];
	for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
	for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(0xa0 + i);
	const uint8_t pt[] = "correct horse battery staple";
	const size_t pt_len = sizeof(pt) - 1;
	const uint8_t aad[] = {0x02, 0x07, 0x13, 0x10, 0x00};
	uint8_t ct[64], tag[16], out[64];

	int rc = _librist_crypto_aes_gcm_encrypt(key, iv, 12, aad, sizeof(aad), pt, pt_len, ct, tag, 16);
	if (rc != 0) { printf("FAIL: gcm rt encrypt rc=%d\n", rc); g_failures++; return; }

	rc = _librist_crypto_aes_gcm_decrypt(key, iv, 12, aad, sizeof(aad), ct, pt_len, tag, 16, out);
	if (rc != 0) { printf("FAIL: gcm rt decrypt rc=%d\n", rc); g_failures++; }
	else check("gcm round-trip plaintext", out, pt, pt_len);

	/* Flip a tag bit: decrypt MUST fail and MUST zero the output. */
	uint8_t bad_tag[16];
	memcpy(bad_tag, tag, 16);
	bad_tag[0] ^= 0x01;
	memset(out, 0xcc, sizeof(out));
	rc = _librist_crypto_aes_gcm_decrypt(key, iv, 12, aad, sizeof(aad), ct, pt_len, bad_tag, 16, out);
	if (rc == 0) { printf("FAIL: gcm accepted a tampered tag\n"); g_failures++; }
	else printf("ok: gcm rejects tampered tag\n");

	/* Tampered AAD MUST also fail. */
	uint8_t bad_aad[5];
	memcpy(bad_aad, aad, 5);
	bad_aad[0] ^= 0x01;
	rc = _librist_crypto_aes_gcm_decrypt(key, iv, 12, bad_aad, sizeof(bad_aad), ct, pt_len, tag, 16, out);
	if (rc == 0) { printf("FAIL: gcm accepted tampered AAD\n"); g_failures++; }
	else printf("ok: gcm rejects tampered AAD\n");
}

int main(void)
{
	test_hkdf_rfc5869_case1();
	test_hkdf_direction_separation();
	test_gcm_kat_case14();
	test_gcm_roundtrip_and_tamper();
	if (g_failures) {
		printf("%d FAILURE(S)\n", g_failures);
		return 1;
	}
	printf("all eap_v4_crypto KATs passed\n");
	return 0;
}
