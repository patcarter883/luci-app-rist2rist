/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "eap.h"
#include "common/attributes.h"
#include "config.h"
#include "crypto/psk.h"
#include "endian-shim.h"
#include "crypto/crypto-private.h"
#include "crypto/srp.h"
#include "crypto/srp_constants.h"
#include "librist_srp.h"
#include "rist-private.h"
#include "udp-private.h"
#include "transport-private.h"
#include "log-private.h"
#include "proto/rist_time.h"
#include "peer.h"
#include "protocol_gre.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>

#define HASH_ALGO SRP_SHA256
#define DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define EAP_LOG_PREFIX "[EAP-SRP] "
#define EAP_AUTH_RETRY_MAX 3
#define EAP_AUTH_TIMEOUT_RETRY_MAX 5
#define EAP_AUTH_TIMEOUT 500//ms
#define EAP_REAUTH_PERIOD 60000 // ms
#define EAP_AUTH_FAILED_RECOVERY 30000 // ms, soft-FAILED -> UNAUTH after this quiet
#define EAP_IDENTITY_REPLY_INTERVAL 200 // ms, rate-limit pre-auth IDENTITY replies
#define EAP_MAX_MODULUS_BYTES 1024 // largest RFC 5054 group (NG_8192) is 1024 bytes

/* Permanent-failure sentinel for ctx->tries; fixed point under eap_tries_inc(). */
#define EAP_AUTH_TRIES_PERMANENT UINT_MAX

static int eap_request_passphrase(struct eapsrp_ctx *ctx, bool start);

struct eapsrp_ctx
{
	pthread_mutex_t eap_lock;
	struct {
		char username[256];
		char password[256];
		user_verifier_lookup_t lookup_func_old;
		user_verifier_lookup_2_t lookup_func;
		void *lookup_func_userdata_old;
		void *lookup_func_userdata;
        struct rist_logging_settings *logging_settings;
        bool use_key_as_passphrase;
        uint8_t role;
    } config;

    int authentication_state;
    uint8_t last_identifier;
    unsigned int tries;
    bool may_rollover_passphrase;
    bool did_first_auth;

    uint64_t failed_state_timestamp; /* 0 = not in soft-FAILED */
    uint64_t last_identity_reply_timestamp; /* rate-limit pre-auth IDENTITY replies */

    uint64_t passphrase_request_timer;
    int passphrase_request_times;
    uint8_t passphrase_request_identifier;

    uint64_t unsollicited_passphrase_response_timer;
    int unsollicited_passphrase_response_times;
    uint8_t unsollicited_passphrase_response_identifier;
    uint8_t unsollicited_passphrase[128];
    size_t unsollicited_passphrase_len;
    int unsollicited_passphrase_state;

    uint8_t *last_pkt;
    size_t last_pkt_size;
    uint8_t timeout_retries;
    uint64_t last_timestamp;
    uint64_t last_auth_timestamp;

    uint64_t generation;
    struct librist_crypto_srp_authenticator_ctx *auth_ctx;
    struct librist_crypto_srp_client_ctx *client_ctx;
    bool authenticated;

    struct rist_peer *peer;
    char ip_string[46];

    // authenticator data (single user mode) this doesn't need to be in config &
    // cloned because the lookup function keeps a pointer to the original
    // eap_ctx
    char authenticator_username[256];
#if HAVE_MBEDTLS
	size_t authenticator_len_verifier_old;
	uint8_t *authenticator_bytes_verifier_old;
	size_t authenticator_len_salt_old;
	uint8_t *authenticator_bytes_salt_old;
#endif
	size_t authenticator_len_verifier;
	uint8_t *authenticator_bytes_verifier;
	size_t authenticator_len_salt;
	uint8_t *authenticator_bytes_salt;

	bool eapversion3;//EAPv3 signalled. old libRIST used v2, so use this to ensure compat with broken hashing

	bool srp_legacy_pad;         //srp-compat=legacy URL opt-in
	bool srp_legacy_peer_warned; //one-shot latch for the M1/M2 hint
};

static inline void eap_tries_inc(struct eapsrp_ctx *ctx)
{
	/* Saturating: stays parked at EAP_AUTH_TRIES_PERMANENT instead of wrapping. */
	if (ctx->tries < EAP_AUTH_TRIES_PERMANENT)
		ctx->tries++;
}

void eap_reset_data(struct eapsrp_ctx *ctx)
{
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
	{
#if HAVE_MBEDTLS
		free(ctx->authenticator_bytes_salt_old);
		free(ctx->authenticator_bytes_verifier_old);
		ctx->authenticator_bytes_salt_old = NULL;
		ctx->authenticator_bytes_verifier_old = NULL;
#endif
		free(ctx->authenticator_bytes_salt);
		free(ctx->authenticator_bytes_verifier);
		ctx->authenticator_bytes_salt = NULL;
		ctx->authenticator_bytes_verifier = NULL;
	}
	librist_crypto_srp_authenticator_ctx_free(ctx->auth_ctx);
	ctx->auth_ctx = NULL;
	librist_crypto_srp_client_ctx_free(ctx->client_ctx);
	ctx->client_ctx = NULL;
	free(ctx->last_pkt);

	ctx->last_pkt = NULL;

	ctx->authenticated = false;
}

static int send_eapol_pkt(struct eapsrp_ctx *ctx, uint8_t eapoltype, uint8_t eapcode, uint8_t identifier, size_t payload_len, uint8_t buf[], uint8_t eap_version)
{
	size_t offset = 0;
	struct eapol_hdr *eapol_hdr = (struct eapol_hdr *)&buf[offset];
	offset += sizeof(*eapol_hdr);
	struct eap_hdr *eap_hdr = (struct eap_hdr *)&buf[offset];
	offset += sizeof(*eap_hdr);
	eapol_hdr->eapversion = eap_version;
	eapol_hdr->eaptype = eapoltype;
	eap_hdr->code = eapcode;
	eap_hdr->identifier = identifier;
	eapol_hdr->length = eap_hdr->length = htobe16(payload_len + sizeof(*eap_hdr));

	//Store last pkt so we can retransmit it if needed
	if (identifier == ctx->last_identifier)
	{
		free(ctx->last_pkt);
		ctx->last_pkt = malloc((payload_len + EAPOL_EAP_HDRS_OFFSET));
		if (ctx->last_pkt == NULL) {
			// OOM: skip caching the retransmit copy
			ctx->last_pkt_size = 0;
		} else {
			memcpy(ctx->last_pkt, buf, (payload_len + EAPOL_EAP_HDRS_OFFSET));
			ctx->last_pkt_size = (payload_len + EAPOL_EAP_HDRS_OFFSET);
			ctx->last_timestamp = timestampNTP_u64();
			ctx->timeout_retries = 0;
		}
	}
	if (_librist_proto_gre_send_data(ctx->peer, 0, RIST_GRE_PROTOCOL_TYPE_EAPOL, buf, (EAPOL_EAP_HDRS_OFFSET + payload_len), 0, 0, ctx->peer->rist_gre_version) < 0)
		return -1;

	return 0;
}


//EAP REQUEST HANDLING
static int process_eap_request_identity(struct eapsrp_ctx *ctx, uint8_t identifier)
{
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		return EAP_UNEXPECTEDREQUEST;
	/* Refuse pre-auth resets once authenticated; re-auth runs from eap_periodic. */
	if (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS)
		return EAP_UNEXPECTEDREQUEST;
	/* Rate-limit pre-auth replies (caps username echo + eap_reset_data work). */
	uint64_t now = timestampNTP_u64();
	if (ctx->last_identity_reply_timestamp != 0 &&
	    now < ctx->last_identity_reply_timestamp + (uint64_t)EAP_IDENTITY_REPLY_INTERVAL * RIST_CLOCK) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_DEBUG,
			EAP_LOG_PREFIX"Rate-limiting EAP IDENTITY response (last sent %u ms ago)\n",
			(unsigned)((now - ctx->last_identity_reply_timestamp) / RIST_CLOCK));
		return 0;
	}
	ctx->last_identity_reply_timestamp = now;
	eap_reset_data(ctx);
	uint8_t eapolpkt[512];
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	eapolpkt[offset] = EAP_TYPE_IDENTITY;
	offset += 1;
	memcpy(&eapolpkt[offset], ctx->config.username, strlen(ctx->config.username));
	offset += strlen(ctx->config.username);
	size_t len = offset;
	len -= EAPOL_EAP_HDRS_OFFSET;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, len, eapolpkt, ctx->eapversion3? 3 :2);
}

static int process_eap_request_srp_challenge(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[], uint8_t eap_version)
{
	if (len < 6)
		return EAP_LENERR;

#if HAVE_MBEDTLS
	ctx->eapversion3 = (eap_version >= 3);
#elif HAVE_NETTLE
	(void)(eap_version);
#endif
	// each TLV is prefixed with a 2-byte big-endian length, account for it
	size_t offset = 0;
	if (offset + 2 > len)
		return EAP_LENERR;
	uint16_t *tmp_swap = (uint16_t *)&pkt[offset];
	size_t name_len = be16toh(*tmp_swap);
	offset += 2;
	//name can be ignored
	if (name_len > len - offset)
		return EAP_LENERR;
	offset += name_len;
	if (offset + 2 > len)
		return EAP_LENERR;
	tmp_swap = (uint16_t *)&pkt[offset];
	size_t salt_len = be16toh(*tmp_swap);
	offset += 2;
	if (salt_len > len - offset)
		return EAP_LENERR;

	uint8_t *salt = &pkt[offset];
	uint8_t *g = NULL;
	uint8_t *N = NULL;
	size_t N_len = 0;
	offset += salt_len;
	if (offset + 2 > len)
		return EAP_LENERR;
	tmp_swap = (uint16_t *)&pkt[offset];
	size_t generator_len = be16toh(*tmp_swap);
	offset += 2;
	if (generator_len != 0)
	{
		if (generator_len > len - offset)
			return EAP_LENERR;
		if (generator_len > EAP_MAX_MODULUS_BYTES)
			return EAP_LENERR;

		g = &pkt[offset];
		offset += generator_len;
		N = &pkt[offset];
		N_len = len - offset;
		if (N_len > EAP_MAX_MODULUS_BYTES)
			return EAP_LENERR;
	}
	bool use_default_ng = (generator_len == 0);
	librist_crypto_srp_client_ctx_free(ctx->client_ctx);
	ctx->client_ctx = librist_crypto_srp_client_ctx_create(use_default_ng, N, N_len, g, generator_len, salt, salt_len, ctx->eapversion3, ctx->srp_legacy_pad);
	if (ctx->client_ctx == NULL)
		return EAP_INTERNALERR;
	uint8_t response[1500] = {0};
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&response[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_CHALLENGE;
	int len_A = librist_crypto_srp_client_write_A_bytes(ctx->client_ctx, &response[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)], sizeof(response) -(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)));
	if (len_A < 0)
		return -1;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, ((size_t)len_A + sizeof(*hdr)), response, ctx->eapversion3? 3 :2);
}

static int process_eap_request_srp_server_key(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	if (librist_crypto_srp_client_handle_B(ctx->client_ctx, pkt, len, ctx->config.username, ctx->config.password) != 0)
	{
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		//"must disconnect immediately, set tries past limit"
		ctx->tries = EAP_AUTH_TRIES_PERMANENT;
		return EAP_AUTH_TERMINATED;
	}
	size_t out_len = sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH;
	uint8_t response[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH)];
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&response[offset];
	offset += sizeof(*hdr);
	memset(&response[offset], 0, 4);
	offset += 4;
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_KEY;
	if (ctx->config.use_key_as_passphrase && ctx->eapversion3) {
		SET_BIT(response[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 3)], 0);
		librist_peer_update_tx_passphrase(ctx->peer, librist_crypto_srp_client_get_key(ctx->client_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
		ctx->did_first_auth = true;
	}
	librist_crypto_srp_client_write_M1_bytes(ctx->client_ctx, &response[offset]);
	int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, out_len, response, ctx->eapversion3? 3 :2);
	return ret;
}

static int process_eap_request_srp_server_validator(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	if (len < (4 + DIGEST_LENGTH))
		return EAP_LENERR;
	if (librist_crypto_srp_client_verify_m2(ctx->client_ctx, &pkt[4]) == 0)
	{
		if (ctx->authentication_state < EAP_AUTH_STATE_SUCCESS)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"Successfully authenticated\n");
		bool set_passphrase = CHECK_BIT(pkt[3], 0);
		if (set_passphrase && ctx->eapversion3) {
			librist_peer_update_rx_passphrase(ctx->peer, librist_crypto_srp_client_get_key(ctx->client_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
		}

		if (ctx->config.use_key_as_passphrase && ctx->eapversion3)
			ctx->may_rollover_passphrase = true;

		ctx->did_first_auth = true;
		ctx->authentication_state = EAP_AUTH_STATE_SUCCESS;
		ctx->last_auth_timestamp = timestampNTP_u64();
		ctx->tries = 0;
		ctx->failed_state_timestamp = 0;
		uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr))] = {0};
		struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
		if (ctx->eapversion3) {
			int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_SUCCESS, identifier, sizeof(*hdr), outpkt, 3);
			eap_request_passphrase(ctx, true);
			return ret;
		}
		hdr->type = EAP_TYPE_SRP_SHA1;
		hdr->subtype = EAP_SRP_SUBTYPE_SERVER_VALIDATOR;
		return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, sizeof(*hdr), outpkt, ctx->eapversion3? 3 :2);
	}
	//perm failure
	rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
		EAP_LOG_PREFIX"Server M2 verification failed for server@%s\n", ctx->ip_string);
	/* Advisory hint, latched: see srp-compat note in NEWS for v0.2.18. */
	if (!ctx->srp_legacy_peer_warned) {
		ctx->srp_legacy_peer_warned = true;
		if (ctx->srp_legacy_pad) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
				EAP_LOG_PREFIX"  Hint: this side is configured for srp-compat=legacy. If the server is running librist 0.2.16+ (PAD-compliant, the default), drop ?srp-compat=legacy on both sides.\n");
		} else {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
				EAP_LOG_PREFIX"  Hint: if the server is running librist 0.2.15 or earlier, the SRP wire format changed in 0.2.16 for RFC 5054 / TR-06-2 compliance. To interoperate with an older server, add ?srp-compat=legacy on BOTH URLs. Otherwise check the password.\n");
		}
	}
	ctx->authentication_state = EAP_AUTH_STATE_FAILED;
	ctx->tries = EAP_AUTH_TRIES_PERMANENT;

	return -1;
}

static int eap_srp_send_password(struct eapsrp_ctx *ctx, uint8_t identifier, const uint8_t *password, size_t password_len) {
	if (password_len > (1500 - (EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 1)))
		return -1;
	uint8_t outpkt[1500] = {0};
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE;
	if (password_len == 0) { //Use session key
		SET_BIT(outpkt[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)], 7);
	} else {
		SET_BIT(outpkt[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)], 6);
		const uint8_t *key;
		if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
			key = librist_crypto_srp_authenticator_get_key(ctx->auth_ctx);
		else
			key = librist_crypto_srp_client_get_key(ctx->client_ctx);

		uint8_t iv[AES_BLOCK_SIZE] = {0};
		iv[AES_BLOCK_SIZE-1] = identifier;
		_librist_crypto_aes_ctr(key, 256, iv, password, &outpkt[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) +1], password_len);
	}
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, sizeof(*hdr) +1 + password_len, outpkt, ctx->eapversion3? 3 :2);
}

static int process_eap_request_srp_passphrase(struct eapsrp_ctx *ctx, uint8_t identifier) {
	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS) {
		if (ctx->config.use_key_as_passphrase)
			return eap_srp_send_password(ctx, identifier, NULL, 0);

		const uint8_t *passphrase = NULL;
		size_t passphrase_len = 0;
		librist_peer_get_current_tx_passphrase(ctx->peer, &passphrase, &passphrase_len);
		return eap_srp_send_password(ctx, identifier, passphrase,  passphrase_len);
	}

	uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_FAILURE, identifier, 0, buf, ctx->eapversion3? 3 :2);
}

static int process_eap_request(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t identifier, uint8_t eap_version)
{
	if (len < 1)
		return EAP_LENERR;
	uint8_t type = pkt[0];
	if (type == EAP_TYPE_IDENTITY)
		return process_eap_request_identity(ctx, identifier);
	if (type == EAP_TYPE_SRP_SHA1)
	{
		if (len < 2)
			return EAP_LENERR;
		uint8_t subtype = pkt[1];
		if (subtype != EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE && ctx->config.role == EAP_ROLE_AUTHENTICATOR)
			return EAP_UNEXPECTEDREQUEST;

		/* Record identifier for FAILURE matching only after validation
		 * passes.  Moving this out of the prologue prevents an
		 * unauthenticated spoofed REQUEST from priming last_identifier
		 * and defeating the FAILURE-identifier gate. */
		ctx->last_identifier = identifier;
		switch (subtype)
		{
			case EAP_SRP_SUBTYPE_CHALLENGE:
				return process_eap_request_srp_challenge(ctx, identifier, (len -2), &pkt[2], eap_version);
				break;
			case EAP_SRP_SUBTYPE_SERVER_KEY:
				return process_eap_request_srp_server_key(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_VALIDATOR:
				return process_eap_request_srp_server_validator(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_LWRECHALLENGE:
				//handle SRP lw rechallenge
				break;
			case EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE:
				return process_eap_request_srp_passphrase(ctx, identifier);
				break;
			default:
				return EAP_SRP_WRONGSUBTYPE;
		}
	}
	return -1;
}

//EAP RESPONSE HANDLING

static int process_eap_response_identity(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[], uint8_t eap_version)
{
	if (len > 255)
		return -1;
	/* On the authenticatee side ctx->config.lookup_func is NULL (calloc'd
	 * in rist_enable_eap_srp_2 and never assigned for that role); refuse the
	 * IDENTITY response here so we don't deref it further down. */
	if (ctx->config.role != EAP_ROLE_AUTHENTICATOR || !ctx->config.lookup_func)
		return -1;
	memcpy(ctx->config.username, pkt, len);
	ctx->config.username[len] = '\0';
#if HAVE_MBEDTLS
	int hashversion = eap_version >= 3 ? 1 : 0;
#elif HAVE_NETTLE
	(void)eap_version;
	int hashversion = 1;
#endif
	uint64_t generation = 0;
	librist_verifier_lookup_data_t verifier_data = {0};
	ctx->config.lookup_func(ctx->config.username, &verifier_data, &hashversion, &generation, ctx->config.lookup_func_userdata);
#if HAVE_NETTLE
	if (hashversion == 0) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Lookup from SRP File got hashversion 0 response, Nettle backend does not support this, authentication likely to fail\n");
	}
	hashversion = 1;
#endif
	ctx->generation = generation;
	ctx->eapversion3 = (hashversion >= 1);
	const char *n_hex = verifier_data.n_modulus_ascii;
	const char *g_hex = verifier_data.generator_ascii;
	bool found = (verifier_data.verifier_len != 0 && verifier_data.verifier && verifier_data.salt_len != 0 && verifier_data.salt);
	uint8_t outpkt[1500] = { 0 };//TUNE THIS
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[offset];
	offset += sizeof(*hdr);
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_CHALLENGE;
	int rc = -1;
	if (found)
	{
		struct librist_crypto_srp_authenticator_ctx *auth_ctx = NULL;
		if (verifier_data.default_ng)
			librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &n_hex, &g_hex);

		auth_ctx = librist_crypto_srp_authenticator_ctx_create(n_hex, g_hex, verifier_data.verifier, verifier_data.verifier_len, verifier_data.salt, verifier_data.salt_len, ctx->eapversion3, ctx->srp_legacy_pad);
		if (!auth_ctx)
			goto out;
		librist_crypto_srp_authenticator_ctx_free(ctx->auth_ctx);
		ctx->auth_ctx = auth_ctx;
		memset(&outpkt[offset], 0, 2);
		offset += 2;//we dont send the server name
		uint16_t *tmp_swap = (uint16_t *)&outpkt[offset];
		*tmp_swap = htobe16(verifier_data.salt_len);
		offset += 2;
		memcpy(&outpkt[offset], verifier_data.salt, verifier_data.salt_len);
		offset += verifier_data.salt_len;
		if (verifier_data.default_ng)
		{
			memset(&outpkt[offset], 0, 2);
			offset += 2;
		} else {
			tmp_swap = (uint16_t *)&outpkt[offset];
			offset += 2;
			int g_size = librist_crypto_srp_authenticator_write_g_bytes(auth_ctx, &outpkt[offset], sizeof(outpkt) -offset);
			if (g_size < 0)
				goto out;
			*tmp_swap = htobe16(g_size);
			offset += g_size;

			int n_len = librist_crypto_srp_authenticator_write_n_bytes(auth_ctx, &outpkt[offset], sizeof(outpkt) -offset);
			if (n_len < 0)
				goto out;
			offset += n_len;
		}
		ctx->last_identifier++;
		size_t out_len = offset - EAPOL_EAP_HDRS_OFFSET;
		rc = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, out_len, outpkt, ctx->eapversion3? 3 :2);
	}
out:
	free(verifier_data.verifier);
	free(verifier_data.salt);
	free(verifier_data.generator_ascii);
	free(verifier_data.n_modulus_ascii);
	return rc;
}

static int process_eap_response_client_key(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	if (!ctx->auth_ctx) {
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		return EAP_INTERNALERR;
	}

	if (librist_crypto_srp_authenticator_handle_A(ctx->auth_ctx, pkt, len) != 0) {
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		ctx->tries = EAP_AUTH_TRIES_PERMANENT;
		return EAP_AUTH_TERMINATED;
	}

	uint8_t outpkt[1500];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_KEY;
	int len_B = librist_crypto_srp_authenticator_write_B_bytes(ctx->auth_ctx, &outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr))], sizeof(outpkt) - (EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)));
	if (len_B < 0)
		return -1;
	ctx->last_identifier++;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, (sizeof(struct eap_srp_hdr) + (size_t)len_B), outpkt, ctx->eapversion3? 3 :2);
}

static int process_eap_response_client_validator(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	if (len < (4 + DIGEST_LENGTH))
		return EAP_LENERR;

	if (!ctx->auth_ctx) {
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		return EAP_INTERNALERR;
	}

	if (librist_crypto_srp_authenticator_verify_m1(ctx->auth_ctx, ctx->config.username, &pkt[4]) != 0) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN, EAP_LOG_PREFIX"Authentication failed for %s@%s\n", ctx->config.username, ctx->ip_string);
		/* Advisory hint, latched: see srp-compat note in NEWS for v0.2.18. */
		if (!ctx->srp_legacy_peer_warned) {
			ctx->srp_legacy_peer_warned = true;
			if (ctx->srp_legacy_pad) {
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
					EAP_LOG_PREFIX"  Hint: this side is configured for srp-compat=legacy. If %s is running librist 0.2.16+ (PAD-compliant, the default), drop ?srp-compat=legacy on both sides.\n",
					ctx->ip_string);
			} else {
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
					EAP_LOG_PREFIX"  Hint: if %s is running librist 0.2.15 or earlier, the SRP wire format changed in 0.2.16 for RFC 5054 / TR-06-2 compliance. To interoperate with an older peer, add ?srp-compat=legacy on BOTH URLs. Otherwise check the password.\n",
					ctx->ip_string);
			}
		}
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		eap_tries_inc(ctx);
		int ret = EAP_AUTH_FAILED;
		if (ctx->tries > EAP_AUTH_RETRY_MAX) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Authentication retry count exceeded\n");
			ret = EAP_AUTH_TERMINATED;
		}
		uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
		send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_FAILURE, ctx->last_identifier, 0, buf, ctx->eapversion3? 3 :2);
		eap_reset_data(ctx);
		return ret;
	}
	ctx->authenticated = true;
	bool set_passphrase = CHECK_BIT(pkt[3], 0);
	if (set_passphrase) {
		librist_peer_update_rx_passphrase(ctx->peer, librist_crypto_srp_authenticator_get_key(ctx->auth_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
	}
	ctx->did_first_auth = true;
	uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH)];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_VALIDATOR;
	memset(&outpkt[EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr)], 0, 4);
	if (ctx->config.use_key_as_passphrase) {
		SET_BIT(outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 3)], 0);
		librist_peer_update_tx_passphrase(ctx->peer, librist_crypto_srp_authenticator_get_key(ctx->auth_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
		ctx->did_first_auth = true;
	}
	librist_crypto_srp_authenticator_write_M2_bytes(ctx->auth_ctx, &outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 4)]);
	ctx->last_identifier++;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, (sizeof(*hdr) + 4 + DIGEST_LENGTH), outpkt, ctx->eapversion3? 3 :2);
}

static int process_eap_response_srp_server_validator(struct eapsrp_ctx *ctx)
{
	if (ctx->authenticated)
	{
		if (ctx->authentication_state < EAP_AUTH_STATE_SUCCESS)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"Successfully authenticated %s@%s\n", ctx->config.username, ctx->ip_string);

		if (ctx->config.use_key_as_passphrase && ctx->eapversion3)
			ctx->may_rollover_passphrase = true;

		ctx->authentication_state = EAP_AUTH_STATE_SUCCESS;
		ctx->last_auth_timestamp = timestampNTP_u64();
		ctx->tries = 0;
		ctx->failed_state_timestamp = 0;
		ctx->last_identifier++;
	}
	return 0;
}

static int process_eap_response_passphrase(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[]) {
	if (ctx->authentication_state != EAP_AUTH_STATE_SUCCESS)
		return 0;

	/* If a solicited passphrase request is outstanding, only accept a
	 * response whose identifier matches the request.  This prevents
	 * replay or spoofed RESPONSEs from hijacking an active exchange.
	 *
	 * When no request is active the RESPONSE is an unsolicited
	 * passphrase push (the protocol explicitly allows this — see
	 * rist_eap_send_passphrase).  Its payload is AES-CTR encrypted
	 * under the SRP session key, which provides integrity. */
	bool matches_request = (ctx->passphrase_request_timer != 0 &&
	                        identifier == ctx->passphrase_request_identifier);
	if (ctx->passphrase_request_timer != 0 && !matches_request)
		return 0;

	if (len < 1)
		return EAP_LENERR;
	bool use_derived_key = CHECK_BIT(pkt[0], 7);
	const uint8_t *key = NULL;
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		key = librist_crypto_srp_authenticator_get_key(ctx->auth_ctx);
	else
		key = librist_crypto_srp_client_get_key(ctx->client_ctx);
	if (use_derived_key) {
		librist_peer_update_rx_passphrase(ctx->peer, key, SHA256_DIGEST_LENGTH, matches_request);
	} else {
		bool aes_256 = CHECK_BIT(pkt[0], 6);
		uint8_t iv[16] = {0};
		iv[15] = identifier;
		_librist_crypto_aes_ctr(key, aes_256? 256: 128, iv, &pkt[1], &pkt[1], len -1);
		librist_peer_update_rx_passphrase(ctx->peer, &pkt[1], len-1, matches_request);
	}
	uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
	if (ctx->passphrase_request_timer)
		ctx->passphrase_request_timer = 0;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_SUCCESS, identifier, 0, buf, ctx->eapversion3? 3 :2);
}

static int eap_request_passphrase(struct eapsrp_ctx *ctx, bool start) {
	if (start) {
		ctx->unsollicited_passphrase_response_times = 0;
		ctx->passphrase_request_identifier++;
		if (ctx->config.role == EAP_ROLE_AUTHENTICATEE)
			SET_BIT(ctx->passphrase_request_identifier, 7);
		SET_BIT(ctx->passphrase_request_identifier, 6);
	}
	uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr))];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE;
	ctx->passphrase_request_times++;
	ctx->passphrase_request_timer = timestampNTP_u64();
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->passphrase_request_identifier, sizeof(*hdr), outpkt, ctx->eapversion3? 3 :2);
}

static int process_eap_response(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t identifier, uint8_t eap_version)
{
	if (len < 1)
		return EAP_LENERR;
	uint8_t type = pkt[0];
	ctx->timeout_retries = 0;
	free(ctx->last_pkt);
	ctx->last_pkt_size = 0;
	ctx->last_pkt = NULL;
	if (type == EAP_TYPE_IDENTITY) {
		/* Only an authenticator should ever process IDENTITY RESPONSE; on the
		 * authenticatee side ctx->config.lookup_func is NULL (set up via
		 * calloc + role/username/password assignment in rist_enable_eap_srp_2)
		 * and process_eap_response_identity would dereference it. */
		if (ctx->config.role != EAP_ROLE_AUTHENTICATOR || !ctx->config.lookup_func)
			return EAP_UNEXPECTEDRESPONSE;
		if (identifier != ctx->last_identifier)
			return EAP_WRONGIDENTIFIER;
		return process_eap_response_identity(ctx, (len -1), &pkt[1], eap_version);
	}
	if (type == EAP_TYPE_SRP_SHA1)
	{
		if (len < 2)
			return EAP_LENERR;
		uint8_t subtype = pkt[1];

		if (subtype != EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE && ctx->config.role == EAP_ROLE_AUTHENTICATEE)
			return EAP_UNEXPECTEDRESPONSE;

		//A password response can be send unsollicited!
		if (subtype != EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE && identifier != ctx->last_identifier)
			return EAP_WRONGIDENTIFIER;

		switch (subtype)
		{
			case EAP_SRP_SUBTYPE_CLIENT_KEY:
				return process_eap_response_client_key(ctx, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SYPTYPE_CLIENT_VALIDATOR:
				return process_eap_response_client_validator(ctx, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_VALIDATOR:
				return process_eap_response_srp_server_validator(ctx);
				break;
			case EAP_SRP_SUBTYPE_LWRECHALLENGE:
				//handle SRP lw rechallenge
				break;
			case EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE:
				return process_eap_response_passphrase(ctx, identifier, (len -2), &pkt[2]);
				break;
			default:
				return EAP_SRP_WRONGSUBTYPE;
		}
	}
	return -1;
}

static int process_eap_succes(struct eapsrp_ctx *ctx, uint8_t identifier) {
	if (identifier == ctx->unsollicited_passphrase_response_identifier && ctx->unsollicited_passphrase_response_timer != 0) {
		ctx->unsollicited_passphrase_state = EAP_PASSPHRASE_STATE_SUCCESS;
		ctx->unsollicited_passphrase_response_identifier = 0;
		ctx->unsollicited_passphrase_response_timer = 0;
		ctx->unsollicited_passphrase_response_times = 0;
		return 0;
	}
	if (identifier ==ctx->last_identifier)//The spec mandates we use the success packet on reception of the server_validator
		return process_eap_response_srp_server_validator(ctx);
	return 0;
}

static int process_eap_pkt(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t eap_version)
{
	if (ctx == NULL)
		return -1;
	if (ctx->authentication_state == EAP_AUTH_STATE_FAILED && ctx->tries >EAP_AUTH_RETRY_MAX)
		return EAP_AUTH_TERMINATED;
	if (len < sizeof(struct eap_hdr))
		return EAP_LENERR;
	struct eap_hdr *hdr = (struct eap_hdr *)pkt;
	uint8_t code = hdr->code;
	uint8_t identifier = hdr->identifier;
	uint16_t length = be16toh(hdr->length);
	if (length != len)
		return EAP_LENERR;

	switch (code)
	{
		case EAP_CODE_REQUEST:
			return process_eap_request(ctx, &pkt[sizeof(*hdr)], (len - sizeof(*hdr)), identifier, eap_version);
			break;
		case EAP_CODE_RESPONSE:
			return process_eap_response(ctx, &pkt[sizeof(*hdr)], (len - sizeof(*hdr)),identifier, eap_version);
			break;
		case EAP_CODE_SUCCESS:
			return process_eap_succes(ctx, identifier);
			break;
		case EAP_CODE_FAILURE:
			/* Drop FAILUREs whose identifier doesn't match the in-flight exchange. */
			if (identifier != ctx->last_identifier) {
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_DEBUG,
					EAP_LOG_PREFIX"Dropping FAILURE with stale identifier %u (expected %u)\n",
					identifier, ctx->last_identifier);
				return 0;
			}
			// rate-limit, otherwise a spoofed FAILURE can loop us forever
			eap_tries_inc(ctx);
			eap_reset_data(ctx);
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Authentication failed\n");
			if (ctx->tries > EAP_AUTH_RETRY_MAX) {
				ctx->authentication_state = EAP_AUTH_STATE_FAILED;
				ctx->failed_state_timestamp = timestampNTP_u64();
				return EAP_AUTH_TERMINATED;
			}
			return _librist_proto_eap_start(ctx);//try to restart the process
		default:
			return -1;
	}
	return -1;
}

int eap_request_identity(struct eapsrp_ctx *ctx)
{
	uint8_t outpkt[EAPOL_EAP_HDRS_OFFSET +1];
	outpkt[EAPOL_EAP_HDRS_OFFSET] = EAP_TYPE_IDENTITY;
	uint32_t id_rand;
	if (_librist_crypto_random_u32(&id_rand) != 0)
		return -1;
	ctx->last_identifier = (uint8_t)(id_rand >> 24);
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, 1, outpkt, ctx->eapversion3? 3 :2);
}

int _librist_proto_eap_start(struct eapsrp_ctx *ctx)
{
	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS)
		ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
	struct eapol_hdr eapol;
	eapol.eapversion = 3;
	eapol.eaptype = EAPOL_TYPE_START;
	eapol.length = 0;
	if (_librist_proto_gre_send_data(ctx->peer, 0, RIST_GRE_PROTOCOL_TYPE_EAPOL, (uint8_t*)&eapol, sizeof(eapol), 0, 0, ctx->peer->rist_gre_version) < 0)
		return -1;
	return 0;
}

void eap_set_ip_string(struct eapsrp_ctx *ctx, char ip_string[])
{
	if (ctx != NULL) {
		strncpy(ctx->ip_string, ip_string, sizeof(ctx->ip_string) - 1);
		ctx->ip_string[sizeof(ctx->ip_string) - 1] = '\0';
	}
}

int eap_clone_ctx(struct eapsrp_ctx *in, struct rist_peer *peer)
{
	if (in == NULL)
		return 0;
	if (peer->eap_ctx != NULL)
		return -1;
	struct eapsrp_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	if (pthread_mutex_init(&ctx->eap_lock, NULL) != 0) {
		free(ctx);
		return -1;
	}
    memcpy(&ctx->config, &in->config, sizeof(in->config));
	ctx->srp_legacy_pad = in->srp_legacy_pad;
	peer->eap_ctx = ctx;
	ctx->peer = peer;
	ctx->eapversion3 = true;
	return 0;
}

void eap_delete_ctx(struct eapsrp_ctx **in)
{
	if (*in == NULL)
		return;

	struct eapsrp_ctx *ctx = *in;
	eap_reset_data(ctx);

	free(ctx);
	*in = NULL;
}

int eap_process_eapol(struct eapsrp_ctx* ctx, uint8_t pkt[], size_t len)
{
	assert(ctx != NULL);
	if (len < sizeof(struct eapol_hdr))
		return EAP_LENERR;
	struct eapol_hdr *hdr = (struct eapol_hdr *)pkt;
	uint8_t eap_version = hdr->eapversion;
	size_t body_len = be16toh(hdr->length);
	// the on-the-wire body_len must fit inside what we actually received
	if (body_len + sizeof(struct eapol_hdr) > len)
		return EAP_LENERR;

	pthread_mutex_lock(&ctx->eap_lock);
	int ret = -1;
	switch (hdr->eaptype)
	{
		case EAPOL_TYPE_EAP:
			ret = process_eap_pkt(ctx, &pkt[sizeof(*hdr)], body_len, eap_version);
			break;
		case EAPOL_TYPE_START:
			if (ctx->config.role == EAP_ROLE_AUTHENTICATOR && !ctx->last_pkt)
				ret =  eap_request_identity(ctx);
			if (ctx->config.role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state == EAP_AUTH_STATE_SUCCESS) {
				ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
                ret = eap_request_identity(ctx);
            } else
				ret = 0;
			break;
		case EAPOL_TYPE_LOGOFF:
			/* Refuse LOGOFF once authenticated; re-auth runs from eap_periodic. */
			if (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS) {
				ret = EAP_UNEXPECTEDREQUEST;
				break;
			}
			ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
			ctx->tries = 0;
			ctx->failed_state_timestamp = 0;
			ret = 0;
			break;
		default:
			break;
	}
	pthread_mutex_unlock(&ctx->eap_lock);
	return ret;
}

bool eap_is_authenticated(struct eapsrp_ctx *ctx)
{
	if (ctx == NULL)
		return true;

	pthread_mutex_lock(&ctx->eap_lock);
	bool authenticated = (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS);
	pthread_mutex_unlock(&ctx->eap_lock);
	return authenticated;
}

static void eap_periodic_impl(struct eapsrp_ctx *ctx)
{
	uint64_t now = timestampNTP_u64();
	uint64_t retry_period = EAP_AUTH_TIMEOUT * RIST_CLOCK;
	uint64_t reauth_period = EAP_REAUTH_PERIOD * RIST_CLOCK;//3 seconds
	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS && ctx->passphrase_request_timer != 0 && ctx->passphrase_request_timer + retry_period < now) {
		if (ctx->passphrase_request_times > EAP_AUTH_TIMEOUT_RETRY_MAX) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN, EAP_LOG_PREFIX"Failed to receive requested passphrase in a timely manner\n");
			ctx->passphrase_request_timer = 0;
		} else {
			eap_request_passphrase(ctx, false);
		}
	}

	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS && ctx->unsollicited_passphrase_response_timer != 0 && ctx->unsollicited_passphrase_response_timer + retry_period < now) {
		if (ctx->unsollicited_passphrase_response_times > EAP_AUTH_TIMEOUT_RETRY_MAX) {
			rist_log(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Failed to update passphrase for client\n");
			ctx->unsollicited_passphrase_response_timer = 0;
			ctx->unsollicited_passphrase_state = EAP_PASSPHRASE_STATE_FAILED;
		} else {
			eap_srp_send_password(ctx, ctx->unsollicited_passphrase_response_identifier, ctx->unsollicited_passphrase, ctx->unsollicited_passphrase_len);
			ctx->unsollicited_passphrase_response_timer = timestampNTP_u64();
			ctx->unsollicited_passphrase_response_times++;
		}
    }

	if (ctx->unsollicited_passphrase_response_timer == 0 &&
		ctx->passphrase_request_timer &&
		((ctx->unsollicited_passphrase_response_identifier & 0x3f) == 0x3f ||
		(ctx->unsollicited_passphrase_response_identifier & 0x3f) == 0x3f)) {
			if (ctx->config.role == EAP_ROLE_AUTHENTICATEE)
				_librist_proto_eap_start(ctx);
			else
				eap_request_identity(ctx);
		}
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state != 1 && ctx->last_timestamp + retry_period < now &&
		ctx->timeout_retries < EAP_AUTH_TIMEOUT_RETRY_MAX && ctx->tries <= EAP_AUTH_RETRY_MAX)
	{
		if (ctx->last_pkt)
		{
			rist_transport_sendto(ctx->peer, ctx->last_pkt, ctx->last_pkt_size, 0);
			//check
			ctx->timeout_retries++;
			ctx->last_timestamp = now;
			return;
		} else {
			eap_request_identity(ctx);
			return;
		}
	} else if (ctx->config.role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state == EAP_AUTH_STATE_SUCCESS &&
	           now > ctx->last_auth_timestamp + reauth_period) {
		if (ctx->generation > 0) {
			uint64_t generation = ctx->generation;
			int hashversion = ctx->eapversion3? 1 : 0;
			//If our cached data matches whatever lookup function would return re-auth is pointless.
			ctx->config.lookup_func(ctx->config.username, NULL, &hashversion, &generation, ctx->config.lookup_func_userdata);
			if (generation == ctx->generation) {
				ctx->last_auth_timestamp = now;
				return;
			}
		}
		ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
		eap_request_identity(ctx);
		return;
	}
	uint64_t reauth_time_out = ctx->last_auth_timestamp + reauth_period + EAP_AUTH_RETRY_MAX * retry_period;
	if (ctx->authentication_state == EAP_AUTH_STATE_REAUTH && now > reauth_time_out) {
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
		return;
	}
	/* Soft-FAILED (tries bumped past max but not parked at PERMANENT) -> UNAUTH after quiet. */
	if (ctx->authentication_state == EAP_AUTH_STATE_FAILED &&
	    ctx->tries > EAP_AUTH_RETRY_MAX &&
	    ctx->tries < EAP_AUTH_TRIES_PERMANENT &&
	    ctx->failed_state_timestamp != 0 &&
	    now > ctx->failed_state_timestamp + (uint64_t)EAP_AUTH_FAILED_RECOVERY * RIST_CLOCK) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
			EAP_LOG_PREFIX"Recovered from soft FAILED state after %d ms of quiet\n",
			EAP_AUTH_FAILED_RECOVERY);
		ctx->tries = 0;
		ctx->failed_state_timestamp = 0;
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
	}
}
void eap_periodic(struct eapsrp_ctx *ctx) {
	if (ctx == NULL)
		return;
	pthread_mutex_lock(&ctx->eap_lock);
	eap_periodic_impl(ctx);
	pthread_mutex_unlock(&ctx->eap_lock);
}

static void internal_user_verifier_lookup(char * username,
							librist_verifier_lookup_data_t *lookup_data,
							int *hashversion,
							uint64_t *generation,
							void *user_data)
{
	if (user_data == NULL)
		return;

	if (*generation == 1)
		return;
	//This is static data so it can be permanently cached
	*generation = 1;

	struct eapsrp_ctx *ctx = (struct eapsrp_ctx *)user_data;

	uint8_t *decoded_verifier = NULL;
	uint8_t *decoded_salt = NULL;

	if (strcmp(username, ctx->authenticator_username) != 0)
		goto fail_decode;

	if (*hashversion == 0 && HAVE_MBEDTLS) {
#if HAVE_MBEDTLS
		decoded_verifier = malloc(ctx->authenticator_len_verifier_old);
		decoded_salt = malloc(ctx->authenticator_len_salt_old);
		if (!decoded_verifier || !decoded_salt)
			goto fail_decode;
		memcpy(decoded_verifier, ctx->authenticator_bytes_verifier_old, ctx->authenticator_len_verifier_old);
		memcpy(decoded_salt, ctx->authenticator_bytes_salt_old, ctx->authenticator_len_salt_old);
		lookup_data->verifier_len = ctx->authenticator_len_verifier_old;
		lookup_data->salt_len = ctx->authenticator_len_salt_old;
#endif
	} else {
		decoded_verifier = malloc(ctx->authenticator_len_verifier);
		decoded_salt = malloc(ctx->authenticator_len_salt);
		if (!decoded_verifier || !decoded_salt)
			goto fail_decode;
		memcpy(decoded_verifier, ctx->authenticator_bytes_verifier, ctx->authenticator_len_verifier);
		memcpy(decoded_salt, ctx->authenticator_bytes_salt, ctx->authenticator_len_salt);
		lookup_data->verifier_len = ctx->authenticator_len_verifier;
		lookup_data->salt_len = ctx->authenticator_len_salt;
	}
	lookup_data->verifier = decoded_verifier;
	lookup_data->salt = decoded_salt;

	lookup_data->default_ng = true;
	goto out;

fail_decode:
	lookup_data->verifier_len = 0;
	lookup_data->salt_len = 0;
	free(decoded_verifier);
	free(decoded_salt);
out:
	return;
}

static void old_user_verifier_lookup_wrapper(char * username,
							librist_verifier_lookup_data_t *lookup_data,
							int *hashversion,
							uint64_t *generation,
							void *user_data)
{
	*hashversion = 0;
	*generation = 0;
	struct eapsrp_ctx *ctx = (struct eapsrp_ctx *)user_data;
	ctx->config.lookup_func_old(username, &lookup_data->verifier_len,(char **)&lookup_data->verifier, &lookup_data->salt_len, (char **)&lookup_data->salt, &lookup_data->default_ng, &lookup_data->n_modulus_ascii, &lookup_data->generator_ascii, user_data);
}

//PUBLIC
int rist_enable_eap_srp_2(struct rist_peer *peer, const char *username, const char *password, user_verifier_lookup_2_t lookup_func, void *userdata) {
	if (!peer)
		return RIST_ERR_NULL_PEER;
	struct rist_common_ctx *cctx = get_cctx(peer);
	if (cctx->profile == RIST_PROFILE_SIMPLE)
		return RIST_ERR_INVALID_PROFILE;
	if ((peer->listening && !peer->multicast_receiver) || peer->multicast_sender)
	{
		struct eapsrp_ctx *ctx = calloc(1, sizeof(*ctx));
		if (ctx == NULL)
			return RIST_ERR_MALLOC;
		ctx->config.logging_settings = get_cctx(peer)->logging_settings;
		if (pthread_mutex_init(&ctx->eap_lock, NULL) != 0) {
			free(ctx);
			return RIST_ERR_MALLOC;
		}
		if (lookup_func == NULL && username != NULL && password != NULL)
		{
			size_t u_len = strlen(username);
			size_t p_len = strlen(password);
			if (u_len == 0 || u_len > 255 || p_len == 0 || p_len > 255) {
				free(ctx);
				return RIST_ERR_INVALID_STRING_LENGTH;
			}
			lookup_func = internal_user_verifier_lookup;
			const char *n = NULL;
			const char *g = NULL;
			int ret;
			ret = librist_get_ng_constants(LIBRIST_SRP_NG_2048, &n, &g);
			assert(ret == 0);
#if HAVE_MBEDTLS
			ret = librist_crypto_srp_create_verifier(n, g, username, password, &ctx->authenticator_bytes_salt_old, &ctx->authenticator_len_salt_old, &ctx->authenticator_bytes_verifier_old, &ctx->authenticator_len_verifier_old, false);
			assert(ret == 0);
#endif
			ret = librist_crypto_srp_create_verifier(n, g, username, password, &ctx->authenticator_bytes_salt, &ctx->authenticator_len_salt, &ctx->authenticator_bytes_verifier, &ctx->authenticator_len_verifier, true);
			assert(ret == 0);
			strcpy(ctx->authenticator_username, username);
			userdata = (void *)ctx;
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticator, single user\n");
		}
		else if (lookup_func == NULL) {
			free(ctx);
			return RIST_ERR_MISSING_CALLBACK_FUNCTION;
		}
		else
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticator, srp file\n");
		ctx->config.lookup_func = lookup_func;
		ctx->config.lookup_func_userdata = userdata;
		ctx->config.role = EAP_ROLE_AUTHENTICATOR;
		ctx->config.use_key_as_passphrase = peer->key_tx.password_len == 0;
		ctx->eapversion3 = true;
		ctx->srp_legacy_pad = (peer->config.srp_compat_legacy != 0);
		if (ctx->srp_legacy_pad)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
				EAP_LOG_PREFIX"SRP legacy compat mode ACTIVE on this authenticator (srp-compat=legacy). Wire format is the pre-0.2.16 unpadded form — NOT TR-06-2 / RFC 5054 compliant. For transitional interop only.\n");
		peer->eap_ctx = ctx;
		struct rist_peer *child = peer->child;
		peer->eap_authentication_state = 1;
		ctx->peer = peer;
		while (child != NULL)
		{
			eap_clone_ctx(ctx, child);
			child = child->sibling_next;
		}
		return 0;
	}
	if (username == NULL || password == NULL)
		return RIST_ERR_NULL_CREDENTIALS;
	size_t u_len = strlen(username);
	size_t p_len = strlen(password);
	if (u_len == 0 || u_len > 255 || p_len == 0 || p_len > 255)
		return RIST_ERR_INVALID_STRING_LENGTH;
	struct eapsrp_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return RIST_ERR_MALLOC;
	if (pthread_mutex_init(&ctx->eap_lock, NULL) != 0) {
		free(ctx);
		return RIST_ERR_MALLOC;
	}
	ctx->peer = peer;
	ctx->config.logging_settings = get_cctx(peer)->logging_settings;
	ctx->config.role = EAP_ROLE_AUTHENTICATEE;
	strcpy(ctx->config.username, username);
	strcpy(ctx->config.password, password);
	ctx->srp_legacy_pad = (peer->config.srp_compat_legacy != 0);
	peer->eap_ctx = ctx;
	rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticatee\n");
	if (ctx->srp_legacy_pad)
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
			EAP_LOG_PREFIX"SRP legacy compat mode ACTIVE on this client (srp-compat=legacy). Wire format is the pre-0.2.16 unpadded form — NOT TR-06-2 / RFC 5054 compliant. For transitional interop only.\n");
	ctx->eapversion3 = true;
	if (!peer->multicast_receiver)
		_librist_proto_eap_start(ctx);
	return 0;
}

int rist_enable_eap_srp(struct rist_peer *peer, const char *username, const char *password, user_verifier_lookup_t lookup_func, void *userdata)
{
	if (!peer)
		return RIST_ERR_NULL_PEER;

	user_verifier_lookup_2_t pass_lookup = lookup_func? old_user_verifier_lookup_wrapper : NULL;
	int ret = rist_enable_eap_srp_2(peer, username, password, pass_lookup, NULL);
	if (ret == 0) {
		peer->eap_ctx->config.lookup_func_old = lookup_func;
		peer->eap_ctx->config.lookup_func_userdata = peer->eap_ctx;
		peer->eap_ctx->config.lookup_func_userdata_old = userdata;
	}
	return ret;
}

//returns true when either succesfull or failed
bool rist_eap_password_sending_done(struct eapsrp_ctx *ctx) {
	pthread_mutex_lock(&ctx->eap_lock);
	bool success = ctx->unsollicited_passphrase_state >= EAP_PASSPHRASE_STATE_SUCCESS;
	pthread_mutex_unlock(&ctx->eap_lock);
	return success;
}

bool rist_eap_may_rollover_tx(struct eapsrp_ctx *ctx) {
	pthread_mutex_lock(&ctx->eap_lock);
	bool rollover = ctx->may_rollover_passphrase;
	ctx->may_rollover_passphrase = false;
	pthread_mutex_unlock(&ctx->eap_lock);
	return rollover;
}

void rist_eap_send_passphrase(struct eapsrp_ctx *ctx, const char *passphrase) {
	pthread_mutex_lock(&ctx->eap_lock);
	size_t plen = strlen(passphrase);
	if (plen > sizeof(ctx->unsollicited_passphrase)) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR,
			EAP_LOG_PREFIX"Passphrase too long (%zu > %zu), dropping\n",
			plen, sizeof(ctx->unsollicited_passphrase));
		pthread_mutex_unlock(&ctx->eap_lock);
		return;
	}
	ctx->unsollicited_passphrase_len = plen;
	memcpy(ctx->unsollicited_passphrase, passphrase, plen);
	ctx->unsollicited_passphrase_response_timer = timestampNTP_u64();
	ctx->unsollicited_passphrase_response_times = 1;
	ctx->unsollicited_passphrase_response_identifier++;
	ctx->unsollicited_passphrase_state = 0;
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		SET_BIT(ctx->unsollicited_passphrase_response_identifier, 7);
	UNSET_BIT(ctx->unsollicited_passphrase_response_identifier, 6);
    eap_srp_send_password(ctx, ctx->unsollicited_passphrase_response_identifier, ctx->unsollicited_passphrase, ctx->unsollicited_passphrase_len);
    pthread_mutex_unlock(&ctx->eap_lock);
}
