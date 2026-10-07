/* This set of unit tests covers the entire SRP flow, with deterministic
 * a/b/salt fixtures (DEBUG_USE_EXAMPLE_CONSTANTS=1) on the 2048-bit
 * NG_DEFAULT group from RFC 5054 Appendix A.  Fixtures were regenerated
 * for librist 0.2.16+ audit3 H3 (RFC 5054 PAD compliance, §2.6). */

#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <assert.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include "librist/librist_config.h"

#include "src/crypto/srp.h"
#include "src/crypto/srp_constants.h"
#define DEBUG_USE_EXAMPLE_CONSTANTS 1

#if HAVE_MBEDTLS
// musl's sched.h declares calloc, so include it before we redefine
// calloc to the cmocka allocator (POSIX-only header).
#ifndef _WIN32
#include <sched.h>
#endif

#define malloc(size) _test_malloc(size, __FILE__, __LINE__)
#define calloc(num, size) _test_calloc(num, size, __FILE__, __LINE__)
#define free(obj) _test_free(obj, __FILE__, __LINE__)
#endif

#include "src/crypto/srp.c"
#include "src/crypto/srp_constants.c"

/* random.c (compiled into the srp_unit binary) calls rist_log_priv3() on
 * CSPRNG init failure since release-0.2.16. The unit test deliberately
 * does not link the full logging machinery, so provide a no-op stub
 * here to satisfy the linker. The behaviour being logged - CSPRNG seed
 * failure - is not reachable from the SRP unit test paths anyway. */
#include "librist/logging.h"
void rist_log_priv3(enum rist_log_level level, const char *format, ...)
{
	(void)level;
	(void)format;
}

static void hexstr_to_uint(const char *hexstr, uint8_t *buf, size_t buf_len) {
	for (size_t i = 0, j = 0; j < buf_len; i += 2, j++)
		buf[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
}

static void uint_to_hex(const uint8_t *buf, size_t buf_len, char *outbuf) {
	size_t j;
	for (j = 0; j < buf_len; j++) {
		outbuf[2 * j] = (buf[j] >> 4) + 48;
		outbuf[2 * j + 1] = (buf[j] & 15) + 48;
		if (outbuf[2 * j] > 57)
			outbuf[2 * j] += 7;
		if (outbuf[2 * j + 1] > 57)
			outbuf[2 * j + 1] += 7;
	}
	outbuf[2 * j] = '\0';
}

struct srp_test_state {
	const char *n;
	const char *g;
	uint8_t *salt;
	size_t salt_len;
	uint8_t *incorrect_hash_verifier;
	uint8_t *correct_hash_verifier;
	size_t verifier_len;
	struct librist_crypto_srp_authenticator_ctx *wrong_hash_authenticator;
	struct librist_crypto_srp_authenticator_ctx *correct_hash_authenticator;
	struct librist_crypto_srp_client_ctx *wrong_hash_client;
	struct librist_crypto_srp_client_ctx *correct_hash_client;
};

/* The deterministic test exchange uses the 2048-bit RFC 5054 group
 * (LIBRIST_SRP_NG_DEFAULT, also the only enum-selectable group since
 * librist 0.2.15 dropped the sub-1024-bit groups for security).  The
 * full hex literal is inlined here so the test can pass it through the
 * (N_string, g_string) verifier-create and authenticator-create APIs;
 * client_ctx_create uses default_ng=true to exercise the enum path. */
static const char SRP_TEST_N_2048[] =
	"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
	"A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
	"95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
	"747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
	"8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
	"60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
	"FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
static const char SRP_TEST_G_2048[] = "2";

static int srp_test_state_setup(void **state) {
	*state = calloc(sizeof(struct srp_test_state), 1);
	struct srp_test_state *s = *state;
	s->n = SRP_TEST_N_2048;
	s->g = SRP_TEST_G_2048;
#if HAVE_MBEDTLS
	librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &s->salt, &s->salt_len, &s->incorrect_hash_verifier, &s->verifier_len, false);
	s->wrong_hash_authenticator = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->incorrect_hash_verifier, s->verifier_len, s->salt, s->salt_len, false, false);
	size_t v_len = s->verifier_len;
	free(s->salt);
	s->salt = NULL;
#endif
	librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &s->salt, &s->salt_len, &s->correct_hash_verifier, &s->verifier_len, true);
#if HAVE_MBEDTLS
	assert(v_len == s->verifier_len);
#endif
	s->correct_hash_authenticator = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->correct_hash_verifier, s->verifier_len, s->salt, s->salt_len, true, false);

	/* Client uses default_ng=true (NG_DEFAULT = 2048-bit) which matches
	 * the authenticator's inlined SRP_TEST_N_2048 above.  Passing custom
	 * sub-1024-bit N/g would (correctly) be rejected by audit3 L3. */
#if HAVE_MBEDTLS
	s->wrong_hash_client = librist_crypto_srp_client_ctx_create(true, NULL, 0, NULL, 0, s->salt, s->salt_len, false, false);
#endif
	s->correct_hash_client = librist_crypto_srp_client_ctx_create(true, NULL, 0, NULL, 0, s->salt, s->salt_len, true, false);
	return 0;
}

static int srp_test_state_teardown(void **state) {
	struct srp_test_state *s = *state;
	free(s->salt);
	free(s->incorrect_hash_verifier);
	free(s->correct_hash_verifier);
	librist_crypto_srp_authenticator_ctx_free(s->wrong_hash_authenticator);
	librist_crypto_srp_authenticator_ctx_free(s->correct_hash_authenticator);
	librist_crypto_srp_client_ctx_free(s->wrong_hash_client);
	librist_crypto_srp_client_ctx_free(s->correct_hash_client);
	free(s);
	return 0;
}

static void test_hash_func(void **state) {
	(void)(state);
	//expected hash gather via: `echo -n "rist:mainprofile" | sha256sum | awk '{print toupper($1)}'`
	const char expected_hash[] = "8427F6E0E69DC9B99DFE1052DDAF7E50D4FEA316C63C6AD23FE197C9C1DA2AF1";
	const char test_string[] = "rist:mainprofile";
	uint8_t hash_data[SHA256_DIGEST_LENGTH];
	assert_int_equal(librist_crypto_srp_hash((const uint8_t *)test_string, sizeof(test_string) -1, hash_data), 0);
	char outhash[sizeof(expected_hash)];
	uint_to_hex(hash_data, sizeof(hash_data), outhash);
	assert_string_equal(outhash, expected_hash);
}

static void test_hash_update_func(void **state) {
	(void)(state);
	const char expected_hash[] = "8427F6E0E69DC9B99DFE1052DDAF7E50D4FEA316C63C6AD23FE197C9C1DA2AF1";
	HASH_CONTEXT ctx;
	HASH_CONTEXT_INIT(&ctx, true);
	assert_int_equal(librist_crypto_srp_hash_update(&ctx, "rist", strlen("rist")), 0);
	assert_int_equal(librist_crypto_srp_hash_update(&ctx, ":", 1), 0);
	assert_int_equal(librist_crypto_srp_hash_update(&ctx, "mainprofile", strlen("mainprofile")), 0);
	uint8_t hash_data[SHA256_DIGEST_LENGTH];
	assert_int_equal(librist_crypto_srp_hash_final(&ctx, hash_data), 0);
	char outhash[sizeof(expected_hash)];
	uint_to_hex(hash_data, sizeof(hash_data), outhash);
	assert_string_equal(outhash, expected_hash);
}

static void test_get_default_ng(void **state) {
	(void)(state);
	const char *n = NULL;
	const char *g = NULL;
	assert_int_equal(librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &n, &g), 0);
	assert_string_equal(n,
		"AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
   		"A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
		"95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
		"747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
		"8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
		"60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
		"FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
	);
   	assert_string_equal(g, "2");
}

#if HAVE_MBEDTLS
static void test_srp_wrong_hashing_verifier_create(void **state) {
	struct srp_test_state *s = *state;
	const char sample_salt[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
	const char sample_verifier[] = "8A5F1D5A055C15889711054E7E3BA993D5A28773A345751BA24236AB35355B3536064A4D54D67FD41044CE543FCFD9DB99378ABD8AC5FA949BD2FC093A93E62CC501F5B70359254C9E895048CC884DF8FEA57233D985FD613EF5CA6D821B37D12C4836F4736EBBEDCFA7C944A906721355CB7ADE19756CF487807A9EDB527B78D4097D4B84EFF2F1CFE978B80F464A0002D6AE8058E37556E81154F889AE15EE1698E9F8F60281B3D1BBEDDD2EB28F5F83B9F88142E8204675F3D1F81E3FFD3149880C38299F975A757594162F70465E6BD0868A6C578319BA1262C2789B0E8CD13CF36AFC4332566EB4BCDC1FE1681B21B66D55879004DFC510FC4B33EEBB08";

	uint8_t *salt = NULL;
	size_t salt_len = 0;
	uint8_t *verifier = NULL;
	size_t verifier_len = 0;
	assert_int_equal(librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &salt, &salt_len, &verifier, &verifier_len, false), 0);

	assert_int_equal(verifier_len, (sizeof(sample_verifier) -1)/2);
	assert_int_equal(salt_len, (sizeof(sample_salt) -1)/2);

	char salt_hex[sizeof(sample_salt)];
	uint_to_hex(salt, salt_len, salt_hex);
	assert_string_equal(salt_hex, sample_salt);

	char verifier_hex[sizeof(sample_verifier)];
	uint_to_hex(verifier, verifier_len, verifier_hex);
	assert_string_equal(sample_verifier, verifier_hex);
	free(verifier);
	free(salt);
}

static void test_srp_wrong_hashing_auth_ctx_create(void **state) {
	struct srp_test_state *s = *state;
	struct librist_crypto_srp_authenticator_ctx * ctx = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->incorrect_hash_verifier, s->verifier_len, s->salt, s->salt_len, false, false);
	assert_true(ctx != NULL);

	const char well_known_n[] = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
	uint8_t n[(sizeof(well_known_n) -1)/2];
	uint8_t g[1];

	assert_int_equal(librist_crypto_srp_authenticator_write_n_bytes(ctx, n, sizeof(n)), sizeof(n));
	assert_int_equal(librist_crypto_srp_authenticator_write_g_bytes(ctx, g, sizeof(g)), sizeof(g));

	char n_hex[sizeof(well_known_n)];
	char g_hex[sizeof("02")];

	uint_to_hex(n, sizeof(n), n_hex);
	assert_string_equal(n_hex, well_known_n);

	uint_to_hex(g, sizeof(g), g_hex);
	assert_string_equal(g_hex, "02");

	librist_crypto_srp_authenticator_ctx_free(ctx);
}

static void test_srp_wrong_hashing_auth_handle_A(void **state) {
	struct srp_test_state *s = *state;
	const char client_A_hex[] = "545DD89CD403BA71172016F156A537A2D369B8551004AB521CC62D76B71BD278E687294A3D265B96393A582D8823E4BB3A7960F641D7A01DD7E13C982F06B0522EC147B1451C63F099FD08A9D5A6FD5CA73907B13E0672DEFAEF976BEA78E8F4C3E60E85B86FE68F84658D3A792D90F2FB834E657C5F1E6AAA532A3D3F4F2D747D8F3D0C0CC8F999773ED4FFE159A8B8ACB2761C6C523C68BC866EE464091B6F86720EFFB02824AC1FB31675B7F07DD2292B937C9EDE73C2420A3204CA0BBD519274B5D35771019265BE5E213C9634540A0D56EA94BA306AD1965EFF986AF8963ECE5E30E057517A0D0082205E1086520039A03D60D739FCD7BB335CBB3AF39A";
	uint8_t client_A[(sizeof(client_A_hex) -1)/2];
	hexstr_to_uint(client_A_hex, client_A, sizeof(client_A));
	assert_int_equal(librist_crypto_srp_authenticator_handle_A(s->wrong_hash_authenticator, client_A, sizeof(client_A)), 0);

	const char expected_B[] = "0C455F4A7D081DF6E3AFA0E41D121D6BAE8A28C40ABFB7898E24417C18EE6279D3A8D87A64B0B05D5B9EBB304BDEA075478052F9ED69F49AF56E5F7B321DA414289FB66B62CF7D109386AFB19B1B80C49A63B14B7F8E5649D3E6AA5C09C91BAAD31A049A719975D40F05C6B11A8E64E6CA4C0FE9D8CF45079117C78649AB058CFC36746051E6792FF143851DF3F370B56F3F3630E47B39AE42987B294762214BE29B90B9E9B980CFB5C86151DE43D1D27ECE270CE2D9FD8AB688F50311D2A786D4E339BDFE12DB544A1F782CF2ECB1B3236BDFC40152CEAB9E54851CBEDB7B1E21F068D7D9627C2A94EF91F255269993F194FC1FB07C1E466AE852B18C7A5FED";

	uint8_t B[(sizeof(expected_B) -1)/2];
	assert_int_equal(librist_crypto_srp_authenticator_write_B_bytes(s->wrong_hash_authenticator, B, sizeof(B)), sizeof(B));

	char B_hex[sizeof(expected_B)];
	uint_to_hex(B, sizeof(B), B_hex);
	assert_string_equal(expected_B, B_hex);
}

static void test_srp_wrong_hashing_auth_verify_M1(void **state) {
	struct srp_test_state *s = *state;
	const char client_M1_hex[] = "75C3E739333518C4F8C6636D1F3D54663C4CBDB6FEDC49CD82354BC145C79040";
	uint8_t client_M1[(sizeof(client_M1_hex) -1)/2];
	hexstr_to_uint(client_M1_hex, client_M1, sizeof(client_M1));

	assert_int_equal(librist_crypto_srp_authenticator_verify_m1(s->wrong_hash_authenticator, "rist", client_M1), 0);

	const char expected_m2[] = "D20842186401BE2179E01C49130B6113CD0A89E28EE4B363529C60477E32AA4A";
	char m2_hex[sizeof(expected_m2)];
	uint8_t m2[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_authenticator_write_M2_bytes(s->wrong_hash_authenticator, m2);

	uint_to_hex(m2, sizeof(m2), m2_hex);

	assert_string_equal(m2_hex, expected_m2);
}
#endif

//Nothing in client creation relies on hashing, hence this test isn't doubled
static void test_srp_client_ctx_create(void **state) {
	(void)(state);
	const char salt_hex[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";

	uint8_t salt[(sizeof(salt_hex) -1)/2];
	hexstr_to_uint(salt_hex, salt, sizeof(salt));

	/* Default-NG path. */
	struct librist_crypto_srp_client_ctx *ctx = librist_crypto_srp_client_ctx_create(true, NULL, 0, NULL, 0, salt, sizeof(salt), true, false);
	assert_true(ctx != NULL);

	/* librist_srp_client_write_A_bytes returns a byte string of length
	 * mbedtls_mpi_size(N) — 256 bytes for NG_DEFAULT (2048 bits). */
	uint8_t A[256];
	assert_int_equal(librist_crypto_srp_client_write_A_bytes(ctx, A, sizeof(A)), (ssize_t)sizeof(A));
	librist_crypto_srp_client_ctx_free(ctx);

	/* Custom-N path: anything below the 1024-bit floor is rightly
	 * rejected by audit3 L3.  Use NG_2048 hex literal. */
	uint8_t N[256];
	hexstr_to_uint(SRP_TEST_N_2048, N, sizeof(N));
	uint8_t g[1] = {0x02};
	ctx = librist_crypto_srp_client_ctx_create(false, N, sizeof(N), g, sizeof(g), salt, sizeof(salt), true, false);
	assert_true(ctx != NULL);
	assert_int_equal(librist_crypto_srp_client_write_A_bytes(ctx, A, sizeof(A)), (ssize_t)sizeof(A));
	librist_crypto_srp_client_ctx_free(ctx);
}

#if HAVE_MBEDTLS

static void test_srp_wrong_hashing_client_handle_B(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_B[] = "0C455F4A7D081DF6E3AFA0E41D121D6BAE8A28C40ABFB7898E24417C18EE6279D3A8D87A64B0B05D5B9EBB304BDEA075478052F9ED69F49AF56E5F7B321DA414289FB66B62CF7D109386AFB19B1B80C49A63B14B7F8E5649D3E6AA5C09C91BAAD31A049A719975D40F05C6B11A8E64E6CA4C0FE9D8CF45079117C78649AB058CFC36746051E6792FF143851DF3F370B56F3F3630E47B39AE42987B294762214BE29B90B9E9B980CFB5C86151DE43D1D27ECE270CE2D9FD8AB688F50311D2A786D4E339BDFE12DB544A1F782CF2ECB1B3236BDFC40152CEAB9E54851CBEDB7B1E21F068D7D9627C2A94EF91F255269993F194FC1FB07C1E466AE852B18C7A5FED";
	uint8_t B[(sizeof(server_B) -1)/2];
	hexstr_to_uint(server_B, B, sizeof(B));

	assert_int_equal(librist_crypto_srp_client_handle_B(ctx->wrong_hash_client, B, sizeof(B), "rist", "mainprofile"), 0);

	const char expected_M1[] = "75C3E739333518C4F8C6636D1F3D54663C4CBDB6FEDC49CD82354BC145C79040";
	uint8_t m1[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_client_write_M1_bytes(ctx->wrong_hash_client, m1);

	char m1_hex[sizeof(expected_M1)];
	uint_to_hex(m1, sizeof(m1), m1_hex);
	assert_string_equal(m1_hex, expected_M1);
}

static void test_srp_wrong_hashing_client_verify_M2(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_M2[] = "D20842186401BE2179E01C49130B6113CD0A89E28EE4B363529C60477E32AA4A";
	uint8_t M2[(sizeof(server_M2)-1)/2];
	hexstr_to_uint(server_M2, M2, sizeof(M2));
	assert_int_equal(librist_crypto_srp_client_verify_m2(ctx->wrong_hash_client, M2), 0);
}

#endif

static void test_srp_correct_hashing_verifier_create(void **state) {
	struct srp_test_state *s = *state;
	const char sample_salt[] = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";
	const char sample_verifier[] = "16B380409C1D6A43A96B42DD0FAC130D54A1932205F51F26AC13FB5332331C7B66A313ED969E24CB2AC5447C04FFC6565BC9FEA75A79D865FF7BB0DD65C62065EAAE7A27048F3B4C1FC0502C622FFE5B196400AD9470DB9F9DFB55CC4710081FDAEE3B63B69C15D43E189EF3E6E1C1FB1A9268F8E6DCDF16E1726585B883960EE09B318D3DD9E1C93D1B3EC98C148C00927028C1ED14D342B72811B962C233B71096BDD2EE505539DDC04ED03FDAA69926417E86016406480F8EB41317FF3D5E3B4735C76BCE67333B1F1E5E6A467E7E45A70D66EE1FC474A179697C5690AC1A525D2ADD050CC9D9824232AEC6FD8206CBEA5144AA2AC31B9865CEACF3BA2A72";

	uint8_t *salt = NULL;
	size_t salt_len = 0;
	uint8_t *verifier = NULL;
	size_t verifier_len = 0;
	assert_int_equal(librist_crypto_srp_create_verifier(s->n, s->g, "rist", "mainprofile", &salt, &salt_len, &verifier, &verifier_len, true), 0);

	assert_int_equal(verifier_len, (sizeof(sample_verifier) -1)/2);
	assert_int_equal(salt_len, (sizeof(sample_salt) -1)/2);

	char salt_hex[sizeof(sample_salt)];
	uint_to_hex(salt, salt_len, salt_hex);
	assert_string_equal(salt_hex, sample_salt);

	char verifier_hex[sizeof(sample_verifier)];
	uint_to_hex(verifier, verifier_len, verifier_hex);
	assert_string_equal(sample_verifier, verifier_hex);
	free(verifier);
	free(salt);
}

static void test_srp_correct_hashing_auth_ctx_create(void **state) {
	struct srp_test_state *s = *state;
	struct librist_crypto_srp_authenticator_ctx * ctx = librist_crypto_srp_authenticator_ctx_create(s->n, s->g, s->correct_hash_verifier, s->verifier_len, s->salt, s->salt_len, true, false);
	assert_true(ctx != NULL);

	const char well_known_n[] = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";
	uint8_t n[(sizeof(well_known_n) -1)/2];
	uint8_t g[1];

	assert_int_equal(librist_crypto_srp_authenticator_write_n_bytes(ctx, n, sizeof(n)), sizeof(n));
	assert_int_equal(librist_crypto_srp_authenticator_write_g_bytes(ctx, g, sizeof(g)), sizeof(g));

	char n_hex[sizeof(well_known_n)];
	char g_hex[sizeof("02")];

	uint_to_hex(n, sizeof(n), n_hex);
	assert_string_equal(n_hex, well_known_n);

	uint_to_hex(g, sizeof(g), g_hex);
	assert_string_equal(g_hex, "02");

	librist_crypto_srp_authenticator_ctx_free(ctx);
}

static void test_srp_correct_hashing_auth_handle_A(void **state) {
	struct srp_test_state *s = *state;
	const char client_A_hex[] = "545DD89CD403BA71172016F156A537A2D369B8551004AB521CC62D76B71BD278E687294A3D265B96393A582D8823E4BB3A7960F641D7A01DD7E13C982F06B0522EC147B1451C63F099FD08A9D5A6FD5CA73907B13E0672DEFAEF976BEA78E8F4C3E60E85B86FE68F84658D3A792D90F2FB834E657C5F1E6AAA532A3D3F4F2D747D8F3D0C0CC8F999773ED4FFE159A8B8ACB2761C6C523C68BC866EE464091B6F86720EFFB02824AC1FB31675B7F07DD2292B937C9EDE73C2420A3204CA0BBD519274B5D35771019265BE5E213C9634540A0D56EA94BA306AD1965EFF986AF8963ECE5E30E057517A0D0082205E1086520039A03D60D739FCD7BB335CBB3AF39A";
	uint8_t client_A[(sizeof(client_A_hex) -1)/2];
	hexstr_to_uint(client_A_hex, client_A, sizeof(client_A));
	assert_int_equal(librist_crypto_srp_authenticator_handle_A(s->correct_hash_authenticator, client_A, sizeof(client_A)), 0);

	const char expected_B[] = "461F82DB9BBD64DD580800C38B854437F0AE29CA14B0AD4A03797CA4EB6A27CD3C1B90E06E1C539A5FFE61E905497E78E8433F5303BEC8ECB23008DA86EBFB1B1B2FED35129BBC2ED346A810CC2A0AB20E44E2B94E048C9F9A17ABD87651CD1F2642873E487E0DDB3987D68F1B831CA8598AB88B377FAA7B06DCFE0E83A6D97FFB50D429285518209A4AEFA66F5A2BA499918209362CF0907EDC9E265156FCB8A945027F4DCDE178B8169D796187B79AA133E3BE02AF81C6AEC0B675D5F9E25E78CE00D5A0FE3BADC7106A2DAFB078BF30EF8677DD4D1EE60B50B110446C576CDDA3FA930C837938FE4AC4CF2F28185A2DD87F9524F1D5746E93D9A8FFF53626";

	uint8_t B[(sizeof(expected_B) -1)/2];
	assert_int_equal(librist_crypto_srp_authenticator_write_B_bytes(s->correct_hash_authenticator, B, sizeof(B)), sizeof(B));

	char B_hex[sizeof(expected_B)];
	uint_to_hex(B, sizeof(B), B_hex);
	assert_string_equal(expected_B, B_hex);
}

static void test_srp_correct_hashing_auth_verify_M1(void **state) {
	struct srp_test_state *s = *state;
	const char client_M1_hex[] = "2EE41138D2C447E7469EB589B89CF96FAF869B55DD684897DAB173056F1D8F90";
	uint8_t client_M1[(sizeof(client_M1_hex) -1)/2];
	hexstr_to_uint(client_M1_hex, client_M1, sizeof(client_M1));

	assert_int_equal(librist_crypto_srp_authenticator_verify_m1(s->correct_hash_authenticator, "rist", client_M1), 0);

	const char expected_m2[] = "28E0412112CD83DDC97B3395AB0D27F5C0A1EB4FA89205CD505957F53988A639";
	char m2_hex[sizeof(expected_m2)];
	uint8_t m2[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_authenticator_write_M2_bytes(s->correct_hash_authenticator, m2);

	uint_to_hex(m2, sizeof(m2), m2_hex);

	assert_string_equal(m2_hex, expected_m2);
}

static void test_srp_correct_hashing_client_handle_B(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_B[] = "461F82DB9BBD64DD580800C38B854437F0AE29CA14B0AD4A03797CA4EB6A27CD3C1B90E06E1C539A5FFE61E905497E78E8433F5303BEC8ECB23008DA86EBFB1B1B2FED35129BBC2ED346A810CC2A0AB20E44E2B94E048C9F9A17ABD87651CD1F2642873E487E0DDB3987D68F1B831CA8598AB88B377FAA7B06DCFE0E83A6D97FFB50D429285518209A4AEFA66F5A2BA499918209362CF0907EDC9E265156FCB8A945027F4DCDE178B8169D796187B79AA133E3BE02AF81C6AEC0B675D5F9E25E78CE00D5A0FE3BADC7106A2DAFB078BF30EF8677DD4D1EE60B50B110446C576CDDA3FA930C837938FE4AC4CF2F28185A2DD87F9524F1D5746E93D9A8FFF53626";
	uint8_t B[(sizeof(server_B) -1)/2];
	hexstr_to_uint(server_B, B, sizeof(B));

	assert_int_equal(librist_crypto_srp_client_handle_B(ctx->correct_hash_client, B, sizeof(B), "rist", "mainprofile"), 0);

	const char expected_M1[] = "2EE41138D2C447E7469EB589B89CF96FAF869B55DD684897DAB173056F1D8F90";
	uint8_t m1[SHA256_DIGEST_LENGTH];

	librist_crypto_srp_client_write_M1_bytes(ctx->correct_hash_client, m1);

	char m1_hex[sizeof(expected_M1)];
	uint_to_hex(m1, sizeof(m1), m1_hex);
	assert_string_equal(m1_hex, expected_M1);
}

static void test_srp_correct_hashing_client_verify_M2(void **state) {
	struct srp_test_state *ctx = *state;
	const char server_M2[] = "28E0412112CD83DDC97B3395AB0D27F5C0A1EB4FA89205CD505957F53988A639";
	uint8_t M2[(sizeof(server_M2)-1)/2];
	hexstr_to_uint(server_M2, M2, sizeof(M2));
	assert_int_equal(librist_crypto_srp_client_verify_m2(ctx->correct_hash_client, M2), 0);
}

/* Fresh authenticator+client pair using only the public SRP API.  These
 * tests do not depend on the deterministic fixture above (a/b are random
 * each run) and exercise the srp-compat=1 plumbing end-to-end.
 *
 * Four exchanges on the 2048-bit NG_DEFAULT group:
 *   1. Both PAD (default)               → handshake succeeds (verify_m1 == 0)
 *   2. Both LEGACY (unpadded)           → handshake succeeds (verify_m1 == 0)
 *   3. Authenticator PAD, client LEGACY → handshake fails (verify_m1 != 0)
 *   4. Authenticator LEGACY, client PAD → handshake fails (verify_m1 != 0)
 *
 * Cases 3 and 4 are the "operator forgot to set srp-compat=1 on one side"
 * scenarios.  They MUST fail at M1 (otherwise the legacy-bypass would be
 * leaking through), but we do not attempt to detect the cross-mode case
 * cryptographically — that is impossible without changing the wire
 * protocol because the SRP-6a identity (Av^u)^b = (B - kg^x)^(a+ux)
 * only holds when both sides use the same k. */
static int srp_run_exchange(bool auth_legacy, bool client_legacy) {
	const char *username = "rist";
	const char *password = "mainprofile";
	const char *n = NULL;
	const char *g = NULL;
	if (librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &n, &g) != 0)
		return -100;

	uint8_t *salt = NULL;
	size_t   salt_len = 0;
	uint8_t *verifier = NULL;
	size_t   verifier_len = 0;
	if (librist_crypto_srp_create_verifier(n, g, username, password, &salt, &salt_len, &verifier, &verifier_len, true) != 0)
		return -101;

	struct librist_crypto_srp_authenticator_ctx *auth =
		librist_crypto_srp_authenticator_ctx_create(n, g, verifier, verifier_len, salt, salt_len, true, auth_legacy);
	struct librist_crypto_srp_client_ctx *client =
		librist_crypto_srp_client_ctx_create(true, NULL, 0, NULL, 0, salt, salt_len, true, client_legacy);
	int ret = -102;
	if (auth == NULL || client == NULL)
		goto out;

	uint8_t A[256];
	int alen = librist_crypto_srp_client_write_A_bytes(client, A, sizeof(A));
	if (alen != (int)sizeof(A))
		goto out;
	if (librist_crypto_srp_authenticator_handle_A(auth, A, sizeof(A)) != 0)
		goto out;

	uint8_t B[256];
	if (librist_crypto_srp_authenticator_write_B_bytes(auth, B, sizeof(B)) != (int)sizeof(B))
		goto out;
	if (librist_crypto_srp_client_handle_B(client, B, sizeof(B), username, password) != 0)
		goto out;

	uint8_t M1[SHA256_DIGEST_LENGTH];
	librist_crypto_srp_client_write_M1_bytes(client, M1);

	/* The value under test: 0 on a matching mode-pair, -2 on a
	 * mode-mismatch the diagnostic recognised, -1 on opaque failure. */
	ret = librist_crypto_srp_authenticator_verify_m1(auth, username, M1);

out:
	librist_crypto_srp_authenticator_ctx_free(auth);
	librist_crypto_srp_client_ctx_free(client);
	free(verifier);
	free(salt);
	return ret;
}

static void test_srp_compat_both_pad(void **state) {
	(void)state;
	assert_int_equal(srp_run_exchange(false, false), 0);
}
static void test_srp_compat_both_legacy(void **state) {
	(void)state;
	assert_int_equal(srp_run_exchange(true, true), 0);
}
static void test_srp_compat_mismatch_auth_pad_client_legacy(void **state) {
	(void)state;
	assert_int_not_equal(srp_run_exchange(false, true), 0);
}
static void test_srp_compat_mismatch_auth_legacy_client_pad(void **state) {
	(void)state;
	assert_int_not_equal(srp_run_exchange(true, false), 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_func),
		cmocka_unit_test(test_hash_update_func),
		cmocka_unit_test(test_get_default_ng),
#if HAVE_MBEDTLS
		cmocka_unit_test(test_srp_wrong_hashing_auth_handle_A),
		cmocka_unit_test(test_srp_wrong_hashing_auth_verify_M1),
		cmocka_unit_test(test_srp_wrong_hashing_verifier_create),
		cmocka_unit_test(test_srp_wrong_hashing_auth_ctx_create),
#endif
		cmocka_unit_test(test_srp_correct_hashing_verifier_create),
		cmocka_unit_test(test_srp_correct_hashing_auth_ctx_create),
		cmocka_unit_test(test_srp_correct_hashing_auth_handle_A),
		cmocka_unit_test(test_srp_correct_hashing_auth_verify_M1),
		cmocka_unit_test(test_srp_client_ctx_create),
#if HAVE_MBEDTLS
		cmocka_unit_test(test_srp_wrong_hashing_client_handle_B),
		cmocka_unit_test(test_srp_wrong_hashing_client_verify_M2),
#endif
		cmocka_unit_test(test_srp_correct_hashing_client_handle_B),
		cmocka_unit_test(test_srp_correct_hashing_client_verify_M2),
		cmocka_unit_test(test_srp_compat_both_pad),
		cmocka_unit_test(test_srp_compat_both_legacy),
		cmocka_unit_test(test_srp_compat_mismatch_auth_pad_client_legacy),
		cmocka_unit_test(test_srp_compat_mismatch_auth_legacy_client_pad),
	};

    return cmocka_run_group_tests(tests, srp_test_state_setup, srp_test_state_teardown);
}
