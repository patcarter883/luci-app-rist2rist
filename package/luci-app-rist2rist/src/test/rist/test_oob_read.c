/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Coverage for the polling out-of-band receive API (rist_oob_read).
 * A sender pushes OOB packets to a receiver that has oob enabled with a
 * NULL callback; the receiver must be able to drain them through
 * rist_oob_read() and see the exact payloads back.
 */

#include "librist/librist.h"
#include "rist-private.h"
#include <stdatomic.h>
#include <inttypes.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define msleep(ms) Sleep(ms)
#else
#include <unistd.h>
#define msleep(ms) usleep((ms) * 1000)
#endif

#define OOB_PAYLOAD_PREFIX "RIST-OOB-TEST-PACKET-"
#define OOB_TARGET_COUNT 25

atomic_ulong stop;

struct rist_logging_settings *logging_settings_sender = NULL;
struct rist_logging_settings *logging_settings_receiver = NULL;
char *senderstring = "sender";
char *receiverstring = "receiver";

static struct rist_peer *sender_peer = NULL;

static int log_callback(void *arg, int level, const char *msg) {
    /* Print but never fail the test on a log line: oob is best effort and a
     * transient "no oob peer" during connection setup is expected. */
    if (level <= RIST_LOG_ERROR)
        fprintf(stdout, "[%s] [ERROR] %s", (char *)arg, msg);
    else
        fprintf(stdout, "[%s] %s", (char *)arg, msg);
    return 0;
}

static struct rist_ctx *setup_rist_receiver(int profile, const char *url) {
    struct rist_ctx *ctx;
    if (rist_receiver_create(&ctx, profile, logging_settings_receiver) != 0)
        return NULL;
    struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config))
        return NULL;
    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config) == -1) {
        free((void *)peer_config);
        return NULL;
    }
    free((void *)peer_config);
    if (rist_oob_callback_set(ctx, NULL, NULL) != 0) {
        rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not enable oob on receiver\n");
        return NULL;
    }
    if (rist_start(ctx) == -1)
        return NULL;
    return ctx;
}

static struct rist_ctx *setup_rist_sender(int profile, const char *url) {
    struct rist_ctx *ctx;
    if (rist_sender_create(&ctx, profile, 0, logging_settings_sender) != 0)
        return NULL;
    const struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config))
        return NULL;
    if (rist_peer_create(ctx, &sender_peer, peer_config) == -1) {
        free((void *)peer_config);
        return NULL;
    }
    free((void *)peer_config);
    if (rist_oob_callback_set(ctx, NULL, NULL) != 0) {
        rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not enable oob on sender\n");
        return NULL;
    }
    if (rist_start(ctx) == -1)
        return NULL;
    return ctx;
}

static PTHREAD_START_FUNC(send_oob, arg) {
    struct rist_ctx *sender = arg;
    char buffer[128];
    int counter = 0;
    /* ~6s worth of attempts at ~2ms spacing */
    while (counter < 3000 && !atomic_load(&stop)) {
        int len = snprintf(buffer, sizeof(buffer), "%s%d", OOB_PAYLOAD_PREFIX, counter);
        struct rist_oob_block oob = { 0 };
        oob.peer = sender_peer;
        oob.payload = buffer;
        oob.payload_len = (size_t)len + 1; /* include NUL for easy compare */
        rist_oob_write(sender, &oob); /* best effort; ignore transient errors */
        counter++;
        msleep(2);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int profile = (argc > 1) ? atoi(argv[1]) : 1;
    const char *recv_url = (argc > 2) ? argv[2] : "rist://@127.0.0.1:8190";
    const char *send_url = (argc > 3) ? argv[3] : "rist://127.0.0.1:8190";

    atomic_init(&stop, 0);

    fprintf(stdout, "Testing oob polling read on profile %d (recv %s, send %s)\n",
            profile, recv_url, send_url);

    if (rist_logging_set(&logging_settings_sender, RIST_LOG_INFO, log_callback, senderstring, NULL, stderr) != 0)
        return 99;
    if (rist_logging_set(&logging_settings_receiver, RIST_LOG_INFO, log_callback, receiverstring, NULL, stderr) != 0)
        return 99;

    struct rist_ctx *receiver_ctx = setup_rist_receiver(profile, recv_url);
    struct rist_ctx *sender_ctx = setup_rist_sender(profile, send_url);
    int ret = 0;
    if (!receiver_ctx || !sender_ctx) {
        ret = 99;
        goto out;
    }

    pthread_t send_loop;
    if (pthread_create(&send_loop, NULL, send_oob, (void *)sender_ctx) != 0) {
        ret = 99;
        goto out;
    }

    int received = 0;
    int last_seen = -1;
    bool ordered = true;
    /* poll for up to ~8 seconds */
    for (int i = 0; i < 4000 && received < OOB_TARGET_COUNT; i++) {
        const struct rist_oob_block *oob = NULL;
        int avail = rist_oob_read(receiver_ctx, &oob);
        if (avail < 0) {
            fprintf(stderr, "rist_oob_read returned error %d\n", avail);
            ret = 1;
            break;
        }
        if (avail == 0 || oob == NULL) {
            msleep(2);
            continue;
        }
        /* validate payload shape */
        if (oob->payload_len < strlen(OOB_PAYLOAD_PREFIX) + 1 ||
            memcmp(oob->payload, OOB_PAYLOAD_PREFIX, strlen(OOB_PAYLOAD_PREFIX)) != 0) {
            fprintf(stderr, "Unexpected oob payload (len %zu)\n", oob->payload_len);
            ret = 1;
            break;
        }
        int seq = atoi((const char *)oob->payload + strlen(OOB_PAYLOAD_PREFIX));
        if (seq <= last_seen)
            ordered = false; /* not fatal: oob is unordered/best effort, just note */
        last_seen = seq;
        if (oob->peer == NULL) {
            fprintf(stderr, "oob block missing peer\n");
            ret = 1;
            break;
        }
        received++;
    }

    atomic_store(&stop, 1);
    pthread_join(send_loop, NULL);

    fprintf(stdout, "Received %d oob packets (target %d), ordered=%s\n",
            received, OOB_TARGET_COUNT, ordered ? "yes" : "no");
    if (ret == 0 && received < OOB_TARGET_COUNT) {
        fprintf(stderr, "FAIL: only %d/%d oob packets read back\n", received, OOB_TARGET_COUNT);
        ret = 1;
    }

out:
    if (sender_ctx)
        rist_destroy(sender_ctx);
    if (receiver_ctx)
        rist_destroy(receiver_ctx);
    free(logging_settings_sender);
    free(logging_settings_receiver);
    if (ret > 0 && ret != 99) {
        fprintf(stderr, "FAIL\n");
        return ret;
    }
    if (ret == 99)
        return 99;
    fprintf(stdout, "OK\n");
    return 0;
}
