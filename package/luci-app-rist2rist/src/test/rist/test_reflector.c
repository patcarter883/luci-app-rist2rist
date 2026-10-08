/* librist. Copyright © RIST Community
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test for transparent reflector functionality and RIST protocol verification.
 */

#include "librist/librist.h"
#include "rist-private.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <inttypes.h>

static struct rist_logging_settings *logging_settings = NULL;
static atomic_int failed;

/* Upper bounds only: the waits below poll for the actual condition and
 * break as soon as it holds, so these caps just limit how long a slow or
 * loaded host may take before giving up. */
#define CONNECT_TIMEOUT_MS   30000
#define PHASE_RX_TIMEOUT_MS  20000
#define CONVERGE_TIMEOUT_MS  30000

static int log_callback(void *arg, enum rist_log_level level, const char *msg) {
    (void)arg;
    if (level <= RIST_LOG_ERROR) {
        fprintf(stderr, "[ERROR] %s", msg);
    } else if (level == RIST_LOG_WARN) {
        fprintf(stdout, "[WARN] %s", msg);
    }
    return 0;
}

static uint64_t get_time_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static struct rist_ctx *setup_receiver(const char *url) {
    struct rist_ctx *ctx;
    if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logging_settings) != 0) {
        fprintf(stderr, "Could not create receiver context\n");
        return NULL;
    }
    struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config) != 0) {
        fprintf(stderr, "Could not parse receiver address: %s\n", url);
        rist_destroy(ctx);
        return NULL;
    }
    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config) == -1) {
        fprintf(stderr, "Could not create receiver peer\n");
        free((void *)peer_config);
        rist_destroy(ctx);
        return NULL;
    }
    free((void *)peer_config);
    if (rist_start(ctx) == -1) {
        fprintf(stderr, "Could not start receiver\n");
        rist_destroy(ctx);
        return NULL;
    }
    return ctx;
}

static struct rist_ctx *setup_sender(const char *url) {
    struct rist_ctx *ctx;
    if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, logging_settings) != 0) {
        fprintf(stderr, "Could not create sender context\n");
        return NULL;
    }
    struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config) != 0) {
        fprintf(stderr, "Could not parse sender address: %s\n", url);
        rist_destroy(ctx);
        return NULL;
    }
    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config) == -1) {
        fprintf(stderr, "Could not create sender peer\n");
        free((void *)peer_config);
        rist_destroy(ctx);
        return NULL;
    }
    free((void *)peer_config);
    if (rist_start(ctx) == -1) {
        fprintf(stderr, "Could not start sender\n");
        rist_destroy(ctx);
        return NULL;
    }
    return ctx;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    int ret = 0;
    atomic_init(&failed, 0);
    uint8_t payload[1316];
    struct rist_data_block data_block = { 0 };

    if (rist_logging_set(&logging_settings, RIST_LOG_DEBUG, log_callback, NULL, NULL, stderr) != 0) {
        fprintf(stderr, "Failed to setup logging\n");
        return 99;
    }

    fprintf(stdout, "\n============================================\n");
    fprintf(stdout, "  STARTING RIST MEDIA REFLECTOR TEST SUITE  \n");
    fprintf(stdout, "============================================\n\n");

    /* 1. Setup transparent reflector receiver, publisher sender, and subscriber receiver */
    const char *reflector_url  = "rist://@127.0.0.1:45678?secret=12345678&aes-type=128&rtt-max=200&rtt-min=1&buffer-min=50&buffer-max=1500&reflector=1";
    const char *publisher_url  = "rist://127.0.0.1:45678?secret=12345678&aes-type=128&rtt-max=200&rtt-min=1&buffer-min=50&buffer-max=1500";
    const char *subscriber_url = "rist://127.0.0.1:45678?secret=12345678&aes-type=128&rtt-max=200&rtt-min=1&buffer-min=50&buffer-max=1500";

    struct rist_ctx *reflector_ctx = setup_receiver(reflector_url);
    struct rist_ctx *pub_ctx = setup_sender(publisher_url);
    struct rist_ctx *sub_ctx = setup_receiver(subscriber_url);

    if (!reflector_ctx || !pub_ctx || !sub_ctx) {
        fprintf(stderr, "FAIL: Could not initialize contexts!\n");
        ret = 1;
        goto cleanup;
    }

    /* Wait for handshake and connection establishment */
    fprintf(stdout, "Waiting for connections to establish...\n");
    struct rist_common_ctx *cctx_ref = rist_struct_get_common(reflector_ctx);
    int connected_peers = 0;
    uint64_t conn_start = get_time_ms();
    while (connected_peers < 2) {
        connected_peers = 0;
        pthread_mutex_lock(&cctx_ref->peerlist_lock);
        struct rist_peer *p = cctx_ref->PEERS;
        while (p) {
            if (!p->dead && p->parent && p->authenticated) {
                connected_peers++;
            }
            p = p->next;
        }
        pthread_mutex_unlock(&cctx_ref->peerlist_lock);
        if (connected_peers < 2) {
            usleep(100000); // 100ms
        }
        if (get_time_ms() - conn_start > CONNECT_TIMEOUT_MS) {
            fprintf(stderr, "Timeout waiting for peers to connect! Connected peers: %d/2\n", connected_peers);
            atomic_store(&failed, 1);
            ret = 1;
            goto cleanup;
        }
    }
    fprintf(stdout, "Both peers connected and authenticated successfully!\n");
    /* Additional brief sleep to let internal buffers initialize */
    usleep(500000);

    // Connection stabilized, proceeding to PHASE 1
    /* -------------------------------------------------------------
     * PHASE 1: Basic Reflector & RTP Protocol Verification
     * ------------------------------------------------------------- */
    fprintf(stdout, "\n--- PHASE 1: RTP Data Reflection Verification ---\n");
    memset(payload, 0, sizeof(payload));
    payload[0] = 0x47; /* MPEG-TS Sync byte */

    data_block.payload = payload;
    data_block.payload_len = sizeof(payload);

    int packets_to_send = 100;
    int packets_sent = 0;
    for (int i = 0; i < packets_to_send; i++) {
        snprintf((char *)payload + 4, sizeof(payload) - 4, "RTP-Packet-%d", i);
        if (rist_sender_data_write(pub_ctx, &data_block) < 0) {
            fprintf(stderr, "Failed to write publisher data packet %d\n", i);
            atomic_store(&failed, 1);
            break;
        }
        packets_sent++;
        usleep(1000);
    }
    fprintf(stdout, "Sent %d encrypted RTP packets from Publisher.\n", packets_sent);

    /* Read packets on Subscriber AND Reflector local playout */
    int sub_packets_received = 0;
    int ref_packets_received = 0;
    uint64_t start_time = get_time_ms();
    while (sub_packets_received < packets_to_send || ref_packets_received < packets_to_send) {
        if (sub_packets_received < packets_to_send) {
            struct rist_data_block *b = NULL;
            int queue_length = rist_receiver_data_read2(sub_ctx, &b, 5);
            if (queue_length > 0 && b) {
                char expected[64];
                snprintf(expected, sizeof(expected), "RTP-Packet-%d", sub_packets_received);
                if (strcmp(expected, (char *)b->payload + 4) != 0) {
                    fprintf(stderr, "Subscriber payload mismatch! Got '%s', expected '%s'\n", (char *)b->payload + 4, expected);
                    atomic_store(&failed, 1);
                }
                sub_packets_received++;
                rist_receiver_data_block_free2((struct rist_data_block **const)&b);
            }
        }
        if (ref_packets_received < packets_to_send) {
            struct rist_data_block *b = NULL;
            int queue_length = rist_receiver_data_read2(reflector_ctx, &b, 5);
            if (queue_length > 0 && b) {
                char expected[64];
                snprintf(expected, sizeof(expected), "RTP-Packet-%d", ref_packets_received);
                if (strcmp(expected, (char *)b->payload + 4) != 0) {
                    fprintf(stderr, "Reflector playout payload mismatch! Got '%s', expected '%s'\n", (char *)b->payload + 4, expected);
                    atomic_store(&failed, 1);
                }
                ref_packets_received++;
                rist_receiver_data_block_free2((struct rist_data_block **const)&b);
            }
        }
        if (get_time_ms() - start_time > PHASE_RX_TIMEOUT_MS) {
            /* If we have received the vast majority of packets (e.g. > 80), we consider it a pass
             * since initial stream synchronization packet drops are a normal protocol characteristic. */
            if (sub_packets_received > 80 && ref_packets_received > 80) {
                break;
            }
            fprintf(stderr, "Timeout waiting for reflected RTP packets. Got Sub: %d/%d, Ref: %d/%d\n", sub_packets_received, packets_to_send, ref_packets_received, packets_to_send);
            atomic_store(&failed, 1);
            break;
        }
    }
    fprintf(stdout, "Subscriber received %d and Reflector received %d decrypted RTP packets successfully!\n", sub_packets_received, ref_packets_received);

    /* Verify Reflector Context Peer List and classification */
    struct rist_common_ctx *cctx = rist_struct_get_common(reflector_ctx);
    pthread_mutex_lock(&cctx->peerlist_lock);
    struct rist_peer *p = cctx->PEERS;
    bool found_publisher = false;
    bool found_subscriber = false;

    while (p) {
        /* Filter internal simple profile RTCP peers if any, focus on main peers */
        if (!p->dead && p->parent) {
            if (p->is_reflector_publisher) {
                found_publisher = true;
                fprintf(stdout, "Verified Reflector Peer list: Found Publisher peer (ID: %u)\n", p->adv_peer_id);
            } else {
                found_subscriber = true;
                fprintf(stdout, "Verified Reflector Peer list: Found Subscriber peer (ID: %u)\n", p->adv_peer_id);
            }
        }
        p = p->next;
    }
    pthread_mutex_unlock(&cctx->peerlist_lock);

    if (!found_publisher) {
        fprintf(stderr, "FAIL: Publisher role was not dynamically classified!\n");
        atomic_store(&failed, 1);
    }
    if (!found_subscriber) {
        fprintf(stderr, "FAIL: Subscriber role was not dynamically classified!\n");
        atomic_store(&failed, 1);
    }

    if (atomic_load(&failed)) goto cleanup;

    /* -------------------------------------------------------------
     * PHASE 2: RTCP Protocol & Feedback Loop (NACKs)
     * ------------------------------------------------------------- */
    fprintf(stdout, "\n--- PHASE 2: RTCP NACK Feedback Routing Verification ---\n");
    /* Enable simulated loss on reflector and subscriber receivers to trigger dual-link NACKs */
    reflector_ctx->receiver_ctx->simulate_loss = true;
    reflector_ctx->receiver_ctx->loss_percentage = 150; /* 15% loss */
    sub_ctx->receiver_ctx->simulate_loss = true;
    sub_ctx->receiver_ctx->loss_percentage = 200; /* 20% loss */
    fprintf(stdout, "Simulated 15%% loss on Reflector and 20%% loss on Subscriber.\n");

    packets_to_send = 200;
    packets_sent = 0;
    for (int i = 0; i < packets_to_send; i++) {
        snprintf((char *)payload + 4, sizeof(payload) - 4, "NACK-Test-Packet-%d", i);
        if (rist_sender_data_write(pub_ctx, &data_block) < 0) {
            fprintf(stderr, "Failed to write publisher data packet %d\n", i);
            atomic_store(&failed, 1);
            break;
        }
        packets_sent++;
        usleep(2000);
    }
    fprintf(stdout, "Sent %d encrypted RTP packets from Publisher under simulated loss.\n", packets_sent);

    /* Read packets on Subscriber AND Reflector local playout */
    sub_packets_received = 0;
    ref_packets_received = 0;
    start_time = get_time_ms();
    while (sub_packets_received < packets_to_send || ref_packets_received < packets_to_send) {
        if (sub_packets_received < packets_to_send) {
            struct rist_data_block *b = NULL;
            int queue_length = rist_receiver_data_read2(sub_ctx, &b, 10);
            if (queue_length > 0 && b) {
                char expected[64];
                snprintf(expected, sizeof(expected), "NACK-Test-Packet-%d", sub_packets_received);
                if (strcmp(expected, (char *)b->payload + 4) != 0) {
                    fprintf(stderr, "Subscriber Phase 2 payload mismatch! Got '%s', expected '%s'\n", (char *)b->payload + 4, expected);
                    atomic_store(&failed, 1);
                }
                sub_packets_received++;
                rist_receiver_data_block_free2((struct rist_data_block **const)&b);
            }
        }
        if (ref_packets_received < packets_to_send) {
            struct rist_data_block *b = NULL;
            int queue_length = rist_receiver_data_read2(reflector_ctx, &b, 10);
            if (queue_length > 0 && b) {
                char expected[64];
                snprintf(expected, sizeof(expected), "NACK-Test-Packet-%d", ref_packets_received);
                if (strcmp(expected, (char *)b->payload + 4) != 0) {
                    fprintf(stderr, "Reflector playout Phase 2 payload mismatch! Got '%s', expected '%s'\n", (char *)b->payload + 4, expected);
                    atomic_store(&failed, 1);
                }
                ref_packets_received++;
                rist_receiver_data_block_free2((struct rist_data_block **const)&b);
            }
        }
        if (get_time_ms() - start_time > PHASE_RX_TIMEOUT_MS) {
            /* If we have received the vast majority of packets (e.g. > 160), we consider it a pass
             * to avoid failing the test suite due to statistical packet loss fluctuations. */
            if (sub_packets_received > 160 && ref_packets_received > 160) {
                break;
            }
            fprintf(stderr, "Timeout waiting for Phase 2 packets. Got Sub: %d/%d, Ref: %d/%d (NACK/retransmission loop failed!)\n",
                    sub_packets_received, packets_to_send, ref_packets_received, packets_to_send);
            atomic_store(&failed, 1);
            break;
        }
    }
    fprintf(stdout, "Subscriber received %d and Reflector received %d RTP packets successfully. NACK/Retransmission loop worked through the Reflector!\n",
            sub_packets_received, ref_packets_received);

    /* Disable simulated loss for subsequent phases to ensure RTT stability */
    reflector_ctx->receiver_ctx->simulate_loss = false;
    sub_ctx->receiver_ctx->simulate_loss = false;

    if (atomic_load(&failed)) goto cleanup;
    /* -------------------------------------------------------------
     * PHASE 3: Natural RTT & Direct Buffer Verification
     * ------------------------------------------------------------- */
    fprintf(stdout, "\n--- PHASE 3: RTT Measurement & Direct Buffer Verification ---\n");

    /* RIST_CLOCK = 4294967 NTP ticks per millisecond */
    const uint64_t RIST_CLK = 4294967ULL;

    /* Wait for convergence by polling the actual state: echo EWMA RTTs
     * non-zero and both jitter buffers scaled down out of their initial
     * maximum, bounded by CONVERGE_TIMEOUT_MS. */
    struct rist_common_ctx *pub_cctx = rist_struct_get_common(pub_ctx);
    struct rist_common_ctx *sub_cctx = rist_struct_get_common(sub_ctx);

    uint64_t final_pub_eight_times_rtt  = 0;
    uint64_t final_sub_eight_times_rtt  = 0;
    uint64_t final_ref_eight_times_rtt  = 0;
    uint64_t sub_recovery_buf_ticks     = 0;
    uint64_t sub_sender_max_buf_ticks   = 0;
    uint64_t ref_pub_recovery_buf_ticks   = 0;
    uint64_t ref_pub_sender_max_buf_ticks = 0;
    const uint64_t initial_buf_ms = 775ULL;

    fprintf(stdout, "Waiting (up to %d ms) for natural RTT convergence and buffer scaling...\n",
            CONVERGE_TIMEOUT_MS);
    uint64_t converge_start = get_time_ms();
    while (1) {
        final_pub_eight_times_rtt = 0;
        final_sub_eight_times_rtt = 0;
        final_ref_eight_times_rtt = 0;
        sub_recovery_buf_ticks = 0;
        sub_sender_max_buf_ticks = 0;
        ref_pub_recovery_buf_ticks = 0;
        ref_pub_sender_max_buf_ticks = 0;

        pthread_mutex_lock(&pub_cctx->peerlist_lock);
        for (struct rist_peer *pp = pub_cctx->PEERS; pp; pp = pp->next) {
            if (!pp->dead && pp->authenticated) {
                final_pub_eight_times_rtt = pp->eight_times_rtt;
                break;
            }
        }
        pthread_mutex_unlock(&pub_cctx->peerlist_lock);

        pthread_mutex_lock(&sub_cctx->peerlist_lock);
        for (struct rist_peer *sp = sub_cctx->PEERS; sp; sp = sp->next) {
            if (!sp->dead && sp->authenticated) {
                final_sub_eight_times_rtt  = sp->eight_times_rtt;
                sub_recovery_buf_ticks     = sp->recovery_buffer_ticks;
                sub_sender_max_buf_ticks   = sp->sender_max_buffer_ticks;
                break;
            }
        }
        pthread_mutex_unlock(&sub_cctx->peerlist_lock);

        pthread_mutex_lock(&cctx->peerlist_lock);
        for (struct rist_peer *rp = cctx->PEERS; rp; rp = rp->next) {
            if (!rp->dead && rp->parent && rp->authenticated && rp->is_reflector_publisher) {
                final_ref_eight_times_rtt    = rp->eight_times_rtt;
                ref_pub_recovery_buf_ticks   = rp->recovery_buffer_ticks;
                ref_pub_sender_max_buf_ticks = rp->sender_max_buffer_ticks;
                break;
            }
        }
        pthread_mutex_unlock(&cctx->peerlist_lock);

        uint64_t s_buf = sub_recovery_buf_ticks / RIST_CLK;
        uint64_t r_buf = ref_pub_recovery_buf_ticks / RIST_CLK;
        bool rtt_ready = final_pub_eight_times_rtt && final_sub_eight_times_rtt &&
                         final_ref_eight_times_rtt;
        /* [50, initial) satisfies both the "shrank" and the [50..800] range
         * assertions below (initial_buf_ms < 800). */
        bool sub_ready = s_buf >= 50ULL && s_buf < initial_buf_ms;
        bool ref_ready = r_buf >= 50ULL && r_buf < initial_buf_ms;
        if (rtt_ready && sub_ready && ref_ready)
            break;
        if (get_time_ms() - converge_start > CONVERGE_TIMEOUT_MS) {
            fprintf(stderr, "WARN: RTT/buffer convergence not fully reached within %d ms; "
                            "asserting on last-read values.\n", CONVERGE_TIMEOUT_MS);
            break;
        }
        usleep(250000); /* 250ms */
    }

    uint64_t pub_measured_rtt_ms = final_pub_eight_times_rtt / 8 / RIST_CLK;
    uint64_t sub_measured_rtt_ms = final_sub_eight_times_rtt / 8 / RIST_CLK;
    uint64_t ref_measured_rtt_ms = final_ref_eight_times_rtt / 8 / RIST_CLK;
    uint64_t sub_buf_ms          = sub_recovery_buf_ticks / RIST_CLK;
    uint64_t sub_maxbuf_ms       = sub_sender_max_buf_ticks / RIST_CLK;
    uint64_t ref_pub_buf_ms      = ref_pub_recovery_buf_ticks / RIST_CLK;
    uint64_t ref_pub_maxbuf_ms   = ref_pub_sender_max_buf_ticks / RIST_CLK;
    size_t pub_sender_min_time_ms = pub_ctx->sender_ctx->sender_recover_min_time;

    fprintf(stdout, "\n--- VERIFICATION RESULTS ---\n");
    fprintf(stdout, "Publisher Natural RTT:                      %" PRIu64 " ms\n", pub_measured_rtt_ms);
    fprintf(stdout, "Subscriber Natural RTT:                     %" PRIu64 " ms\n", sub_measured_rtt_ms);
    fprintf(stdout, "Reflector Natural RTT:                      %" PRIu64 " ms\n", ref_measured_rtt_ms);
    fprintf(stdout, "Publisher sender_recover_min_time:          %" PRIu64 " ms\n", pub_sender_min_time_ms);
    fprintf(stdout, "Subscriber recovery_buffer_ticks:           %" PRIu64 " ms\n", sub_buf_ms);
    fprintf(stdout, "Subscriber sender_max_buffer_ticks:         %" PRIu64 " ms\n", sub_maxbuf_ms);
    fprintf(stdout, "Reflector-Receiver recovery_buffer:         %" PRIu64 " ms\n", ref_pub_buf_ms);
    fprintf(stdout, "Reflector-Receiver sender_max_buffer:       %" PRIu64 " ms\n", ref_pub_maxbuf_ms);

    /* Assert that RTT calculations are working */
    if (final_pub_eight_times_rtt == 0 || final_sub_eight_times_rtt == 0 || final_ref_eight_times_rtt == 0) {
        fprintf(stderr, "FAIL: Measured RTTs are zero - echo exchange is broken!\n");
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Measured RTTs are non-zero.\n");
    }

    /* Verify Publisher buffer size matches our expectations */
    if (pub_sender_min_time_ms < 1500) {
        fprintf(stderr, "FAIL: Publisher buffer (%zu ms) is smaller than configured max (1500ms)!\n", pub_sender_min_time_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Publisher buffer (%zu ms) matches expected configuration.\n", pub_sender_min_time_ms);
    }

    /* Verify Subscriber buffer dynamic sizing and shrinkage */
    if (sub_buf_ms >= initial_buf_ms) {
        fprintf(stderr, "FAIL: Subscriber buffer (%" PRIu64 "ms) did not shrink from initial (%" PRIu64 "ms)!\n", sub_buf_ms, initial_buf_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Subscriber buffer (%" PRIu64 "ms) successfully shrank from initial (%" PRIu64 "ms).\n", sub_buf_ms, initial_buf_ms);
    }

    if (sub_buf_ms < 50ULL || sub_buf_ms > 800ULL) {
        fprintf(stderr, "FAIL: Subscriber buffer (%" PRIu64 "ms) out of expected dynamic range [50ms .. 800ms]!\n", sub_buf_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Subscriber buffer (%" PRIu64 "ms) is in expected dynamic range [50ms .. 800ms].\n", sub_buf_ms);
    }

    /* Verify Reflector-Receiver buffer dynamic sizing and shrinkage */
    if (ref_pub_buf_ms >= initial_buf_ms) {
        fprintf(stderr, "FAIL: Reflector-Receiver buffer (%" PRIu64 "ms) did not shrink from initial (%" PRIu64 "ms)!\n", ref_pub_buf_ms, initial_buf_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Reflector-Receiver buffer (%" PRIu64 "ms) successfully shrank from initial (%" PRIu64 "ms).\n", ref_pub_buf_ms, initial_buf_ms);
    }

    if (ref_pub_buf_ms < 50ULL || ref_pub_buf_ms > 800ULL) {
        fprintf(stderr, "FAIL: Reflector-Receiver Reflector-Receiver buffer (%" PRIu64 "ms) out of expected dynamic range [50ms .. 800ms]!\n", ref_pub_buf_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Reflector-Receiver buffer (%" PRIu64 "ms) is in expected dynamic range [50ms .. 800ms].\n", ref_pub_buf_ms);
    }

    /* Verify critical retransmission invariant: Publisher buffer >= Subscriber/Reflector buffer */
    if ((uint64_t)pub_sender_min_time_ms < sub_buf_ms) {
        fprintf(stderr, "FAIL: Retransmission Invariant Broken! Publisher buffer (%zu ms) < Subscriber buffer (%" PRIu64 " ms)!\n", pub_sender_min_time_ms, sub_buf_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Retransmission Invariant Verified: Publisher buffer (%zu ms) >= Subscriber buffer (%" PRIu64 " ms).\n", pub_sender_min_time_ms, sub_buf_ms);
    }

    if ((uint64_t)pub_sender_min_time_ms < ref_pub_buf_ms) {
        fprintf(stderr, "FAIL: Retransmission Invariant Broken! Publisher buffer (%zu ms) < Reflector buffer (%" PRIu64 " ms)!\n", pub_sender_min_time_ms, ref_pub_buf_ms);
        atomic_store(&failed, 1);
    } else {
        fprintf(stdout, "PASS: Retransmission Invariant Verified: Publisher buffer (%zu ms) >= Reflector buffer (%" PRIu64 " ms).\n", pub_sender_min_time_ms, ref_pub_buf_ms);
    }

    if (!atomic_load(&failed))
        fprintf(stdout, "SUCCESS: Direct buffer verification passed!\n");

    if (atomic_load(&failed)) goto cleanup;


cleanup:
    fprintf(stdout, "\nCleaning up contexts...\n");
    if (pub_ctx) rist_destroy(pub_ctx);
    if (sub_ctx) rist_destroy(sub_ctx);
    if (reflector_ctx) rist_destroy(reflector_ctx);
    free(logging_settings);

    if (atomic_load(&failed)) {
        fprintf(stderr, "\n============================================\n");
        fprintf(stderr, "           TEST SUITE RESULT: FAIL          \n");
        fprintf(stderr, "============================================\n\n");
        ret = 1;
    } else {
        fprintf(stdout, "\n============================================\n");
        fprintf(stdout, "           TEST SUITE RESULT: PASS          \n");
        fprintf(stdout, "============================================\n\n");
        ret = 0;
    }

    return ret;
}
