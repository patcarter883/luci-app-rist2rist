/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test for sender restart bug fix.
 * Verifies that creating, using, destroying, and recreating a sender
 * does not cause "Sender queue is full" errors.
 */

#include "librist/librist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#ifdef _WIN32
#include <windows.h>
#define usleep(x) Sleep((x)/1000)
#else
#include <unistd.h>
#endif

static struct rist_logging_settings *logging_settings = NULL;
static atomic_int error_count;

static int log_callback(void *arg, enum rist_log_level level, const char *msg) {
    (void)arg;
    fprintf(stdout, "[%s] %s", 
            level <= RIST_LOG_ERROR ? "ERROR" : "INFO", msg);
    
    if (level <= RIST_LOG_ERROR) {
        if (strstr(msg, "queue is full") != NULL) {
            fprintf(stderr, "DETECTED: Sender queue is full error!\n");
            atomic_fetch_add(&error_count, 1);
        }
    }
    return 0;
}

static int create_and_use_sender(int iteration, const char *url) {
    struct rist_ctx *ctx = NULL;
    struct rist_peer *peer = NULL;
    int ret = 0;
    
    fprintf(stdout, "=== Iteration %d: Creating sender ===\n", iteration);
    
    if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, logging_settings) != 0) {
        fprintf(stderr, "Failed to create sender context\n");
        return -1;
    }
    
    struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config) != 0) {
        fprintf(stderr, "Failed to parse peer config\n");
        rist_destroy(ctx);
        return -1;
    }
    
    if (rist_peer_create(ctx, &peer, peer_config) != 0) {
        fprintf(stderr, "Failed to create peer\n");
        free((void *)peer_config);
        rist_destroy(ctx);
        return -1;
    }
    free((void *)peer_config);
    
    if (rist_start(ctx) != 0) {
        fprintf(stderr, "Failed to start sender\n");
        rist_destroy(ctx);
        return -1;
    }
    
    fprintf(stdout, "Iteration %d: Sending packets...\n", iteration);
    
    /* Send some packets to exercise the queue */
    uint8_t packet[1316];
    memset(packet, 0x47, sizeof(packet));
    
    struct rist_data_block data_block = {
        .payload = packet,
        .payload_len = sizeof(packet),
        .virt_src_port = 1234,
        .virt_dst_port = 1234,
    };
    
    int errors_before = atomic_load(&error_count);
    
    for (int i = 0; i < 1000; i++) {
        snprintf((char *)packet + 4, sizeof(packet) - 4, 
                 "Test packet iteration=%d seq=%d", iteration, i);
        
        int send_ret = rist_sender_data_write(ctx, &data_block);
        if (send_ret < 0) {
            fprintf(stderr, "Iteration %d: Failed to enqueue packet %d (ret=%d)\n", 
                    iteration, i, send_ret);
            ret = -1;
            break;
        }
        
        /* Small delay to let the sender process */
        if (i % 100 == 0) {
            usleep(1000);
        }
    }
    
    int errors_after = atomic_load(&error_count);
    if (errors_after > errors_before) {
        fprintf(stderr, "Iteration %d: Queue full errors detected!\n", iteration);
        ret = -1;
    }
    
    /* Let the sender flush */
    usleep(100000);
    
    fprintf(stdout, "Iteration %d: Destroying sender...\n", iteration);
    rist_destroy(ctx);
    
    /* Brief pause between iterations */
    usleep(50000);
    
    return ret;
}

int main(int argc, char *argv[]) {
    int iterations = 5;
    int ret = 0;
    
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations < 1) iterations = 5;
    }
    
    atomic_init(&error_count, 0);
    
    if (rist_logging_set(&logging_settings, RIST_LOG_DEBUG, log_callback, 
                         NULL, NULL, stderr) != 0) {
        fprintf(stderr, "Failed to setup logging\n");
        return 99;
    }
    
    fprintf(stdout, "Testing sender restart with %d iterations\n", iterations);
    fprintf(stdout, "This test verifies that stopping and restarting a sender\n");
    fprintf(stdout, "does not cause 'Sender queue is full' errors.\n\n");
    
    /* Use a listener URL so we don't need a receiver */
    const char *url = "rist://@127.0.0.1:19999?rtt-max=10&rtt-min=1";
    
    for (int i = 1; i <= iterations; i++) {
        if (create_and_use_sender(i, url) != 0) {
            fprintf(stderr, "FAIL: Iteration %d failed\n", i);
            ret = 1;
            break;
        }
        fprintf(stdout, "Iteration %d: OK\n\n", i);
    }
    
    int total_errors = atomic_load(&error_count);
    if (total_errors > 0) {
        fprintf(stderr, "\nFAIL: %d 'queue full' errors detected\n", total_errors);
        ret = 1;
    }
    
    free(logging_settings);
    
    if (ret == 0) {
        fprintf(stdout, "\nPASS: Sender restart test completed successfully\n");
    }
    
    return ret;
}
