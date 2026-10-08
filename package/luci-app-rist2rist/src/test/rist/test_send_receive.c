/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "librist/librist.h"
#include "rist-private.h"
#include <stdatomic.h>
#include <inttypes.h>
#include "mpegts.h"
#include "endian-shim.h"

#ifdef _WIN32
#include <windows.h>
#endif

atomic_ulong failed;
atomic_ulong stop;
atomic_ulong flow_attr_received;
int use_seq = 0;
int check_flow_attr = 0;
int has_loss = 0;
#define USE_SEQ_START 1000

struct rist_logging_settings *logging_settings_sender = NULL;
struct rist_logging_settings *logging_settings_receiver = NULL;
char* senderstring = "sender";
char* receiverstring = "receiver";

int log_callback(void *arg, int level, const char *msg) {
    if (level > RIST_LOG_ERROR)
        fprintf(stdout, "[%s] %s",(char*)arg, msg);
    if (level <= RIST_LOG_ERROR) {
	fprintf(stdout, "[%s] [ERROR] %s", (char* )arg, msg);
	if (!has_loss) {
	    atomic_store(&failed, 1);
	    atomic_store(&stop, 1);
	}
    }
    return 0;
}

static int flow_attr_callback(void *arg, struct rist_peer *peer, const char *json, size_t json_len) {
    (void)arg;
    (void)peer;
    if (json && json_len > 0)
        atomic_fetch_add(&flow_attr_received, 1);
    return 0;
}

struct rist_ctx *setup_rist_receiver(int profile, const char *url) {
    struct rist_ctx *ctx;
	if (rist_receiver_create(&ctx, profile, logging_settings_receiver) != 0) {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not create rist receiver context\n");
		return NULL;
	}
    // Rely on the library to parse the url
    struct rist_peer_config *peer_config = NULL;
    if (rist_parse_address2(url, (void *)&peer_config))
    {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not parse peer options for receiver\n");
		return NULL;
	}
    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config) == -1) {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not add peer connector to receiver\n");
		return NULL;
	}
#if HAVE_SRP_SUPPORT
    if (strlen(peer_config->srp_username) > 0 &&
        strlen(peer_config->srp_password) > 0) {
        int srp_error =
            rist_enable_eap_srp_2(peer, peer_config->srp_username,
                                peer_config->srp_password, NULL, NULL);
        if (srp_error)
          rist_log(logging_settings_receiver, RIST_LOG_WARN,
                   "Error %d trying to enable SRP for peer\n", srp_error);
    }
#endif
    free((void *)peer_config);
    if (check_flow_attr) {
        rist_receiver_flow_attr_callback_set(ctx, flow_attr_callback, NULL);
    }
    if (rist_start(ctx) == -1) {
		rist_log(logging_settings_receiver, RIST_LOG_ERROR, "Could not start rist sender\n");
		return NULL;
	}
    return ctx;
}

struct rist_ctx *setup_rist_sender(int profile, const char *url) {
    struct rist_ctx *ctx;
    if (rist_sender_create(&ctx, profile, 0, logging_settings_sender) != 0) {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not create rist sender context\n");
		return NULL;
	}

    const struct rist_peer_config *peer_config_link = NULL;
    if (rist_parse_address2(url, (void *)&peer_config_link))
    {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not parse peer options for sender\n");
		return NULL;
	}

    struct rist_peer *peer;
    if (rist_peer_create(ctx, &peer, peer_config_link) == -1) {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not add peer connector to sender\n");
		return NULL;
	}

#if HAVE_SRP_SUPPORT
    if (strlen(peer_config_link->srp_username) > 0 &&
        strlen(peer_config_link->srp_password) > 0) {
        int srp_error =
            rist_enable_eap_srp_2(peer, peer_config_link->srp_username,
                                peer_config_link->srp_password, NULL, NULL);
        if (srp_error)
          rist_log(logging_settings_sender, RIST_LOG_WARN,
                   "Error %d trying to enable SRP for peer\n", srp_error);
    }
#endif

	free((void *)peer_config_link);
	if (rist_start(ctx) == -1) {
		rist_log(logging_settings_sender, RIST_LOG_ERROR, "Could not start rist sender\n");
		return NULL;
	}
    return ctx;
}

static PTHREAD_START_FUNC(send_data, arg) {
    struct rist_ctx *rist_sender = arg;
    int send_counter = 0;
    char buffer[1316] = { 0 };
    struct rist_data_block data = { 0 };
    srand((unsigned int)time(NULL));
    /* we just try to send some string at ~20mbs for ~8 seconds */
    while (send_counter < 16000) {
        if (atomic_load(&stop))
            break;
        // Make it a random size as a multiple of mpegts 188 bytes (max 7) and add sync byte, pid and flags
        int random_num = (rand() % 7) + 1;
        for(int ts = 0; ts < random_num; ts++){
            int offset = 188*ts;
            struct mpegts_header * hdr = (struct mpegts_header *)&buffer[offset];
			memset(hdr, 0, sizeof(*hdr));
			hdr->syncbyte = 0x47;
            // Random null pids
            int random_bit = rand() % 2;
            if (random_bit) {
                hdr->flags1 = htobe16(0x1FFF);
                SET_BIT(hdr->flags2,4);
            }
            else {
                hdr->flags1 = htobe16(0x1111);
            }
            int pkt_id = use_seq ? (send_counter + USE_SEQ_START) : send_counter;
            sprintf(&buffer[offset+sizeof(*hdr)+1], "DEADBEAF TEST PACKET #%i-%i", pkt_id, ts);
        }
        data.payload = &buffer;
        data.payload_len = 188 * random_num;
        if (use_seq) {
            data.flags = RIST_DATA_FLAGS_USE_SEQ;
            data.seq = (uint64_t)(send_counter + USE_SEQ_START);
        }
        int ret = rist_sender_data_write(rist_sender, &data);
        if (ret < 0) {
            fprintf(stderr, "Failed to send test packet with error code %d!\n", ret);
            atomic_store(&failed, 1);
            atomic_store(&stop, 1);
            break;
        }
        else if (ret != (int)data.payload_len) {
            fprintf(stderr, "Failed to send test packet %d != %d !\n", ret, (int)data.payload_len);
            atomic_store(&failed, 1);
            atomic_store(&stop, 1);
            break;
        }
        send_counter++;
#ifdef _WIN32
		Sleep(1);
#else
        usleep(500);
#endif
    }

#ifdef _WIN32
	Sleep(2);
#else
    usleep(1500);
#endif

    atomic_store(&stop, 1);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5 || argc > 8) {
        return 99;
    }
    int profile = atoi(argv[1]);
    char *url1 = strdup(argv[2]);
    char *url2 = strdup(argv[3]);
    int losspercent = atoi(argv[4]) * 10;
    has_loss = losspercent > 0;
    int npd = 0;
    int ret = 0;

    if (argc >= 6)
        npd = atoi(argv[5]);
    if (argc >= 7)
        use_seq = atoi(argv[6]);
    if (argc >= 8)
        check_flow_attr = atoi(argv[7]);

    struct rist_ctx *receiver_ctx = NULL;
    struct rist_ctx *sender_ctx = NULL;

    atomic_init(&failed, 0);
    atomic_init(&stop, 0);
    atomic_init(&flow_attr_received, 0);


    fprintf(stdout, "Testing profile %i with receiver url %s and sender url %s and losspercentage: %i\n", profile, url1, url2, losspercent);

    if (rist_logging_set(&logging_settings_sender, RIST_LOG_DEBUG, log_callback, senderstring, NULL, stderr) != 0) {
		fprintf(stderr,"Failed to setup logging!\n");
		ret = 99;
		goto out;
	}

	if (rist_logging_set(&logging_settings_receiver, RIST_LOG_DEBUG, log_callback, receiverstring, NULL, stderr) != 0)
	{
		fprintf(stderr, "Failed to setup logging!\n");
		ret = 99;
		goto out;
	}
	receiver_ctx = setup_rist_receiver(profile, url1);
    sender_ctx = setup_rist_sender(profile, url2);
	if (!sender_ctx || !receiver_ctx) {
		ret = 99;
		goto out;
	}

    if (losspercent > 0) {
        receiver_ctx->receiver_ctx->simulate_loss = true;
        receiver_ctx->receiver_ctx->loss_percentage = losspercent;
        sender_ctx->sender_ctx->simulate_loss = true;
        sender_ctx->sender_ctx->loss_percentage = losspercent;
    }
    if (npd > 0)
        rist_sender_npd_enable(sender_ctx);

    pthread_t send_loop;
    if (pthread_create(&send_loop, NULL, send_data, (void *)sender_ctx) != 0)
    {
        fprintf(stderr, "Could not start send data thread\n");
		ret = 99;
		goto out;
	}

    struct rist_data_block *b = NULL;
    char rcompare[1316];
    int receive_count = 1;
    bool got_first = false;
    while (receive_count < 16000) {
        if (atomic_load(&stop))
            break;
        int queue_length = rist_receiver_data_read2(receiver_ctx, &b, 5);
        if (queue_length > 0) {
            if (!got_first) {
                receive_count = (int)b->seq;
				got_first = true;
				if (use_seq && (int)b->seq < USE_SEQ_START) {
					fprintf(stderr, "USE_SEQ: first seq %"PRIu64" < expected start %d, "
					        "sender-supplied seq was not preserved\n",
					        b->seq, USE_SEQ_START);
					atomic_store(&failed, 1);
					atomic_store(&stop, 1);
				}
			}
            // Check entire mpegts structure
            int tsindex = (int)(b->payload_len / 188);
            for(int ts = 0; ts < tsindex; ts++){
                int offset = 188*ts;
                uint8_t *payload = ((uint8_t*)b->payload + offset);
                struct mpegts_header * hdr = (struct mpegts_header *)(payload);
                if (hdr->syncbyte != 0x47)
                {
                    fprintf(stderr, "Packet contents not as expected!\n");
                    fprintf(stderr, "Sync Byte at index %d was %d instead of 0x47 with %zu bytes\n", ts, hdr->syncbyte, b->payload_len);
                    atomic_store(&failed, 1);
                    atomic_store(&stop, 1);
                    break;
                }
                // We only check for non-null segments or when null packet deletion is not enabled
                // Otherwise our data would have been replaced with 0xff everywhere
                if ((npd == 0 || (npd == 1 && be16toh(hdr->flags1) != 0x1FFF)))
                {
                    // Check for string we wrote
                    sprintf(rcompare, "DEADBEAF TEST PACKET #%i-%i", receive_count, ts);
                    if (strcmp(rcompare, (char *)b->payload + offset + sizeof(*hdr) + 1)) {
                        fprintf(stderr, "Packet contents not as expected at index %i!\n", ts);
                        fprintf(stderr, "Got : %s (%zu/%d)\n", (char*)b->payload, b->payload_len, b->virt_dst_port);
                        fprintf(stderr, "Expected : %s\n", (char*)rcompare);
                        atomic_store(&failed, 1);
                        atomic_store(&stop, 1);
                        break;
                    }
                }
            }
            receive_count++;
            rist_receiver_data_block_free2((struct rist_data_block **const)&b);
        }
    }
	int expected = 16000 * (1000 - losspercent) / 1000;
	int min_receive = (expected < 12500) ? expected * 5 / 6 : 12500;
	if (!got_first || receive_count < min_receive) {
		fprintf(stderr, "Received %d packets, minimum required %d\n",
			receive_count, min_receive);
		atomic_store(&failed, 1);
	}
	if (check_flow_attr) {
		unsigned long fa_count = atomic_load(&flow_attr_received);
		fprintf(stdout, "Flow attributes received: %lu\n", fa_count);
		if (fa_count == 0) {
			fprintf(stderr, "FAIL: expected at least one flow attribute callback\n");
			atomic_store(&failed, 1);
		}
	}
	if (atomic_load(&failed))
		ret = 1;
	pthread_join(send_loop, NULL);
out:
	free(url1);
	free(url2);
	if (sender_ctx)
		rist_destroy(sender_ctx);
	if (receiver_ctx)
		rist_destroy(receiver_ctx);
	free(logging_settings_receiver);
	free(logging_settings_sender);
	if (ret > 0) {
		fprintf(stderr, "FAIL\n");
		return ret;
	}

	fprintf(stdout, "OK\n");
    return 0;
}
