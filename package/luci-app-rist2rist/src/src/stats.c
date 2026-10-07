/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 * Author: Gijs Peskens <gijs@in2inip.nl>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"
#include "proto/rist_time.h"
#include <string.h>
#include "cjson/cJSON.h"

/* Bump on any incompatible shape change to the stats JSON payloads. */
#define RIST_STATS_JSON_SCHEMA_VERSION 5

/* How often to repeat the no-retransmission-budget warning. */
#define RIST_BANDWIDTH_WARN_INTERVAL (30000ULL * RIST_CLOCK)

static double round_two_digits(double number)
{
	long new_number = (long)(number * 100);
	return (double)(new_number) / 100;
}

static const char *rist_profile_name(int profile)
{
	switch (profile) {
	case RIST_PROFILE_SIMPLE:   return "simple";
	case RIST_PROFILE_MAIN:     return "main";
	case RIST_PROFILE_ADVANCED: return "advanced";
	default:                    return "unknown";
	}
}

void rist_sender_flow_statistics(struct rist_sender *ctx)
{
	cJSON *stats = cJSON_CreateObject();
	cJSON_AddNumberToObject(stats, "schema_version", RIST_STATS_JSON_SCHEMA_VERSION);
	cJSON *rist_sender_stats = cJSON_AddObjectToObject(stats, "sender-stats");
	cJSON *peers = cJSON_AddArrayToObject(rist_sender_stats, "peers");

	pthread_mutex_lock(&ctx->common.peerlist_lock);
	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		struct rist_peer *peer = ctx->peer_lst[j];
		if (!peer->dead && peer->authenticated) {
			cJSON *peer_obj = rist_sender_peer_statistics(peer);
			cJSON_AddItemToArray(peers, peer_obj);
		}
	}
	pthread_mutex_unlock(&ctx->common.peerlist_lock);

	cJSON *udp_queue_obj = cJSON_AddObjectToObject(rist_sender_stats, "incoming_queue");
	cJSON_AddNumberToObject(udp_queue_obj, "size", ctx->sender_queue_size);
	cJSON_AddNumberToObject(udp_queue_obj, "bytesize", ctx->sender_queue_bytesize);
	cJSON_AddNumberToObject(udp_queue_obj, "time_length", ctx->sender_queue_timelength);
	if (ctx->sender_queue_timelength > 0)
		cJSON_AddNumberToObject(udp_queue_obj, "packets_per_second", 1000 * ctx->sender_queue_size / ctx->sender_queue_timelength);
	else
		cJSON_AddNumberToObject(udp_queue_obj, "packets_per_second", 0);

	if (ctx->split_mode != LIBRIST_SPLIT_MODE_OFF) {
		cJSON *split_obj = cJSON_AddObjectToObject(rist_sender_stats, "split");
		const char *mode_str = ctx->split_mode == LIBRIST_SPLIT_MODE_AUTO ? "auto" : "half";
		cJSON_AddStringToObject(split_obj, "mode", mode_str);
		cJSON_AddNumberToObject(split_obj, "pairs_emitted", (double)ctx->stats_pairs_emitted);
		cJSON_AddNumberToObject(split_obj, "fallback_not_ts", (double)ctx->stats_split_fallback_not_ts);
	}

	char *stats_json = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);

	if (ctx->sender_stats_callback != NULL)
		ctx->sender_stats_callback(ctx->sender_stats_callback_argument, RIST_SENDER_STATS_VERSION, stats_json, (uint32_t)strlen(stats_json));

	free(stats_json);
}

cJSON *rist_sender_peer_statistics(struct rist_peer *peer)
{
	pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
	struct rist_stats *stats_container = malloc(sizeof(struct rist_stats));
	stats_container->stats_type = RIST_STATS_SENDER_PEER;
	stats_container->version = RIST_STATS_VERSION;

	peer->stats_sender_total.received += peer->stats_sender_instant.received;

	size_t retry_buf_size = rist_get_sender_retry_queue_size(peer->sender_ctx);

	struct rist_bandwidth_estimation *cli_bw = &peer->bw;
	struct rist_bandwidth_estimation *retry_bw = &peer->retry_bw;
	struct rist_bandwidth_estimation *ts_nulls_bw = &peer->ts_nulls_bw;

	// Refresh stats value just in case
	rist_calculate_bitrate(0, cli_bw);
	rist_calculate_bitrate(0, retry_bw);
	rist_calculate_bitrate(0, ts_nulls_bw);

	double Q = 100;
	if (peer->stats_sender_instant.sent > 0)
	{
		Q = (double)((peer->stats_sender_instant.sent) * 100.0) /
			(double)(peer->stats_sender_instant.sent + peer->stats_sender_instant.bloat_skip + peer->stats_sender_instant.bandwidth_skip + peer->stats_sender_instant.retrans_skip + peer->stats_sender_instant.retrans);
		Q = round_two_digits(Q);
	}

	uint32_t time_left = 0;
	if (peer->sender_ctx->cooldown_time > 0)
	{
		time_left = (uint32_t)(timestampNTP_u64() - peer->sender_ctx->cooldown_time) / 1000;
	}

	size_t bitrate = cli_bw->eight_times_bitrate_fast / 8;
	size_t retry_bitrate = retry_bw->eight_times_bitrate_fast / 8;
	size_t ts_nulls_bitrate = ts_nulls_bw->eight_times_bitrate_fast / 8;
	double avg_rtt = ((double)peer->eight_times_rtt / 8);

	struct rist_common_ctx *cctx = get_cctx(peer);

	if (peer->is_data
	    && rist_retransmit_budget_starved(bitrate,
					      (size_t)peer->config.recovery_maxbitrate * 1000)) {
		uint64_t now = timestampNTP_u64();
		if (rist_bandwidth_warn_due(peer->bandwidth_warn_ts,
					    RIST_BANDWIDTH_WARN_INTERVAL, now)) {
			peer->bandwidth_warn_ts = now;
			rist_log_priv(cctx, RIST_LOG_WARN,
				"Peer #%"PRIu32": no retransmission budget. Payload alone is %zu kbps "
				"against a %u kbps bandwidth ceiling, and that ceiling covers payload "
				"plus retransmissions, so every NACK is refused (%"PRIu32" this interval) "
				"and lost packets are never recovered. Raise ?bandwidth= above the "
				"payload rate, leaving headroom for recovery.\n",
				peer->adv_peer_id, bitrate / 1000, peer->config.recovery_maxbitrate,
				peer->stats_sender_instant.bandwidth_skip);
		}
	}

	cJSON *peer_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(peer_obj, "flow_id", peer->adv_flow_id);
	cJSON_AddNumberToObject(peer_obj, "id", peer->adv_peer_id);
	cJSON_AddStringToObject(peer_obj, "cname", peer->receiver_name);
	cJSON_AddStringToObject(peer_obj, "type", peer->is_data ? "data" : "rtcp");
	cJSON_AddNumberToObject(peer_obj, "profile", cctx->profile);
	cJSON_AddStringToObject(peer_obj, "profile_name", rist_profile_name(cctx->profile));
	cJSON_AddBoolToObject(peer_obj, "advanced_active", peer->is_advanced ? 1 : 0);
	if (peer->miface[0])
		cJSON_AddStringToObject(peer_obj, "miface", peer->miface);
	cJSON *json_stats = cJSON_AddObjectToObject(peer_obj, "stats");
	cJSON_AddNumberToObject(json_stats, "quality", Q);
	cJSON_AddNumberToObject(json_stats, "sent", (double)peer->stats_sender_instant.sent);
	cJSON_AddNumberToObject(json_stats, "ts_null", (double)peer->stats_sender_instant.ts_null);
	cJSON_AddNumberToObject(json_stats, "received", (double)peer->stats_sender_instant.received);
	cJSON_AddNumberToObject(json_stats, "retransmitted", (double)peer->stats_sender_instant.retrans);
	cJSON_AddNumberToObject(json_stats, "sent_bytes", (double)peer->stats_sender_instant.sent_bytes);
	cJSON_AddNumberToObject(json_stats, "retransmitted_bytes", (double)peer->stats_sender_instant.retransmitted_bytes);
	cJSON_AddNumberToObject(json_stats, "bandwidth", (double)bitrate);
	cJSON_AddNumberToObject(json_stats, "retry_bandwidth", (double)retry_bitrate);
	cJSON_AddNumberToObject(json_stats, "ts_nulls_bandwidth", (double)ts_nulls_bitrate);
	cJSON_AddNumberToObject(json_stats, "bandwidth_skipped", (double)peer->stats_sender_instant.bandwidth_skip);
	cJSON_AddNumberToObject(json_stats, "bloat_skipped", (double)peer->stats_sender_instant.bloat_skip);
	cJSON_AddNumberToObject(json_stats, "retransmit_skipped", (double)peer->stats_sender_instant.retrans_skip);
	cJSON_AddNumberToObject(json_stats, "rtt", (double)peer->last_rtt / RIST_CLOCK);
	cJSON_AddNumberToObject(json_stats, "avg_rtt", (double)avg_rtt / RIST_CLOCK);
	cJSON_AddNumberToObject(json_stats, "retry_buffer_size", (double)retry_buf_size);
	cJSON_AddNumberToObject(json_stats, "cooldown_time", (double)time_left);
	cJSON_AddBoolToObject(json_stats, "rtt_muted", peer->rtt_muted ? 1 : 0);
	cJSON_AddNumberToObject(json_stats, "rtt_mute_events", (double)peer->rtt_mute_count);
	cJSON *stats = cJSON_CreateObject();
	cJSON_AddNumberToObject(stats, "schema_version", RIST_STATS_JSON_SCHEMA_VERSION);
	cJSON *rist_sender_stats = cJSON_AddObjectToObject(stats, "sender-stats");
	cJSON *peers = cJSON_AddArrayToObject(rist_sender_stats, "peers");
	cJSON_AddItemToArray(peers, cJSON_Duplicate(peer_obj, true));
	char *stats_string = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);

	stats_container->stats_json = stats_string;
	stats_container->json_size = (uint32_t)strlen(stats_string);
	strncpy(stats_container->stats.sender_peer.cname,
		peer->receiver_name,
		sizeof(stats_container->stats.sender_peer.cname) - 1);
	stats_container->stats.sender_peer.cname[sizeof(stats_container->stats.sender_peer.cname) - 1] = '\0';
	stats_container->stats.sender_peer.peer_id = peer->adv_peer_id;
	stats_container->stats.sender_peer.bandwidth = bitrate;
	stats_container->stats.sender_peer.retry_bandwidth = retry_bitrate;
	//stats_container->stats.sender_peer.ts_nulls_bandwidth = ts_nulls_bitrate;
	stats_container->stats.sender_peer.sent = peer->stats_sender_instant.sent;
	stats_container->stats.sender_peer.received = peer->stats_sender_instant.received;
	stats_container->stats.sender_peer.retransmitted = peer->stats_sender_instant.retrans;
	stats_container->stats.sender_peer.quality = Q;
	stats_container->stats.sender_peer.rtt = avg_rtt / RIST_CLOCK;
	stats_container->stats.sender_peer.sent_bytes = peer->stats_sender_instant.sent_bytes;
	stats_container->stats.sender_peer.retransmitted_bytes = peer->stats_sender_instant.retransmitted_bytes;
	stats_container->stats.sender_peer.profile = (uint8_t)cctx->profile;
	stats_container->stats.sender_peer.advanced_active = peer->is_advanced ? 1 : 0;
	stats_container->stats.sender_peer.rtt_muted = peer->rtt_muted ? 1 : 0;
	stats_container->stats.sender_peer.rtt_mute_events = peer->rtt_mute_count;

	if (cctx->stats_callback != NULL)
		cctx->stats_callback(cctx->stats_callback_argument, stats_container);
	else
		rist_stats_free(stats_container);

	memset(&peer->stats_sender_instant, 0, sizeof(peer->stats_sender_instant));
	pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));

	return peer_obj;
}

void rist_receiver_flow_statistics(struct rist_receiver *ctx, struct rist_flow *flow)
{
	if (!flow)
		return;
	pthread_mutex_lock(&ctx->common.stats_lock);
	//Log errors that used to be packet
	if (flow->stats_instant.dropped_full)
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Dropped %u packets due to buffers being full\n", flow->stats_instant.dropped_full );
	if (flow->stats_instant.dropped_late)
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Dropped %u late packets\n", flow->stats_instant.dropped_late);
	if (flow->stats_instant.lost)
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Lost %u packets\n", flow->stats_instant.lost);

	struct rist_stats *stats_container = malloc(sizeof(struct rist_stats));
	stats_container->stats_type = RIST_STATS_RECEIVER_FLOW;
	stats_container->version = RIST_STATS_VERSION;

	if (flow->stats_instant.avg_count)
	{
		flow->stats_instant.cur_ips = (flow->stats_instant.total_ips / flow->stats_instant.avg_count);
	}

	stats_container->stats.receiver_flow.peers = calloc(flow->peer_lst_len, sizeof(struct rist_stats_receiver_peer));

	cJSON *stats = cJSON_CreateObject();
	cJSON_AddNumberToObject(stats, "schema_version", RIST_STATS_JSON_SCHEMA_VERSION);
	cJSON *stats_obj = cJSON_AddObjectToObject(stats, "receiver-stats");
	cJSON *flow_obj = cJSON_AddObjectToObject(stats_obj, "flowinstant");
	cJSON_AddNumberToObject(flow_obj, "flow_id", flow->flow_id);
	cJSON_AddNumberToObject(flow_obj, "dead",  flow->dead);
	cJSON_AddNumberToObject(flow_obj, "profile", ctx->common.profile);
	cJSON_AddStringToObject(flow_obj, "profile_name", rist_profile_name(ctx->common.profile));
	cJSON_AddNumberToObject(flow_obj, "seq_bits", flow->short_seq ? 16 : 32);
	cJSON_AddBoolToObject(flow_obj, "advanced_active",
		(ctx->common.profile >= RIST_PROFILE_ADVANCED && !flow->short_seq) ? 1 : 0);
	cJSON *json_stats = cJSON_AddObjectToObject(flow_obj, "stats");
	cJSON *peers = cJSON_AddArrayToObject(flow_obj, "peers");
	uint32_t flow_rtt = 0;
	uint32_t flow_sent_instant = 0;
	for (size_t i = 0; i < flow->peer_lst_len; i++)
	{
		struct rist_peer *peer = flow->peer_lst[i];
		if (!peer->is_data && peer->peer_data)
			peer = peer->peer_data;
		double avg_rtt = ((double)peer->eight_times_rtt / 8);

		size_t bitrate = peer->bw.eight_times_bitrate_fast / 8;
		size_t avg_bitrate = peer->bw.eight_times_bitrate / 8;
		flow_sent_instant += peer->stats_receiver_instant.sent_rtcp;
		flow_rtt += (uint32_t)(peer->eight_times_rtt / 8);

		cJSON *peer_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(peer_obj, "id", peer->adv_peer_id);
		cJSON_AddNumberToObject(peer_obj, "dead", peer->dead);
		/* Listener-mode children have url=NULL; the configured URL
		 * lives on the parent peer. */
		const char *peer_url_str = peer->url;
		if ((peer_url_str == NULL || peer_url_str[0] == '\0') && peer->parent && peer->parent->url) {
			peer_url_str = peer->parent->url;
		}
		cJSON_AddStringToObject(peer_obj, "url", peer_url_str ? peer_url_str : "");
		cJSON *peer_stats = cJSON_AddObjectToObject(peer_obj, "stats");
		cJSON_AddNumberToObject(peer_stats, "received_data", (double)peer->stats_receiver_instant.received);
		cJSON_AddNumberToObject(peer_stats, "received_bytes", (double)peer->stats_receiver_instant.received_bytes);
		cJSON_AddNumberToObject(peer_stats, "ts_null", (double)peer->stats_receiver_instant.ts_null);	
		cJSON_AddNumberToObject(peer_stats, "received_rtcp", (double)peer->stats_receiver_instant.received_rtcp);
		cJSON_AddNumberToObject(peer_stats, "sent_rtcp", (double)peer->stats_receiver_instant.sent_rtcp);
		cJSON_AddNumberToObject(peer_stats, "rtt", (double)peer->last_rtt / RIST_CLOCK);
		cJSON_AddNumberToObject(peer_stats, "avg_rtt", (double)avg_rtt / RIST_CLOCK);
		cJSON_AddNumberToObject(peer_stats, "bitrate", (double)bitrate);
		cJSON_AddNumberToObject(peer_stats, "avg_bitrate", (double)avg_bitrate);
		cJSON_AddItemToArray(peers, peer_obj);

		stats_container->stats.receiver_flow.peers[i].peer_id = peer->adv_peer_id;
		stats_container->stats.receiver_flow.peers[i].received_data = peer->stats_receiver_instant.received;
		stats_container->stats.receiver_flow.peers[i].received_bytes = peer->stats_receiver_instant.received_bytes;
		stats_container->stats.receiver_flow.peers[i].received_rtcp = peer->stats_receiver_instant.received_rtcp;
		stats_container->stats.receiver_flow.peers[i].sent_rtcp = peer->stats_receiver_instant.sent_rtcp;
		stats_container->stats.receiver_flow.peers[i].rtt = peer->last_rtt / RIST_CLOCK;
		stats_container->stats.receiver_flow.peers[i].avg_rtt = avg_rtt / RIST_CLOCK;
		stats_container->stats.receiver_flow.peers[i].bandwidth = bitrate;
		stats_container->stats.receiver_flow.peers[i].avg_bandwidth = avg_bitrate;

		// Clear peer instant stats
		memset(&peer->stats_receiver_instant, 0, sizeof(peer->stats_receiver_instant));
	}

	flow->stats_instant.recovered_average = (flow->stats_instant.recovered_sum * 100) - flow->stats_instant.recovered;
	flow->stats_instant.recovered_slope = flow->stats_instant.recovered_3nack - flow->stats_instant.recovered_0nack;
	if ((int32_t)(flow->stats_instant.recovered_1nack - flow->stats_instant.recovered_0nack) > 0 &&
		flow->stats_instant.recovered_1nack != 0 && flow->stats_instant.recovered_0nack != 0)
	{
		flow->stats_instant.recovered_slope_inverted++;
	}

	if ((int32_t)(flow->stats_instant.recovered_2nack - flow->stats_instant.recovered_1nack) > 0 &&
		flow->stats_instant.recovered_2nack != 0 && flow->stats_instant.recovered_1nack != 0)
	{
		flow->stats_instant.recovered_slope_inverted++;
	}

	if ((int32_t)(flow->stats_instant.recovered_3nack - flow->stats_instant.recovered_2nack) > 0 &&
		flow->stats_instant.recovered_3nack != 0 && flow->stats_instant.recovered_2nack != 0)
	{
		flow->stats_instant.recovered_slope_inverted++;
	}

	double Q = 100;
	if (flow->stats_instant.received > 0)
	{
		Q = (double)((flow->stats_instant.received)*100.0) /
			(double)(flow->stats_instant.received + flow->stats_instant.missing);
		Q = round_two_digits(Q);
	}

	// This last one should trigger buffer protection immediately
	if ((flow->missing_counter == 0 || flow->stats_instant.recovered == 0 ||
		 (flow->stats_instant.recovered * 10) < flow->stats_instant.missing) &&
		flow->stats_instant.received > 10 &&
		flow->stats_instant.received < flow->stats_instant.missing)
	{
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "\tThe flow link is dead %" PRIu32 " > %" PRIu64 ", deleting all missing queue elements!\n",
			flow->stats_instant.missing, flow->stats_instant.received);
		/* Delete all missing queue elements (if any) */
		rist_flush_missing_flow_queue(flow);
	}

	uint64_t avg_buffer_duration = 0;
	if (flow->stats_instant.buffer_duration_count > 0)
	{

		for (size_t i = 0; i < flow->stats_instant.buffer_duration_count; i++)
		{
			avg_buffer_duration += flow->stats_instant.buffer_duration[i];
		}
		avg_buffer_duration /= flow->stats_instant.buffer_duration_count;
		flow->stats_instant.buffer_duration_count = 0;
	}
	cJSON_AddNumberToObject(json_stats, "quality", Q);
	cJSON_AddNumberToObject(json_stats, "received", (double)flow->stats_instant.received);
	cJSON_AddNumberToObject(json_stats, "received_bytes", (double)flow->stats_instant.received_bytes);
	cJSON_AddNumberToObject(json_stats, "dropped_late", (double)flow->stats_instant.dropped_late);
	cJSON_AddNumberToObject(json_stats, "dropped_full", (double)flow->stats_instant.dropped_full);
	cJSON_AddNumberToObject(json_stats, "missing", (double)flow->stats_instant.missing);
	cJSON_AddNumberToObject(json_stats, "recovered_total", (double)flow->stats_instant.recovered);
	cJSON_AddNumberToObject(json_stats, "reordered", (double)flow->stats_instant.reordered);
	cJSON_AddNumberToObject(json_stats, "retries", (double)flow->stats_instant.retries);
	cJSON_AddNumberToObject(json_stats, "recovered_one_nack", (double)flow->stats_instant.recovered_0nack);
	cJSON_AddNumberToObject(json_stats, "recovered_two_nacks", (double)flow->stats_instant.recovered_1nack);
	cJSON_AddNumberToObject(json_stats, "recovered_three_nacks", (double)flow->stats_instant.recovered_2nack);
	cJSON_AddNumberToObject(json_stats, "recovered_four_nacks", (double)flow->stats_instant.recovered_3nack);
	cJSON_AddNumberToObject(json_stats, "recovered_more_nacks", (double)flow->stats_instant.recovered_morenack);
	cJSON_AddNumberToObject(json_stats, "lost", (double)flow->stats_instant.lost);
	cJSON_AddNumberToObject(json_stats, "avg_buffer_time", (double)avg_buffer_duration);
	cJSON_AddNumberToObject(json_stats, "duplicates", (double)flow->stats_instant.dupe);
	cJSON_AddNumberToObject(json_stats, "missing_queue", (double)flow->missing_counter);
	cJSON_AddNumberToObject(json_stats, "missing_queue_max", (double)flow->missing_counter_max);
	cJSON_AddNumberToObject(json_stats, "min_inter_packet_spacing", (double)flow->stats_instant.min_ips);
	cJSON_AddNumberToObject(json_stats, "cur_inter_packet_spacing", (double)flow->stats_instant.cur_ips);
	cJSON_AddNumberToObject(json_stats, "max_inter_packet_spacing", (double)flow->stats_instant.max_ips);
	/* Decay flow bitrate counters when no traffic has arrived since the last tick. */
	rist_refresh_flow_bitrate(&flow->bw);
	rist_refresh_flow_bitrate(&flow->bw_retries);
	rist_refresh_flow_bitrate(&flow->bw_rejected);
	rist_refresh_flow_bitrate(&flow->bw_tsnull);
	cJSON_AddNumberToObject(json_stats, "bitrate", (double)flow->bw.bitrate);
	cJSON_AddNumberToObject(json_stats, "bitrate_retries", (double)flow->bw_retries.bitrate);
	cJSON_AddNumberToObject(json_stats, "bitrate_rejected", (double)flow->bw_rejected.bitrate);
	cJSON_AddNumberToObject(json_stats, "bitrate_ts_nulls", (double)flow->bw_tsnull.bitrate);
	cJSON_AddNumberToObject(json_stats, "bitrate_payload", (double)flow->bw.bitrate + (double)flow->bw_tsnull.bitrate);

	if (ctx->merge_mode != LIBRIST_MERGE_MODE_OFF) {
		cJSON *merge_obj = cJSON_AddObjectToObject(flow_obj, "merge");
		const char *mode_str = ctx->merge_mode == LIBRIST_MERGE_MODE_AUTO ? "auto" : "pairs";
		cJSON_AddStringToObject(merge_obj, "mode", mode_str);
		cJSON_AddNumberToObject(merge_obj, "pairs_merged", (double)ctx->stats_pairs_merged);
		cJSON_AddNumberToObject(merge_obj, "orphan_first_delivered", (double)ctx->stats_orphan_first_delivered);
		cJSON_AddNumberToObject(merge_obj, "orphan_last_delivered", (double)ctx->stats_orphan_last_delivered);
	}

	char *stats_string = cJSON_PrintUnformatted(stats);
	cJSON_Delete(stats);

	stats_container->stats_json = stats_string;
	stats_container->json_size = (uint32_t)strlen(stats_string);

	stats_container->stats.receiver_flow.peer_count = (uint32_t)flow->peer_lst_len;
	// TODO: populate stats_receiver_flow->cname
	stats_container->stats.receiver_flow.cname[0] = '\0';
	stats_container->stats.receiver_flow.flow_id = flow->flow_id;
	stats_container->stats.receiver_flow.status = flow->dead;
	stats_container->stats.receiver_flow.bandwidth = flow->bw.bitrate;
	stats_container->stats.receiver_flow.retry_bandwidth = flow->bw_retries.bitrate;
	//stats_container->stats.receiver_flow.ts_nulls_bandwidth = flow->bw_tsnull.bitrate;
	stats_container->stats.receiver_flow.sent = flow->peer_lst_len ? flow_sent_instant / flow->peer_lst_len : 0;
	stats_container->stats.receiver_flow.received = flow->stats_instant.received;
	stats_container->stats.receiver_flow.received_bytes = flow->stats_instant.received_bytes;
	stats_container->stats.receiver_flow.missing = flow->stats_instant.missing;
	stats_container->stats.receiver_flow.reordered = flow->stats_instant.reordered;
	stats_container->stats.receiver_flow.recovered = flow->stats_instant.recovered;
	stats_container->stats.receiver_flow.recovered_one_retry = flow->stats_instant.recovered_0nack;
	stats_container->stats.receiver_flow.lost = flow->stats_instant.lost;
	stats_container->stats.receiver_flow.quality = Q;
	stats_container->stats.receiver_flow.min_inter_packet_spacing = flow->stats_instant.min_ips;
	stats_container->stats.receiver_flow.cur_inter_packet_spacing = flow->stats_instant.cur_ips;
	stats_container->stats.receiver_flow.max_inter_packet_spacing = flow->stats_instant.max_ips;
	stats_container->stats.receiver_flow.rtt = flow->peer_lst_len ? (flow_rtt / flow->peer_lst_len)/RIST_CLOCK : 0;
	stats_container->stats.receiver_flow.avg_buffer_time = avg_buffer_duration;
	stats_container->stats.receiver_flow.profile = (uint8_t)ctx->common.profile;
	stats_container->stats.receiver_flow.seq_bits = flow->short_seq ? 16 : 32;
	stats_container->stats.receiver_flow.advanced_active =
		(ctx->common.profile >= RIST_PROFILE_ADVANCED && !flow->short_seq) ? 1 : 0;

	/* CALLBACK CALL */
	if (ctx->common.stats_callback != NULL)
		ctx->common.stats_callback(ctx->common.stats_callback_argument, stats_container);
	else
		rist_stats_free(stats_container);

	memset(&flow->stats_instant, 0, sizeof(flow->stats_instant));
	flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;
	pthread_mutex_unlock(&ctx->common.stats_lock);
}
