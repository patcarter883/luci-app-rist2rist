/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"
#include "proto/rist_time.h"
#include <assert.h>

void rist_receiver_missing(struct rist_flow *f, struct rist_peer *peer,uint64_t nack_time, uint32_t seq, uint64_t rtt)
{
	struct rist_missing_buffer *m = calloc(1, sizeof(*m));
	if (!m)
		return;
	uint64_t now = timestampNTP_u64();
	if (nack_time > now)
		nack_time = now;
	if (nack_time < (now - f->recovery_buffer_ticks))
		nack_time = now;
	m->seq = seq;
	m->insertion_time = nack_time;

	m->next_nack = now + rtt;
	m->peer = peer;

	if (get_cctx(peer)->debug)
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
			"Datagram %" PRIu32 " is missing, inserting into the missing queue "
			"with deadline in %" PRIu64 "ms (queue=%d), last_seq_found %"PRIu32"\n",
		seq, m->next_nack > now? (m->next_nack - now)/ RIST_CLOCK: 0, f->missing_counter, f->last_seq_found);

	m->next = NULL;
	// Insert it at the end of the queue
	if (!f->missing) {
		f->missing = m;
		f->missing_tail = m;
	} else {
		f->missing_tail->next = m;
		f->missing_tail = m;
	}
	f->missing_counter++;
}

void empty_receiver_queue(struct rist_flow *f, struct rist_common_ctx *ctx)
{
	size_t output_queue_idx = atomic_load_explicit(&f->receiver_queue_output_idx, memory_order_acquire);
	size_t counter = output_queue_idx;
	while (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) > 0) {
		struct rist_buffer *b = f->receiver_queue[counter];
		if (b)
		{
			f->receiver_queue[counter] = NULL;
			atomic_fetch_sub_explicit(&f->receiver_queue_size, b->size, memory_order_release);
			free_rist_buffer(ctx, b);
		}
		counter = (counter + 1) % f->receiver_queue_max;
		if (counter == output_queue_idx) {
			// full loop complete
			break;
		}
	}
}

void rist_flush_missing_flow_queue(struct rist_flow *flow)
{
	struct rist_missing_buffer *current = flow->missing;
	while (current)
	{
		struct rist_missing_buffer *delme = current;
		current = current->next;
		free(delme);
		delme = NULL;
	}
	flow->missing = NULL;
	flow->missing_counter = 0;
}

void rist_delete_flow(struct rist_receiver *ctx, struct rist_flow *f)
{
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Triggering data output thread termination\n");
	//This needs to be before the lock, as we may (happens rarely) fail to acquire it at all, due to output thread
	//locking/unlocking too quickly.
	atomic_store_explicit(&f->shutdown, 1, memory_order_release);
	pthread_mutex_lock(&f->mutex);
	bool running = f->receiver_thread_running;
	pthread_mutex_unlock(&f->mutex);
	if (running)
		pthread_join(f->receiver_thread, NULL);
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Resetting peer states\n");
	struct rist_peer *p = NULL;
	for (size_t i = 0; i <f->peer_lst_len; i++)
	{
		p = f->peer_lst[i];
		if (p->peer_data) {
			p->peer_data->flow = NULL;
			p->peer_data->authenticated = false;
		}
		if (p->peer_rtcp) {
			p->peer_rtcp->flow = NULL;
			p->peer_rtcp->authenticated = false;
		}
		p->authenticated = false;
		p->flow = NULL;
		if (ctx->common.profile == RIST_PROFILE_SIMPLE && p->parent && p->parent->flow == f) {
			if (p->parent->peer_rtcp) {
				p->parent->peer_rtcp->flow = NULL;
				p->parent->peer_rtcp->authenticated = false;
			}
			if (p->parent->peer_data) {
				p->parent->peer_data->flow = NULL;
				p->parent->peer_data->authenticated = false;
			}
			p->parent->authenticated = false;
			p->parent->flow = NULL;
		}
	}
	struct rist_peer *peer = ctx->common.PEERS;
	while (peer)
	{
		if (peer->flow == f) {
			peer->flow = NULL;
		}
		peer = peer->next;
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Free flow peer list\n");
	f->peer_lst_len = 0;
	free(f->peer_lst);
	f->peer_lst = NULL;

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Deleting missing queue elements\n");
	/* Delete all missing queue elements (if any) */
	rist_flush_missing_flow_queue(f);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Deleting output buffer data\n");
	/* Delete all buffer data (if any) */
	empty_receiver_queue(f, &ctx->common);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing data fifo queue\n");
	for (size_t i = 0; i < ctx->fifo_queue_size; i++)
	{
		if (f->dataout_fifo_queue[i])
		{
			free_data_block(&f->dataout_fifo_queue[i]);
		}
	}
	free(f->dataout_fifo_queue);
	/* Unlink from the flow list under flows_lock so that concurrent
	 * readers (rist_receiver_data_read2) cannot observe a dangling
	 * pointer.  The free happens after the lock is released. */
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Deleting flow\n");
	pthread_mutex_lock(&ctx->common.flows_lock);
	struct rist_flow **prev_flow = &ctx->common.FLOWS;
	struct rist_flow *current_flow = *prev_flow;
	while (current_flow)
	{
		if (current_flow == f) {
			*prev_flow = current_flow->next;
			break;
		}
		prev_flow = &current_flow->next;
		current_flow = current_flow->next;
	}
	pthread_mutex_unlock(&ctx->common.flows_lock);
	free(f);
}

static void rist_flow_append(struct rist_flow **FLOWS, struct rist_flow *f)
{
	if (*FLOWS == NULL) {
		// First entry
		*FLOWS = f;
		return;
	}

	// Append
	struct rist_flow *last = *FLOWS;
	while (last->next) {
		last = last->next;
	}

	last->next = f;
}

/* Soft cap on simultaneous receiver flows. A peer can advertise an
 * arbitrary 32-bit flow_id and we always create_flow() on a previously
 * unseen one, so without a cap an attacker that can land authenticated
 * traffic (or any traffic on a non-encrypted receiver) can exhaust
 * memory by walking flow_id space. 256 is well past any legitimate
 * deployment we've seen. */
#define RIST_MAX_FLOWS 256
#define RIST_MAX_PEERS_PER_FLOW 256

static struct rist_flow *create_flow(struct rist_receiver *ctx, uint32_t flow_id)
{
	struct rist_flow *f = calloc(1, sizeof(*f));
	if (!f) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Could not create receiver buffer of size %d MB, OOM\n", sizeof(*f) / 1000000);
		return NULL;
	}

	f->flow_id = flow_id;
	f->receiver_id = ctx->id;
	f->stats_next_time = timestampNTP_u64();
	f->max_output_jitter = ctx->common.rist_max_jitter;
	f->dataout_fifo_queue = calloc(ctx->fifo_queue_size, sizeof(*f->dataout_fifo_queue));
	if (!f->dataout_fifo_queue) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"OOM allocating dataout fifo queue (%zu entries)\n", ctx->fifo_queue_size);
		free(f);
		return NULL;
	}
	int ret = pthread_cond_init(&f->condition, NULL);
	if (ret) {
		free(f->dataout_fifo_queue);
		free(f);
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_cond_init\n", ret);
		return NULL;
	}

	ret = pthread_mutex_init(&f->mutex, NULL);
	if (ret){
		pthread_cond_destroy(&f->condition);
		free(f->dataout_fifo_queue);
		free(f);
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_mutex_init\n", ret);
		return NULL;
	}

	atomic_init(&f->receiver_queue_size, 0);
	atomic_init(&f->receiver_queue_output_idx, 0);
	atomic_init(&f->dataout_fifo_queue_write_index, 0);
	atomic_init(&f->dataout_fifo_queue_read_index, 0);
	atomic_init(&f->fifo_overflow, false);

	f->session_timeout = RIST_DEFAULT_SESSION_TIMEOUT * RIST_CLOCK;
	f->flow_timeout = 250 * RIST_CLOCK;

	/* Count + cap-check + append under one critical section so concurrent
	 * callers cannot each observe a sub-cap count and each insert. */
	pthread_mutex_lock(&ctx->common.flows_lock);
	size_t flow_count = 0;
	for (struct rist_flow *cur = ctx->common.FLOWS; cur != NULL; cur = cur->next)
		flow_count++;
	if (flow_count >= RIST_MAX_FLOWS) {
		pthread_mutex_unlock(&ctx->common.flows_lock);
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Refusing to create FLOW #%"PRIu32" inside create_flow: "
			"cap of %d flows reached (race with concurrent caller)\n",
			flow_id, RIST_MAX_FLOWS);
		pthread_mutex_destroy(&f->mutex);
		pthread_cond_destroy(&f->condition);
		free(f->dataout_fifo_queue);
		free(f);
		return NULL;
	}
	rist_flow_append(&ctx->common.FLOWS, f);
	pthread_mutex_unlock(&ctx->common.flows_lock);
	f->logging_settings = ctx->common.logging_settings;

	return f;
}

static bool flow_has_peer(struct rist_flow *f, uint32_t flow_id, uint32_t peer_id)
{
	for (size_t j = 0; j < f->peer_lst_len; j++) {
		struct rist_peer *p = f->peer_lst[j];
		if (p->adv_flow_id == flow_id && p->adv_peer_id == peer_id) {
			return true;
		}
	}

	return false;
}

int rist_receiver_associate_flow(struct rist_peer *p, uint32_t flow_id)
{
	struct rist_receiver *ctx = p->receiver_ctx;
	int ret = 0;

	// Find the flow based on the flow_id
	struct rist_flow *f = NULL;
	if (ctx->common.profile > RIST_PROFILE_SIMPLE)
	{
		pthread_mutex_lock(&ctx->common.flows_lock);
		size_t flow_count = 0;
		for (struct rist_flow *cur = ctx->common.FLOWS; cur != NULL; cur = cur->next) {
			flow_count++;
			if (cur->flow_id == flow_id) {
				f = cur;
			}
		}
		pthread_mutex_unlock(&ctx->common.flows_lock);
		if (!f && flow_count >= RIST_MAX_FLOWS) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
				"Refusing to create FLOW #%"PRIu32": cap of %d flows reached\n",
				flow_id, RIST_MAX_FLOWS);
			return -1;
		}
	} else
	{
		if (!p->parent) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "FLOW #%"PRIu32" cannot be created yet because this peer has no parent\n", flow_id);
			return -1;
		}
		f = p->parent->flow;
	}

	/* create flow if necessary */
	if (!f) {
		f = create_flow(ctx, flow_id);
		ret = 1;
		if (!f) {
			return -1;
		}
		if (p->config.timing_mode == RIST_TIMING_MODE_RTC)
			f->rtc_timing_mode = true;

		if (ctx->common.profile < RIST_PROFILE_ADVANCED) {
			f->short_seq = true;
			f->receiver_queue_max = UINT16_SIZE;
		}
		else
			f->receiver_queue_max = RIST_SERVER_QUEUE_BUFFERS;

		f->recovery_buffer_ticks = p->recovery_buffer_ticks;
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "FLOW #%"PRIu32" created (short=%d)\n", flow_id, f->short_seq);
	} else {
		/* double check that this peer is not a member of this flow already */
		if (flow_has_peer(f, flow_id, p->adv_peer_id)) {
			rist_log_priv(&ctx->common, RIST_LOG_INFO, "FLOW #%"PRIu32", Existing peer (id=%"PRIu32") re-joining existing flow ...\n",
				flow_id, p->adv_peer_id);
			ret = 2;
		} else {
			rist_log_priv(&ctx->common, RIST_LOG_INFO, "FLOW #%"PRIu32": New peer (id=%u) joining existing flow ...\n",
				flow_id, p->adv_peer_id);
			ret = 1;
		}
	}

	if (p->config.recovery_length_min != p->config.recovery_length_max) {
		f->flow_auto_buffer_scaling = true;
	}

	if (p->session_timeout > f->session_timeout) {
		f->session_timeout = p->session_timeout;
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Setting flow session timeout to %"PRIu64"ms\n", f->session_timeout / RIST_CLOCK);
	}

	// Set the flow timeout as the buffer size for the flow
	// However, we start with 250 ms as the minimum/default
	// to make sure it is larger than the RTCP interval
	if (f->recovery_buffer_ticks > f->flow_timeout)
		f->flow_timeout = f->recovery_buffer_ticks;
	uint64_t stats_report_time = get_cctx(p)->stats_report_time;
	if (stats_report_time != 0 && stats_report_time != f->stats_report_time)
		f->stats_report_time = stats_report_time;

	// Set/update max missing counter
	if (f->missing_counter_max < p->missing_counter_max)
		f->missing_counter_max = p->missing_counter_max;

	/* now assign flow to peer and add to list */
	p->flow = f;
	p->adv_flow_id = flow_id;
	if (ret == 1) {
		/* f->mutex protects peer_lst against all concurrent walkers/writers. */
		pthread_mutex_lock(&f->mutex);
		if (f->peer_lst_len >= RIST_MAX_PEERS_PER_FLOW) {
			pthread_mutex_unlock(&f->mutex);
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
				"Refusing to attach peer (id=%u) to flow #%"PRIu32": "
				"cap of %d peers/flow reached\n",
				p->adv_peer_id, flow_id, RIST_MAX_PEERS_PER_FLOW);
			p->flow = NULL;
			return -1;
		}
		struct rist_peer **new_lst = realloc(f->peer_lst, (f->peer_lst_len + 1) * sizeof(*f->peer_lst));
		if (!new_lst) {
			pthread_mutex_unlock(&f->mutex);
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
				"OOM growing flow peer list, dropping new peer\n");
			p->flow = NULL;
			return -1;
		}
		f->peer_lst = new_lst;
		f->peer_lst[f->peer_lst_len] = p;
		f->peer_lst_len++;
		pthread_mutex_unlock(&f->mutex);
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO,
		"Peer with id #%u associated with flow #%" PRIu32 "\n", p->adv_peer_id, flow_id);

	rist_log_priv(&ctx->common, RIST_LOG_INFO,
		"Flow #%" PRIu32 " has now %zu peers.\n", flow_id, f->peer_lst_len);

	return ret;
}

size_t rist_best_rtt_index(struct rist_flow *f)
{
	size_t index = 0;
	uint64_t rtt = UINT64_MAX;
	for (size_t i = 0; i < f->peer_lst_len; i++) {
		if (!f->peer_lst[i]->is_rtcp)
			continue;
		if (rtt > f->peer_lst[i]->eight_times_rtt) {
			index = i;
			rtt = f->peer_lst[i]->eight_times_rtt;
		}
	}

	return index;
}
