/*
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_URL_PARAM_H
#define LIBRIST_URL_PARAM_H

/* Rist URL parameter names for peer config */
#define RIST_URL_PARAM_BUFFER_SIZE "buffer"
#define RIST_URL_PARAM_SECRET "secret"
#define RIST_URL_PARAM_AES_TYPE "aes-type"
#define RIST_URL_PARAM_BANDWIDTH "bandwidth"
#define RIST_URL_PARAM_RET_BANDWIDTH "return-bandwidth"
#define RIST_URL_PARAM_REORDER_BUFFER "reorder-buffer"
#define RIST_URL_PARAM_RTT "rtt"
#define RIST_URL_PARAM_COMPRESSION "compression"
#define RIST_URL_PARAM_CNAME "cname"
#define RIST_URL_PARAM_VIRT_DST_PORT "virt-dst-port"
#define RIST_URL_PARAM_WEIGHT "weight"
#define RIST_URL_PARAM_RECOVERY_PRIORITY "recovery-priority"
#define RIST_URL_PARAM_MIFACE "miface"
#define RIST_URL_PARAM_MCAST_TTL "ttl"
#define RIST_URL_PARAM_MCAST_SOURCE "source"
#define RIST_URL_PARAM_SESSION_TIMEOUT "session-timeout"
#define RIST_URL_PARAM_KEEPALIVE_INT "keepalive-interval"
#define RIST_URL_PARAM_SRP_USERNAME "username"
#define RIST_URL_PARAM_SRP_PASSWORD "password"
#define RIST_URL_PARAM_SRP_COMPAT "srp-compat"  //0|1 (1 => pre-0.2.16 SRP wire format)
/* Less common URL parameters */
#define RIST_URL_PARAM_BUFFER_SIZE_MIN "buffer-min"
#define RIST_URL_PARAM_BUFFER_SIZE_MAX "buffer-max"
#define RIST_URL_PARAM_RTT_MIN "rtt-min"
#define RIST_URL_PARAM_RTT_MAX "rtt-max"
#define RIST_URL_PARAM_AES_KEY_ROTATION "key-rotation"
#define RIST_URL_PARAM_CONGESTION_CONTROL "congestion-control"
#define RIST_URL_PARAM_MIN_RETRIES "min-retries"
#define RIST_URL_PARAM_MAX_RETRIES "max-retries"
#define RIST_URL_PARAM_TIMING_MODE "timing-mode"
/* udp specific parameters */
#define RIST_URL_PARAM_STREAM_ID "stream-id"
#define RIST_URL_PARAM_RTP_TIMESTAMP "rtp-timestamp"
#define RIST_URL_PARAM_RTP_SEQUENCE "rtp-sequence"
#define RIST_URL_PARAM_RTP_OUTPUT_PTYPE "rtp-ptype"
#define RIST_URL_PARAM_MULTIPLEX_MODE "multiplex-mode"
#define RIST_URL_PARAM_MULTIPLEX_FILTER "multiplex-filter"
/* Rist additional parameter names */
#define RIST_URL_PARAM_VIRT_SRC_PORT "virt-src-port"
#define RIST_URL_PARAM_PROFILE "profile"
#define RIST_URL_PARAM_SPLIT_MODE "split"
#define RIST_URL_PARAM_MERGE_MODE "merge"
#define RIST_URL_PARAM_VERBOSE_LEVEL "verbose-level"
#define RIST_URL_PARAM_RTT_MULTIPLIER "rtt-multiplier"
#define RIST_URL_PARAM_REFLECTOR "reflector"
#define RIST_URL_PARAM_LOCAL_PORT "local-port"
#define RIST_URL_PARAM_RECOVERY_DEPTH "recovery-depth"  //0..16, ring = 65536<<depth packets, default 3 (Advanced profile)
#define RIST_URL_PARAM_CBR_OUTPUT "cbr-output"  //0|1, on a udp/rtp output url: space receiver output at the stream's measured rate (assumes CBR)
/* Dynamic RTT-based bonded-leg muting (sender) */
#define RIST_URL_PARAM_RTT_DROP "rtt-drop"            //smoothed-RTT ceiling in ms; 0 = disabled
#define RIST_URL_PARAM_RTT_RESTORE "rtt-restore"      //restore low-water in ms; 0 = derive from rtt-drop
#define RIST_URL_PARAM_RTT_DROP_SETTLE "rtt-drop-settle" //dwell in ms before drop/restore
#define RIST_URL_PARAM_RTT_DROP_TRICKLE "rtt-drop-trickle" //1-in-N duplicate rate on a muted leg; 0 = hard mute

#endif /* LIBRIST_URL_PARAM_H */
