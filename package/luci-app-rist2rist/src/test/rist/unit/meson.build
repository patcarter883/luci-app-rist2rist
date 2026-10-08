cmocka = dependency('cmocka', required: false, fallback: ['cmocka', 'cmocka_dep'])

if cmocka.found()
	if have_srp
		# stdatomic_dependency mirrors the main librist target so the
		# srp_unit translation units pick up the compat/msvc shim when
		# MSVC's <stdatomic.h> requires /experimental:c11atomics.
		srp_unit_deps = [threads, cmocka, crypto_deps, stdatomic_dependency]
		if host_machine.system() == 'windows'
			srp_unit_deps += cc.find_library('bcrypt')  # random.c calls BCryptGenRandom
		endif
		srp_unit = executable('srp_unit', rev_target,
								'srp_examples.c',
								'../../../contrib/pthread-shim.c',
								'../../../src/crypto/random.c',
								include_directories : inc,
								dependencies : srp_unit_deps,
		)

		test('srp_unit_test', srp_unit, suite:['unit'])
	endif
endif

# Regression test for #208: rist_logging_set with a remote (udp://)
# address must succeed before any rist_*_create call. Does not require
# cmocka - links against the public librist API only.
logging_init_order = executable('logging_init_order',
                                'logging_init_order.c',
                                include_directories : inc,
                                link_with : librist)
test('logging_init_order', logging_init_order, suite:['unit'])

# Advanced Profile (TR-06-3) header parse/build round-trip tests.
# Compiles adv.c directly to access RIST_PRIV (hidden-visibility) symbols.
adv_test_deps = [lz4_lib]
if host_machine.system() == 'windows'
	adv_test_deps += cc.find_library('ws2_32')
endif
test_adv_roundtrip = executable('test_adv_roundtrip',
                                'test_adv_roundtrip.c',
                                '../../../src/adv.c',
                                include_directories : inc,
                                dependencies : adv_test_deps)
test('adv_roundtrip', test_adv_roundtrip, suite:['unit'])

# EAP v4 crypto primitives (HKDF-Expand-SHA256 + AES-256-GCM) known-answer tests.
# Compiles eap_v4_crypto.c directly to reach RIST_PRIV (hidden-visibility)
# symbols. Gated on have_srp, which implies a real crypto backend (mbedTLS or
# Nettle) is present; the built-in fallback has no AEAD.
if have_srp
	eap_v4_crypto_deps = [crypto_deps]
	if host_machine.system() == 'windows'
		eap_v4_crypto_deps += cc.find_library('bcrypt')  # mbedcrypto entropy_poll calls BCryptGenRandom
	endif
	test_eap_v4_crypto = executable('test_eap_v4_crypto',
	                                'test_eap_v4_crypto.c',
	                                '../../../src/crypto/eap_v4_crypto.c',
	                                include_directories : inc,
	                                dependencies : eap_v4_crypto_deps)
	test('eap_v4_crypto', test_eap_v4_crypto, suite:['unit'])
endif

# URL ?profile= parsing exercised through the public rist_parse_address2 API.
test_url_profile_parse = executable('test_url_profile_parse',
                                    'test_url_profile_parse.c',
                                    include_directories : inc,
                                    link_with : librist)
test('url_profile_parse', test_url_profile_parse, suite:['unit'])

# ?profile= URL override semantics inside rist_peer_create.
test_url_profile_override = executable('test_url_profile_override',
                                       'test_url_profile_override.c',
                                       include_directories : inc,
                                       link_with : librist)
test('url_profile_override', test_url_profile_override, suite:['unit'])

# ?srp-compat= URL parsing exercised through the public rist_parse_address2 API.
test_url_srp_compat_parse = executable('test_url_srp_compat_parse',
                                       'test_url_srp_compat_parse.c',
                                       include_directories : inc,
                                       link_with : librist)
test('url_srp_compat_parse', test_url_srp_compat_parse, suite:['unit'])

# Versioned peer-config defaults gate fields by RIST_PEER_CONFIG_VERSION.
test_peer_config_versioned_defaults = executable('test_peer_config_versioned_defaults',
                                                 'test_peer_config_versioned_defaults.c',
                                                 include_directories : inc,
                                                 link_with : librist)
test('peer_config_versioned_defaults', test_peer_config_versioned_defaults, suite:['unit'])

# ?recovery-priority= URL parsing exercised through the public API.
test_url_recovery_priority_parse = executable('test_url_recovery_priority_parse',
                                              'test_url_recovery_priority_parse.c',
                                              include_directories : inc,
                                              link_with : librist)
test('url_recovery_priority_parse', test_url_recovery_priority_parse, suite:['unit'])

# NACK routing peer-selection predicate (header-only, no link needed).
test_nack_peer_select = executable('test_nack_peer_select',
                                   'test_nack_peer_select.c',
                                   include_directories : inc)
test('nack_peer_select', test_nack_peer_select, suite:['unit'])

# Receiver gap-detector sequence-number gap helper (rist_seq_gap): verifies
# 16-bit wrap for short-sequence (Simple/Main) flows vs the true >64k gap for
# 32-bit (Advanced) flows. Pure, link-free.
test_seq_gap = executable('test_seq_gap',
                          'test_seq_gap.c',
                          include_directories : inc)
test('seq_gap', test_seq_gap, suite:['unit'])

# Expected-next-sequence helper (rist_seq_next): verifies 16-bit wrap for
# short-sequence flows (incl. odd successors) and 32-bit successor for
# Advanced flows. Pure, link-free.
test_seq_next = executable('test_seq_next',
                           'test_seq_next.c',
                           include_directories : inc)
test('seq_next', test_seq_next, suite:['unit'])

# rist_recovery_depth_set() level -> ring-size mapping/resize contract.
# Includes rist-private.h to inspect internal ring sizes.
test_recovery_depth = executable('test_recovery_depth',
                                 'test_recovery_depth.c',
                                 include_directories : inc,
                                 link_with : librist,
                                 dependencies : [threads, stdatomic_dependency])
test('recovery_depth', test_recovery_depth, suite:['unit'])

# udp:// scheme-prefix parsing: guards prefix[16] against copy-length
# underflow (leading '/') and out-of-bounds NUL write (over-long scheme).
test_url_udp_prefix_parse = executable('test_url_udp_prefix_parse',
                                       'test_url_udp_prefix_parse.c',
                                       include_directories : inc,
                                       link_with : librist)
test('url_udp_prefix_parse', test_url_udp_prefix_parse, suite:['unit'])

# ?recovery-depth= URL parsing exercised through the public API.
test_url_recovery_depth_parse = executable('test_url_recovery_depth_parse',
                                           'test_url_recovery_depth_parse.c',
                                           include_directories : inc,
                                           link_with : librist)
test('url_recovery_depth_parse', test_url_recovery_depth_parse, suite:['unit'])

# Retransmission sequence-domain predicate (header-only, no link needed):
# an Advanced head-end serving a Main-downgraded peer must resolve that
# peer's NACKs in the 16-bit RTP domain, else recovered_packets_total = 0.
test_retx_seq_domain = executable('test_retx_seq_domain',
                                  'test_retx_seq_domain.c',
                                  include_directories : inc)
test('retx_seq_domain', test_retx_seq_domain, suite:['unit'])

# Advanced Profile receive-side 1 MHz source-clock reconstruction
# (rist_adv_ts_reconstruct): wrap-safe delta accumulation, retransmit
# positioning, and the bounded-delta fallback to arrival. Pure, link-free.
test_adv_ts_reconstruct = executable('test_adv_ts_reconstruct',
                                     'test_adv_ts_reconstruct.c',
                                     include_directories : inc)
test('adv_ts_reconstruct', test_adv_ts_reconstruct, suite:['unit'])

# Flow re-anchor staleness guard: a packet from a leg queued deeper than the
# buffer must not become the flow baseline. Header-only, no link.
test_reanchor = executable('test_reanchor',
                           'test_reanchor.c',
                           include_directories : inc)
test('reanchor', test_reanchor, suite:['unit'])

# Grace period that keeps a silent peer in the send rotation for one recovery
# buffer window (#196), so a late RTCP reply does not cut a single-path stream
# whose receiver is still there. Header-only, no link.
test_send_grace = executable('test_send_grace',
                             'test_send_grace.c',
                             include_directories : inc)
test('send_grace', test_send_grace, suite:['unit'])

# RTT-based bonded-leg muting hysteresis state machine (header-only, no link).
test_rtt_mute = executable('test_rtt_mute',
                           'test_rtt_mute.c',
                           include_directories : inc)
test('rtt_mute', test_rtt_mute, suite:['unit'])

# Retransmission-budget guard: ?bandwidth= caps payload plus retransmissions
# together, so a ceiling at or under the payload rate refuses every NACK while
# only logging it at debug level. Header-only, no link.
test_bandwidth_guard = executable('test_bandwidth_guard',
                                  'test_bandwidth_guard.c',
                                  include_directories : inc)
test('bandwidth_guard', test_bandwidth_guard, suite:['unit'])

# recovery_maxbitrate = 0 through the C API means "unset", not "no ceiling",
# and must be replaced with the default before a peer runs (#229).
test_recovery_maxbitrate_zero = executable('test_recovery_maxbitrate_zero',
                                           'test_recovery_maxbitrate_zero.c',
                                           include_directories : inc,
                                           link_with : librist)
test('recovery_maxbitrate_zero', test_recovery_maxbitrate_zero, suite:['unit'])

# ?rtt-drop= et al URL parsing exercised through the public API.
test_url_rtt_drop_parse = executable('test_url_rtt_drop_parse',
                                     'test_url_rtt_drop_parse.c',
                                     include_directories : inc,
                                     link_with : librist)
test('url_rtt_drop_parse', test_url_rtt_drop_parse, suite:['unit'])

# ?multiplex-mode= / ?rtp-ptype= URL parsing at the compiled-in udp config
# version, so a bump cannot leave either unreachable.
test_url_udp_versioned_params = executable('test_url_udp_versioned_params',
                                           'test_url_udp_versioned_params.c',
                                           include_directories : inc,
                                           link_with : librist)
test('url_udp_versioned_params', test_url_udp_versioned_params, suite:['unit'])

# TUN CIDR parsing (IPv4 + IPv6) used by risttunnel -l.
test_tun_cidr_parse = executable('test_tun_cidr_parse',
                                 'test_tun_cidr_parse.c',
                                 include_directories : inc,
                                 link_with : librist)
test('tun_cidr_parse', test_tun_cidr_parse, suite:['unit'])

# CBR output pacing scheduler (rist_pacer): rate estimate, occupancy trim,
# due-time schedule and slip resync. Every failure mode of this module still
# emits packets -- at the wrong cadence or the wrong rate -- so the invariants
# are asserted rather than inspected, including a full-sequence cross-check
# against an independent transcription of the algorithm.
test_rist_pacer = executable('test_rist_pacer',
                             'rist_pacer_test.c',
                             '../../../src/rist_pacer.c',
                             include_directories : inc)
test('rist_pacer', test_rist_pacer, suite:['unit'])

# ?cbr-output= parsing plus its context-wide override semantics. The setting is
# not per-peer -- a flow's legs share one output -- so conflicting peers must be
# refused rather than silently resolved.
test_url_cbr_output = executable('test_url_cbr_output',
                                 'test_url_cbr_output.c',
                                 include_directories : inc,
                                 link_with : librist)
test('url_cbr_output', test_url_cbr_output, suite:['unit'])
