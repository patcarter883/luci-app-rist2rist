# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# SPDX-License-Identifier: BSD-2-Clause

subdir('unit')

extra_sources = ['../../contrib/time-shim.c','../../contrib/pthread-shim.c']

if filter_obj
	extra_sources += [objcopy_fake_file ]
endif


test_send_receive = executable('test_send_receive',
                                'test_send_receive.c',
                                extra_sources,
                                include_directories: inc,
                                link_with: librist,
                                dependencies: [
                                    threads,
                                    tools_dependencies,
									stdatomic_dependency
                                ])

test_sender_restart = executable('test_sender_restart',
                                'test_sender_restart.c',
                                extra_sources,
                                include_directories: inc,
                                link_with: librist,
                                dependencies: [
                                    threads,
                                    tools_dependencies,
									stdatomic_dependency
                                ])

test_reflector = executable('test_reflector',
                            'test_reflector.c',
                            extra_sources,
                            include_directories: inc,
                            link_with: librist,
                            dependencies: [
                                threads,
                                tools_dependencies,
                                stdatomic_dependency
                            ])

# issue #188 coverage: listener-side cname re-association.  Three
# modes (plaintext / psk / srp) exercise the SRP-only gate: only an
# authenticated per-peer SRP session may migrate an existing peer
# record onto a new source tuple.
test_nat_port_rebind = executable('test_nat_port_rebind',
                                  'test_nat_port_rebind.c',
                                  extra_sources,
                                  include_directories: inc,
                                  link_with: librist,
                                  dependencies: [
                                      threads,
                                      tools_dependencies,
                                      stdatomic_dependency
                                  ])

# Security regression guard: a shared-PSK peer that forges the victim's
# cname must NOT be absorbed into the victim's peer record (cname is not
# a per-peer secret under PSK).
test_psk_cname_hijack = executable('test_psk_cname_hijack',
                                   'test_psk_cname_hijack.c',
                                   extra_sources,
                                   include_directories: inc,
                                   link_with: librist,
                                   dependencies: [
                                       threads,
                                       tools_dependencies,
                                       stdatomic_dependency
                                   ])

# Multipath safety: two same-cname bonded paths must not be merged by
# the cname re-association, and a healthy path must not rebind.
test_multipath_cname = executable('test_multipath_cname',
                                  'test_multipath_cname.c',
                                  extra_sources,
                                  include_directories: inc,
                                  link_with: librist,
                                  dependencies: [
                                      threads,
                                      tools_dependencies,
                                      stdatomic_dependency
                                  ])

# Multipath safety: one bonded leg rebinds mid-stream while the other
# stays alive; the survivor must be undisturbed and the stream must not
# stall.
test_multipath_leg_rebind = executable('test_multipath_leg_rebind',
                                       'test_multipath_leg_rebind.c',
                                       extra_sources,
                                       include_directories: inc,
                                       link_with: librist,
                                       dependencies: [
                                           threads,
                                           tools_dependencies,
                                           stdatomic_dependency
                                       ])

# Dynamic RTT-based bonded-leg muting (?rtt-drop=): a real two-leg bonded
# sender must mute a leg whose RTT spikes over the ceiling, reroute payload to
# the healthy leg, restore on recovery, and never black out the stream.
test_rtt_mute_bonding = executable('test_rtt_mute_bonding',
                                   'test_rtt_mute_bonding.c',
                                   extra_sources,
                                   include_directories: inc,
                                   link_with: librist,
                                   dependencies: [
                                       threads,
                                       tools_dependencies,
                                       stdatomic_dependency
                                   ])

# issue #188 coverage: receiver-caller socket rebind on session
# silence (plaintext + shared-PSK; SRP uses listener-side path).
test_caller_socket_rebind = executable('test_caller_socket_rebind',
                                       'test_caller_socket_rebind.c',
                                       extra_sources,
                                       include_directories: inc,
                                       link_with: librist,
                                       dependencies: [
                                           threads,
                                           tools_dependencies,
                                           stdatomic_dependency
                                       ])

test_eap_authenticator_restart = executable('test_eap_authenticator_restart',
                                       'test_eap_authenticator_restart.c',
                                       extra_sources,
                                       include_directories: inc,
                                       link_with: librist,
                                       dependencies: [
                                           threads,
                                           tools_dependencies,
                                           stdatomic_dependency
                                       ])


test_oob_read = executable('test_oob_read',
                           'test_oob_read.c',
                           extra_sources,
                           include_directories: inc,
                           link_with: librist,
                           dependencies: [
                               threads,
                               tools_dependencies,
                               stdatomic_dependency
                           ])


###Sender restart test (bug fix verification)
test('Sender restart test', test_sender_restart, args: ['5'], suite: ['regression', 'sender'])

###Out-of-band polling read (rist_oob_read) round-trip
test('OOB polling read Main profile', test_oob_read,
     args: ['1', 'rist://@127.0.0.1:8190', 'rist://127.0.0.1:8190'],
     suite: ['regression', 'oob'], timeout: 60)
test('OOB polling read Advanced profile', test_oob_read,
     args: ['2', 'rist://@127.0.0.1:8192', 'rist://127.0.0.1:8192'],
     suite: ['regression', 'oob'], timeout: 60)

###issue #188 NAT source-port rebind recovery
test('NAT port rebind cname re-association (plaintext gate refuses)', test_nat_port_rebind,
     suite: ['regression', 'nat'], timeout: 90)
test('NAT port rebind cname re-association (psk gate refuses)', test_nat_port_rebind,
     args: ['psk'], suite: ['regression', 'nat'], timeout: 90)
test('Receiver caller socket rebind on silence (plaintext)', test_caller_socket_rebind,
     suite: ['regression', 'nat'], timeout: 90)
test('Receiver caller socket rebind on silence (psk)', test_caller_socket_rebind,
     args: ['psk'], suite: ['regression', 'nat'], timeout: 90)
# PSK cname forgery must not take over an existing peer record.
test('NAT rebind PSK cname hijack is refused', test_psk_cname_hijack,
     suite: ['regression', 'nat', 'security'], timeout: 90)
# Two bonded same-cname paths must stay distinct and not rebind.
test('Multipath same-cname paths stay distinct (psk)', test_multipath_cname,
     suite: ['regression', 'nat', 'multipath'], timeout: 90)
# RTT-based bonded-leg auto-mute: mute on spike, reroute, restore, guard.
test('Bonded leg auto-mutes on RTT spike and recovers', test_rtt_mute_bonding,
     suite: ['regression', 'multipath'], timeout: 120)
if have_srp
	# Positive path: an authenticated SRP caller IS migrated onto the
	# new source tuple after a NAT source-port rebind.
	test('NAT port rebind cname re-association (srp migration)', test_nat_port_rebind,
	     args: ['srp'], suite: ['regression', 'nat', 'srp'], timeout: 120)
	# Two bonded SRP paths with the SAME username/password + cname must
	# stay distinct even though the SRP gate lets re-association fire.
	test('Multipath same-cname paths stay distinct (srp)', test_multipath_cname,
	     args: ['srp'], suite: ['regression', 'nat', 'multipath', 'srp'], timeout: 120)
	# One bonded SRP leg rebinds mid-stream while the other stays alive.
	test('Multipath one leg rebinds mid-stream (srp)', test_multipath_leg_rebind,
	     suite: ['regression', 'nat', 'multipath', 'srp'], timeout: 120)
	# Regression for the EAP-SRP no-rebind bug: an SRP caller whose
	# listener restarts (all session state lost) must reset EAP and
	# re-authenticate on the fresh socket by itself, with no operator
	# intervention.  Before the fix the SRP caller was killed and stayed
	# idle forever.
	test('Receiver caller socket rebind on silence (srp)', test_caller_socket_rebind,
	     args: ['srp'], suite: ['regression', 'nat', 'srp'], timeout: 120)
	# Regression for the EAP-SRP re-auth lockout after an *authenticator*
	# (listener/hub) restart: the fresh authenticator re-challenges with
	# IDENTITY, but a caller parked in EAP SUCCESS refused it forever, so the
	# hub sat in "Waiting for EAP" and carried 0 packets.  Distinct from the
	# silence rebind above (the authenticator is NOT silent here); recovery
	# must come from the identity-request re-auth path.
	test('EAP-SRP caller re-auth after authenticator restart (srp)', test_eap_authenticator_restart,
	     suite: ['regression', 'srp'], timeout: 120)
	# Regression for the bonded EAP-SRP sender-leg flap bug (issue #224).
	# A bonded caller's leg is silenced (100% loss both ways) with its
	# interface left UP, so its miface-bound socket persists on the same
	# source tuple; the listener purges the timed-out leg while the other
	# leg keeps the bond alive.  When the loss clears the caller must reset
	# EAP and re-authenticate the leg on its own -- before the fix it
	# stayed wedged in stale EAP SUCCESS forever.  This needs real
	# interfaces + tc packet loss (a loopback leg has no miface binding and
	# self-heals via a new-port handshake, hiding the bug), so it runs only
	# on Linux as root with netns/tc and cleanly SKIPs (exit 77) otherwise.
	if get_option('built_tools')
		test('Bonded SRP leg re-authenticates after a same-tuple flap (srp, netns)',
		     find_program('test_bonded_leg_flap_netns.sh'),
		     args: [ristsender_exe, ristreceiver_exe],
		     suite: ['netns', 'nat', 'multipath', 'srp'], timeout: 120)
		# Companion: a sub-grace stall must NOT re-auth. Same topology, but a
		# short silence (under the buffer-derived grace) must ride through on
		# the existing session instead of tearing down and re-handshaking.
		test('Bonded SRP leg rides through a sub-grace stall without re-auth (srp, netns)',
		     find_program('test_bonded_leg_stall_grace_netns.sh'),
		     args: [ristsender_exe, ristreceiver_exe],
		     suite: ['netns', 'nat', 'multipath', 'srp'], timeout: 120)
		# A leg muted for high RTT plus its only sibling stalled for silence
		# must not leave the balancer with zero carriers: the receiver must
		# keep getting data on the reinstated leg instead of starving.
		test('Bonded muted+stalled split keeps a carrier (srp, netns)',
		     find_program('test_bonded_carrier_never_starved_netns.sh'),
		     args: [ristsender_exe, ristreceiver_exe],
		     suite: ['netns', 'nat', 'multipath', 'srp'], timeout: 120)
	endif
endif

###?profile= URL override tests (rist_*_create profile != URL profile)
test('?profile=2 URL overrides Main to Advanced',
     test_send_receive,
     args: ['1', 'rist://@127.0.0.1:7080?profile=2', 'rist://127.0.0.1:7080?profile=2', '0'],
     suite: ['url-profile', 'advanced', 'unicast', 'server'])
test('?profile=2 URL overrides Main to Advanced + 10% loss',
     test_send_receive,
     args: ['1', 'rist://@127.0.0.1:7082?profile=2&rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7082?profile=2&rtt-max=10&rtt-min=1', '10'],
     suite: ['url-profile', 'advanced', 'unicast', 'server'])
test('?profile=1 URL overrides Advanced to Main',
     test_send_receive,
     args: ['2', 'rist://@127.0.0.1:7084?profile=1', 'rist://127.0.0.1:7084?profile=1', '0'],
     suite: ['url-profile', 'main', 'unicast', 'server'])
test('?profile=2 URL overrides Simple to Advanced',
     test_send_receive,
     args: ['0', 'rist://@127.0.0.1:7086?profile=2', 'rist://127.0.0.1:7086?profile=2', '0'],
     suite: ['url-profile', 'advanced', 'unicast', 'server'])

###Cross-profile interop (TR-06-3 Section 9): mismatched sender/receiver profiles
### on one flow. Exercises the Advanced sender's Main-Profile fallback (sends
### Main-conformant media until the peer advertises I=1) and the Advanced
### receiver's mid-stream framing-transition reset.
test('Interop - Advanced sender to Main receiver',
     test_send_receive,
     args: ['1', 'rist://@127.0.0.1:7090?profile=1', 'rist://127.0.0.1:7090?profile=2', '0'],
     suite: ['interop', 'advanced', 'main', 'unicast'])
test('Interop - Advanced sender to Main receiver + 10% loss',
     test_send_receive,
     args: ['1', 'rist://@127.0.0.1:7092?profile=1&rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7092?profile=2&rtt-max=10&rtt-min=1', '10'],
     suite: ['interop', 'advanced', 'main', 'unicast'])
test('Interop - Main sender to Advanced receiver',
     test_send_receive,
     args: ['2', 'rist://@127.0.0.1:7094?profile=2', 'rist://127.0.0.1:7094?profile=1', '0'],
     suite: ['interop', 'advanced', 'main', 'unicast'])
test('Interop - Main sender to Advanced receiver + 10% loss',
     test_send_receive,
     args: ['2', 'rist://@127.0.0.1:7096?profile=2&rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7096?profile=1&rtt-max=10&rtt-min=1', '10'],
     suite: ['interop', 'advanced', 'main', 'unicast'])

###Reflector tests
test('Reflector functionality', test_reflector, suite: ['main', 'reflector'], timeout: 120)

###Simple profile tests
#Unicast
test('Simple profile unicast', test_send_receive, args: ['0', 'rist://@127.0.0.1:1234', 'rist://127.0.0.1:1234', '0'], suite: ['simple', 'unicast'])
test('Simple profile unicast packet loss 10%', test_send_receive, args: ['0', 'rist://@127.0.0.1:2234', 'rist://127.0.0.1:2234', '10'],suite: ['simple', 'unicast'])
test('Simple profile unicast packet loss 25%', test_send_receive, args: ['0', 'rist://@127.0.0.1:3234', 'rist://127.0.0.1:3234', '25'],suite: ['simple', 'unicast'])
if (host_machine.system() != 'darwin')
    #Multicast
    test('Simple profile multicast', test_send_receive, args: ['0', 'rist://@239.0.0.1:1236?rtt-max=10&rtt-min=1', 'rist://239.0.0.1:1236?rtt-max=10&rtt-min=1', '0'],suite: ['simple', 'multicast'])
    test('Simple profile multicast packet loss 10%', test_send_receive, args: ['0', 'rist://@239.0.0.2:2236?rtt-max=10&rtt-min=1', 'rist://239.0.0.2:2236?rtt-max=10&rtt-min=1', '10'],suite: ['simple', 'multicast'])
    test('Simple profile multicast packet loss 25%', test_send_receive, args: ['0', 'rist://@239.0.0.3:3236?rtt-max=10&rtt-min=1', 'rist://239.0.0.3:3236?rtt-max=10&rtt-min=1', '25'],suite: ['simple', 'multicast'])
endif

###Main profile tests:
#Null Packet Deletion
test('Main profile NPD receive server mode, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:3501?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:3501?rtt-max=10&rtt-min=1', '0', '1'], suite: ['main', 'unicast', 'server', 'NPD'])
test('Main profile NPD receive client mode, sender server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:3502?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:3502?rtt-max=10&rtt-min=1', '0', '1'], suite: ['main', 'unicast', 'client', 'NPD'])
#Sender connecting to receiver
test('Main profile receive server mode, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:4001?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:4001?rtt-max=10&rtt-min=1', '0'],suite: ['main', 'unicast', 'server'])
test('Main profile receive server mode, sender client mode packet loss 10%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4002?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:4002?rtt-max=10&rtt-min=1', '10'],suite: ['main', 'unicast', 'server'])
test('Main profile receive server mode, sender client mode packet loss 25%', test_send_receive, args: ['1', 'rist://@127.0.0.1:4003?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:4003?rtt-max=10&rtt-min=1', '25'],suite: ['main', 'unicast', 'server'])
#Receiver connecting to sender
test('Main profile receive client mode, sender server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:5001?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:5001?rtt-max=10&rtt-min=1', '0'],suite: ['main', 'unicast', 'client'])
test('Main profile receive client mode, sender server mode packet loss 10%', test_send_receive, args: ['1', 'rist://127.0.0.1:5002?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:5002?rtt-max=10&rtt-min=1', '10'],suite: ['main', 'unicast', 'client'])
test('Main profile receive client mode, sender server mode packet loss 25%', test_send_receive, args: ['1', 'rist://127.0.0.1:5003?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:5003?rtt-max=10&rtt-min=1', '25'],suite: ['main', 'unicast', 'client'])
#Encryption: TODO
test('Main profile encryption receive server mode, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:6001?secret=12345678&aes-type=128', 'rist://127.0.0.1:6001?secret=12345678&aes-type=128', '0'],suite: ['main', 'unicast', 'server', 'encryption'])
test('Main profile encryption receive client mode, sender server mode ', test_send_receive, args: ['1', 'rist://127.0.0.1:6002?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6002?secret=12345678&aes-type=128', '0'],suite: ['main', 'unicast', 'client', 'encryption'])
test('Main profile encryption receive client mode, sender server mode AES256 ', test_send_receive, args: ['1', 'rist://127.0.0.1:6007?secret=12345678&aes-type=256', 'rist://@127.0.0.1:6007?secret=12345678&aes-type=256', '0'],suite: ['main', 'unicast', 'client', 'encryption'])
#Caller-controlled seq (RIST_DATA_FLAGS_USE_SEQ) passthrough
test('Main profile USE_SEQ passthrough', test_send_receive, args: ['1', 'rist://@127.0.0.1:6020?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:6020?rtt-max=10&rtt-min=1', '0', '0', '1'], suite: ['main', 'unicast', 'use_seq'])
test('Main profile USE_SEQ passthrough 10% loss', test_send_receive, args: ['1', 'rist://@127.0.0.1:6021?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:6021?rtt-max=10&rtt-min=1', '10', '0', '1'], suite: ['main', 'unicast', 'use_seq'])
###Advanced profile tests (VSF TR-06-3):
test('Advanced profile receive server mode, sender client mode', test_send_receive, args: ['2', 'rist://@127.0.0.1:7001?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7001?rtt-max=10&rtt-min=1', '0'],suite: ['advanced', 'unicast', 'server'])
test('Advanced profile receive server mode, sender client mode packet loss 10%', test_send_receive, args: ['2', 'rist://@127.0.0.1:7002?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7002?rtt-max=10&rtt-min=1', '10'],suite: ['advanced', 'unicast', 'server'])
test('Advanced profile receive client mode, sender server mode', test_send_receive, args: ['2', 'rist://127.0.0.1:7003?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:7003?rtt-max=10&rtt-min=1', '0'],suite: ['advanced', 'unicast', 'client'])
test('Advanced profile receive client mode, sender server mode packet loss 10%', test_send_receive, args: ['2', 'rist://127.0.0.1:7004?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:7004?rtt-max=10&rtt-min=1', '10'],suite: ['advanced', 'unicast', 'client'])

###Phase C: Native control plane, 32-bit seq, Type 8 wrapping
test('Advanced profile server mode packet loss 25% (native NACK)', test_send_receive, args: ['2', 'rist://@127.0.0.1:7010?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7010?rtt-max=10&rtt-min=1', '25'],suite: ['advanced', 'unicast', 'server', 'phase-c'])
test('Advanced profile client mode packet loss 25% (native NACK)', test_send_receive, args: ['2', 'rist://127.0.0.1:7011?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:7011?rtt-max=10&rtt-min=1', '25'],suite: ['advanced', 'unicast', 'client', 'phase-c'])

###Phase D1: PSK encryption (AES-CTR, mode 1)
test('Advanced profile encryption server mode AES128', test_send_receive, args: ['2', 'rist://@127.0.0.1:7020?secret=12345678&aes-type=128', 'rist://127.0.0.1:7020?secret=12345678&aes-type=128', '0'],suite: ['advanced', 'unicast', 'server', 'encryption', 'phase-d1'])
test('Advanced profile encryption client mode AES128', test_send_receive, args: ['2', 'rist://127.0.0.1:7021?secret=12345678&aes-type=128', 'rist://@127.0.0.1:7021?secret=12345678&aes-type=128', '0'],suite: ['advanced', 'unicast', 'client', 'encryption', 'phase-d1'])
test('Advanced profile encryption server mode AES256', test_send_receive, args: ['2', 'rist://@127.0.0.1:7022?secret=12345678&aes-type=256', 'rist://127.0.0.1:7022?secret=12345678&aes-type=256', '0'],suite: ['advanced', 'unicast', 'server', 'encryption', 'phase-d1'])
test('Advanced profile encryption server mode AES128 + 10% loss', test_send_receive, args: ['2', 'rist://@127.0.0.1:7023?secret=12345678&aes-type=128', 'rist://127.0.0.1:7023?secret=12345678&aes-type=128', '10'],suite: ['advanced', 'unicast', 'server', 'encryption', 'phase-d1'])
test('Advanced profile encryption mismatch (should fail)', test_send_receive, args: ['2', 'rist://@127.0.0.1:7030?secret=12345678&aes-type=128', 'rist://127.0.0.1:7030', '0'], should_fail: true)
test('Advanced profile encryption mismatch reverse (should fail)', test_send_receive, args: ['2', 'rist://@127.0.0.1:7031', 'rist://127.0.0.1:7031?secret=12345678&aes-type=128', '0'], should_fail: true)

###Flow ID: stream-id via virt-dst-port on native AP Type 5
test('Advanced profile Flow ID server mode virt-dst-port', test_send_receive, args: ['2', 'rist://@127.0.0.1:7040?virt-dst-port=5000', 'rist://127.0.0.1:7040?virt-dst-port=5000', '0'],suite: ['advanced', 'unicast', 'server', 'flow-id'])
test('Advanced profile Flow ID client mode virt-dst-port', test_send_receive, args: ['2', 'rist://127.0.0.1:7041?virt-dst-port=5000', 'rist://@127.0.0.1:7041?virt-dst-port=5000', '0'],suite: ['advanced', 'unicast', 'client', 'flow-id'])

###Phase D4: Flow Attribute messages (CI=0x8001)
test('Advanced profile Flow Attribute server mode', test_send_receive, args: ['2', 'rist://@127.0.0.1:7060?rtt-max=10&rtt-min=1', 'rist://127.0.0.1:7060?rtt-max=10&rtt-min=1', '0', '0', '0', '1'],suite: ['advanced', 'unicast', 'server', 'flow-attr'])
test('Advanced profile Flow Attribute client mode', test_send_receive, args: ['2', 'rist://127.0.0.1:7061?rtt-max=10&rtt-min=1', 'rist://@127.0.0.1:7061?rtt-max=10&rtt-min=1', '0', '0', '0', '1'],suite: ['advanced', 'unicast', 'client', 'flow-attr'])

###Phase D6: LZ4 payload compression
test('Advanced profile LZ4 compression server mode', test_send_receive, args: ['2', 'rist://@127.0.0.1:7050', 'rist://127.0.0.1:7050?compression=1', '0'],suite: ['advanced', 'unicast', 'server', 'lz4'])
test('Advanced profile LZ4 compression client mode', test_send_receive, args: ['2', 'rist://127.0.0.1:7051', 'rist://@127.0.0.1:7051?compression=1', '0'],suite: ['advanced', 'unicast', 'client', 'lz4'])
test('Advanced profile LZ4 compression + 10% loss', test_send_receive, args: ['2', 'rist://@127.0.0.1:7052', 'rist://127.0.0.1:7052?compression=1', '10'],suite: ['advanced', 'unicast', 'server', 'lz4'])
test('Advanced profile LZ4 + AES128 server mode', test_send_receive, args: ['2', 'rist://@127.0.0.1:7053?secret=12345678&aes-type=128', 'rist://127.0.0.1:7053?secret=12345678&aes-type=128&compression=1', '0'],suite: ['advanced', 'unicast', 'server', 'lz4', 'encryption'])

###SRP authentication (Advanced Profile)
if have_srp
	test('Advanced profile SRP auth server mode AES128', test_send_receive, args: ['2', 'rist://@127.0.0.1:7070?secret=12345678&aes-type=128&username=testuser&password=testpassword', 'rist://127.0.0.1:7070?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['advanced', 'unicast', 'server', 'encryption', 'srp'], should_fail: false)
	test('Advanced profile SRP auth client mode AES128', test_send_receive, args: ['2', 'rist://127.0.0.1:7071?secret=12345678&aes-type=128&username=testuser&password=testpassword', 'rist://@127.0.0.1:7071?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['advanced', 'unicast', 'client', 'encryption', 'srp'], should_fail: false)
	test('Advanced profile SRP auth client no SRP (should fail)', test_send_receive, args: ['2', 'rist://127.0.0.1:7072?secret=12345678&aes-type=128', 'rist://@127.0.0.1:7072?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'], suite: ['advanced', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
	test('Advanced profile SRP auth password mismatch (should fail)', test_send_receive, args: ['2', 'rist://127.0.0.1:7073?secret=12345678&aes-type=128&username=testuser&password=wrongpassword', 'rist://@127.0.0.1:7073?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['advanced', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
endif

#Encryption tests where 1 side has enabled encryption these should fail
test('Main profile encryption receive server mode unencrypted, sender client mode', test_send_receive, args: ['1', 'rist://@127.0.0.1:6003', 'rist://127.0.0.1:6003?secret=12345678&aes-type=128', '0'], should_fail: true)
test('Main profile encryption receive server mode, sender client mode unencrypted', test_send_receive, args: ['1', 'rist://@127.0.0.1:6004?secret=12345678&aes-type=128', 'rist://127.0.0.1:6004', '0'], should_fail: true)
test('Main profile encryption client mode unencrypted, sender server mode', test_send_receive, args: ['1', 'rist://127.0.0.1:6005', 'rist://@127.0.0.1:6005?secret=12345678&aes-type=128', '0'], should_fail: true)
test('Main profile encryption client mode, sender server mode unencrypted', test_send_receive, args: ['1', 'rist://127.0.0.1:6006?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6006', '0'], should_fail: true)
#Test SRP Auth
if have_srp
	test('Main profile encryption receive client mode, sender server mode, SRP auth', test_send_receive, args: ['1', 'rist://127.0.0.1:6008?secret=12345678&aes-type=128&username=testuser&password=testpassword', 'rist://@127.0.0.1:6008?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: false)
	test('Main profile encryption receive client mode, sender server mode, SRP auth, client no SRP', test_send_receive, args: ['1', 'rist://127.0.0.1:6009?secret=12345678&aes-type=128', 'rist://@127.0.0.1:6009?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'], suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
	test('Main profile encryption receive client mode, sender server mode, SRP auth, server no SRP', test_send_receive, args: ['1', 'rist://127.0.0.1:6010?secret=12345678&aes-type=128&username=testuser&password=testpassword', 'rist://@127.0.0.1:6010?secret=12345678&aes-type=128', '0'], suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
	test('Main profile encryption receive client mode, sender server mode, SRP auth, password mismatch', test_send_receive, args: ['1', 'rist://127.0.0.1:6011?secret=12345678&aes-type=128&username=testuser&password=wrongpassword', 'rist://@127.0.0.1:6011?secret=12345678&aes-type=128&username=testuser&password=testpassword', '0'],suite: ['main', 'unicast', 'server', 'encryption', 'srp'], should_fail: true)
endif
