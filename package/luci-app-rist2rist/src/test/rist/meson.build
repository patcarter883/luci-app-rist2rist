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


###Sender restart test (bug fix verification)
test('Sender restart test', test_sender_restart, args: ['5'], suite: ['regression', 'sender'])

###Reflector tests
test('Reflector functionality', test_reflector, suite: ['main', 'reflector'])

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
