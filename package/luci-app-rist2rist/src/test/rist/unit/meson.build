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