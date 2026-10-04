# librist. Copyright (c) 2020 SipRadius LLC. All right reserved.
# Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
# SPDX-License-Identifier: BSD-2-Clause

if not builtin_mbedtls
    mbedcrypto_lib = dependency('MbedTLS', required: false, method: 'cmake', modules: ['MbedTLS::mbedcrypto'])
    if not mbedcrypto_lib.found()
        mbedcrypto_lib = cc.find_library('mbedcrypto', required: required_library, has_headers: ['mbedtls/aes.h'])
        if not mbedcrypto_lib.found()
            builtin_mbedtls = true
        endif
    endif
    if mbedcrypto_lib.found() and mbedcrypto_lib.type_name() != 'internal'
        mbedcrypto_lib_found = true
		mpi_random_test = '''
#include <mbedtls/bignum.h>
void test_has_func() { mbedtls_mpi_random(NULL, 0, NULL, NULL, NULL); }
'''
		cdata.set10('MBEDTLS_HAS_MPI_RANDOM', cc.compiles(mpi_random_test, name: 'MbedTLS has mbedtls_mpi_random()', dependencies: mbedcrypto_lib))
    endif
endif
if builtin_mbedtls and not mbedcrypto_lib_found
    message('Using builtin mbedtls code')
    mbedcrypto_lib_includes = include_directories('library','include')
    add_project_arguments(['-D_FILE_OFFSET_BITS=64'], language: 'c')
    mbedcrypto_src = files(
                    'library/aes.c',
                    'library/aesni.c',
                    'library/aesce.c',
                    'library/aria.c',
                    'library/asn1parse.c',
                    'library/asn1write.c',
                    'library/base64.c',
                    'library/bignum.c',
                    'library/bignum_core.c',
                    'library/bignum_mod.c',
                    'library/bignum_mod_raw.c',
                    'library/block_cipher.c',
                    'library/camellia.c',
                    'library/ccm.c',
                    'library/chacha20.c',
                    'library/chachapoly.c',
                    'library/cipher.c',
                    'library/cipher_wrap.c',
                    'library/cmac.c',
                    'library/constant_time.c',
                    'library/ctr_drbg.c',
                    'library/des.c',
                    'library/dhm.c',
                    'library/ecdh.c',
                    'library/ecdsa.c',
                    'library/ecjpake.c',
                    'library/ecp.c',
                    'library/ecp_curves.c',
                    'library/ecp_curves_new.c',
                    'library/entropy.c',
                    'library/entropy_poll.c',
                    'library/error.c',
                    'library/gcm.c',
                    'library/hkdf.c',
                    'library/hmac_drbg.c',
                    'library/lmots.c',
                    'library/lms.c',
                    'library/md.c',
                    'library/md5.c',
                    'library/memory_buffer_alloc.c',
                    'library/nist_kw.c',
                    'library/oid.c',
                    'library/padlock.c',
                    'library/pem.c',
                    'library/pk.c',
                    'library/pk_ecc.c',
                    'library/pk_wrap.c',
                    'library/pkcs12.c',
                    'library/pkcs5.c',
                    'library/pkparse.c',
                    'library/pkwrite.c',
                    'library/platform.c',
                    'library/platform_util.c',
                    'library/poly1305.c',
                    'library/psa_crypto.c',
                    'library/psa_crypto_aead.c',
                    'library/psa_crypto_cipher.c',
                    'library/psa_crypto_client.c',
                    'library/psa_crypto_driver_wrappers_no_static.c',
                    'library/psa_crypto_ecp.c',
                    'library/psa_crypto_ffdh.c',
                    'library/psa_crypto_hash.c',
                    'library/psa_crypto_mac.c',
                    'library/psa_crypto_pake.c',
                    'library/psa_crypto_rsa.c',
                    'library/psa_crypto_random.c',
                    'library/psa_crypto_se.c',
                    'library/psa_crypto_slot_management.c',
                    'library/psa_crypto_storage.c',
                    'library/psa_its_file.c',
                    'library/psa_util.c',
                    'library/ripemd160.c',
                    'library/rsa.c',
                    'library/rsa_alt_helpers.c',
                    'library/sha1.c',
                    'library/sha256.c',
                    'library/sha512.c',
                    'library/sha3.c',
                    'library/threading.c',
                    'library/timing.c',
                    'library/version.c',
                    'library/version_features.c',
    )
    mbedcrypto_c_args = cc.get_supported_arguments([
        '-Wno-undef', '-Wno-redundant-decls',
        '-Wno-incompatible-function-pointer-types',
        '-Wno-incompatible-pointer-types',
        '-Wno-shadow', '-Wno-unused-parameter',
        '-Wno-pedantic',
        '-Wno-unguarded-availability',
    ])
    my_mbedcrypto_lib = static_library('mbedcrypto',
        mbedcrypto_src,
        include_directories: mbedcrypto_lib_includes,
        c_args: mbedcrypto_c_args,
    )
    mbedcrypto_lib = declare_dependency(
        link_with: my_mbedcrypto_lib,
        include_directories: mbedcrypto_lib_includes,
    )
    inc += mbedcrypto_lib_includes
    mbedcrypto_lib_found = true
	cdata.set10('MBEDTLS_HAS_MPI_RANDOM', true)
    # We could compile libmbedcrypto.a using make on contrib/mbedtls and copy to the build folder instead
    #my_mbedcrypto_inc = mbedcrypto_lib_includes
    #my_mbedcrypto_lib = static_library('mbedcrypto')
    #mbedcrypto_lib = declare_dependency(link_with : my_mbedcrypto_lib, include_directories : my_mbedcrypto_inc)
endif
