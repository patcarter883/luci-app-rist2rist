#ifndef LIBRIST_CRYPTO_SRP_CONSTANTS_H
#define LIBRIST_CRYPTO_SRP_CONSTANTS_H


#include <librist/common.h>
typedef enum
{
    /* Slots 0 and 1 (formerly NG_512, NG_768) are reserved to keep the
     * post-removal integer values of the surviving groups stable. */
    LIBRIST_SRP_NG_RESERVED_0 = 0,
    LIBRIST_SRP_NG_RESERVED_1 = 1,
    LIBRIST_SRP_NG_1024       = 2,
    LIBRIST_SRP_NG_2048       = 3,
    LIBRIST_SRP_NG_4096       = 4,
    LIBRIST_SRP_NG_8192       = 5
} librist_srp_ng_e;

#define LIBRIST_SRP_NG_DEFAULT LIBRIST_SRP_NG_2048

//Marked as public because we want to use it in ristsrppassword. NOT (yet) intended for public use, so zero API/ABI guarantees/promises.
RIST_API int librist_get_ng_constants(librist_srp_ng_e ng_pair, const char **n, const char **g);

#endif /* LIBRIST_CRYPTO_SRP_CONSTANTS_H */
