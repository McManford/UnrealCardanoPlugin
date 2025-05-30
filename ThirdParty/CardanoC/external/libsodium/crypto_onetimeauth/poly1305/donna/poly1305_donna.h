#ifndef poly1305_donna_H
#define poly1305_donna_H

#include <stddef.h>

#include "crypto_onetimeauth_poly1305.h"
#include "external/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.h"

extern struct crypto_onetimeauth_poly1305_implementation
    crypto_onetimeauth_poly1305_donna_implementation;

#endif /* poly1305_donna_H */
