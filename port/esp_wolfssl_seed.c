/*
 * ESP-IDF seed implementation for wolfSSL
 * Uses the hardware random number generator
 */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "esp_random.h"

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    (void)os;

    if (output == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Use ESP-IDF's hardware RNG */
    esp_fill_random(output, sz);

    return 0;
}
