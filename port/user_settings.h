/* user_settings.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */

#include "sdkconfig.h"

/* Disable ESP32 hardware crypto acceleration.
 * These are also defined in CMakeLists.txt to ensure they're set before settings.h
 * This is required because the ESP32 crypto peripheral APIs changed in IDF 6.x
 * and the wolfSSL Espressif port files are not compatible */
#ifndef NO_ESP32_CRYPT
#define NO_ESP32_CRYPT
#endif
#ifndef NO_WOLFSSL_ESP32_CRYPT_HASH
#define NO_WOLFSSL_ESP32_CRYPT_HASH
#endif
#ifndef NO_WOLFSSL_ESP32_CRYPT_AES
#define NO_WOLFSSL_ESP32_CRYPT_AES
#endif
#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI
#endif
/* NO_WOLFSSL_ESP32WROOM32_CRYPT is deprecated in newer wolfSSL versions */
#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MP_MUL
#endif
#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_MULMOD
#endif
#ifndef NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
#define NO_WOLFSSL_ESP32_CRYPT_RSA_PRI_EXPTMOD
#endif

#undef WOLFSSL_ESPIDF
#define WOLFSSL_ESPIDF

/* Don't define WOLFSSL_ESPWROOM32 - it triggers hardware crypto which is
 * incompatible with IDF 6.x (the Espressif port files use deprecated APIs) */
/* #define WOLFSSL_ESPWROOM32 */

/* Explicitly undefine hardware crypto macros that may have been set by settings.h */
#undef WOLFSSL_ESP32_CRYPT

/* Ensure ESP-IDF FreeRTOS headers are used */
#ifndef PLATFORMIO
#define PLATFORMIO
#endif

/* ESP-IDF uses FreeRTOS, but wolfSSL v5.8.4 expects pthread when WOLFSSL_ESPIDF is defined */
/* Include pthread.h to provide pthread_t type */
#include <pthread.h>

#define BENCH_EMBEDDED

/* ===== RSA 4096-bit Key Support (ISRG Root X1 uses 4096-bit RSA) ===== */
/* Enable larger RSA key support */
#define USE_CERT_BUFFERS_4096
/* FP_MAX_BITS must be at least 2x the key size for math operations */
#define FP_MAX_BITS 8192
/* Enable RSA key generation support (needed for cert parsing) */
#define WOLFSSL_KEY_GEN
/* Enable certificate generation/parsing support */
#define WOLFSSL_CERT_GEN
/* Enable certificate request support */
#define WOLFSSL_CERT_REQ
/* Enable certificate extension support */
#define WOLFSSL_CERT_EXT
/* Allow unknown/undecoded X509v3 extensions - critical for modern CA certs */
#define WOLFSSL_ALLOW_UNDECODED_EXTENSIONS

/* TLS 1.3                                 */
// #define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define WC_RSA_PSS
#define HAVE_HKDF
#define HAVE_AEAD
#define HAVE_SUPPORTED_CURVES

/* when you want to use SINGLE THREAD */
/* #define SINGLE_THREADED */
#define NO_FILESYSTEM

#define HAVE_AESGCM
/* SHA algorithms - required for certificate signature verification */
#define WOLFSSL_SHA256
/* when you want to use SHA384 */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
/* CURVE25519_SMALL disabled - needed for load_3/load_4 functions used by ge_operations.c */
/* #define CURVE25519_SMALL */
#define HAVE_ED25519

/* ALPN in wolfSSL is enabled by default, can be disabled with menuconfig */
#define HAVE_ALPN

#define HAVE_SNI

#ifdef CONFIG_WOLFSSL_HAVE_OCSP
#define HAVE_OCSP
#define HAVE_CERTIFICATE_STATUS_REQUEST
#endif

/* do not use wolfssl defined app_main function used to test esp-wolfssl */
#define NO_MAIN_DRIVER

/* Define NO_INLINE to use misc.h instead of including misc.c directly */
/* This is needed because misc.c is excluded from the build */
#define NO_INLINE

/* you can disable folowing cipher suites by uncommenting following lines */
// #define NO_DSA
// #define NO_DH

/* These Flags are defined to make wolfssl not use some insecure cipher suites */
#define NO_MD4
#define NO_DES3
#define NO_RC4
#define NO_RABBIT
#define NO_OLD_TLS

/* Full OpenSSL X509 compatibility is enabled via OPENSSL_EXTRA below */
/* OPENSSL_EXTRA_X509_SMALL removed - it may limit CA certificate parsing */

/* Only requires the peer certificate to validate to a trusted certificate.
 * If peer sends additional certificates not in the chain they are allowed,
 * but not trusted */
/* Note: WOLFSSL_ALT_CERT_CHAINS can interfere with standard chain verification */
/* Disabled to use standard certificate chain verification */
#define WOLFSSL_ALT_CERT_CHAINS
#define WOLFSSL_TRUST_PEER_CERT

#define WOLFSSL_BASE64_ENCODE

/* Static ciphers are highly discouraged */
// #define WOLFSSL_STATIC_RSA
// #define WOLFSSL_STATIC_PSK
// #define WOLFSSL_STATIC_DH

/* This enables the most common openssl compatibility layer API's */
#define OPENSSL_EXTRA

/* This enables all Openssl compatibility layer functions
 * Note: this is large and cannot be used with NO_ASN_TIME */
// #define OPENSSL_ALL

/* Use smaller version of the certificate checking code */
/* Disabled: WOLFSSL_SMALL_CERT_VERIFY causes issues with full chain verification
 * when only the root CA is provided (e.g., leaf -> intermediate -> root) */
/* #define WOLFSSL_SMALL_CERT_VERIFY */

/* Reduces the stack and session cache used by wolfssl */
#define WOLFSSL_SMALL_STACK
#define SMALL_SESSION_CACHE

/* when you want to use pkcs7 */
/* #define HAVE_PKCS7 */

#if defined(HAVE_PKCS7)
    #define HAVE_AES_KEYWRAP
    #define HAVE_X963_KDF
    #define WOLFSSL_AES_DIRECT
#endif

/* when you want to use aes counter mode */
/* #define WOLFSSL_AES_DIRECT */
/* #define WOLFSSL_AES_COUNTER */

/* esp32-wroom-32se specific definition */
#if defined(WOLFSSL_ESPWROOM32SE)
    #define WOLFSSL_ATECC508A
    #define HAVE_PK_CALLBACKS
    /* when you want to use a custom slot allocation for ATECC608A */
    /* unless your configuration is unusual, you can use default   */
    /* implementation.                                             */
    /* #define CUSTOM_SLOT_ALLOCATION                              */
#endif

/* rsa primitive specific definition */
/* Note: ESP32 RSA primitives disabled for IDF 6.x compatibility */
#if defined(WOLFSSL_ESPWROOM32SE)
    /* Define USE_FAST_MATH and SMALL_STACK                        */
    #define ESP32_USE_RSA_PRIMITIVE
    /* threshold for performance adjustment for hw primitive use   */
    /* X bits of G^X mod P greater than                            */
    #define EPS_RSA_EXPT_XBTIS           36
    /* X and Y of X * Y mod P greater than                         */
    #define ESP_RSA_MULM_BITS            2000
#endif

/* debug options */
// #define DEBUG_WOLFSSL
// #define WOLFSSL_DEBUG_TLS
// #define WOLFSSL_ESP32WROOM32_CRYPT_DEBUG
/* #define WOLFSSL_ATECC_DEBUG */

/* date/time                               */
/* NO_ASN_TIME disables certificate date validation */
/* This is needed because wolfSSL's time code has FreeRTOS include issues */
#define NO_ASN_TIME
#define XTIME time
#define XGMTIME(c, t) gmtime((c))

/* Hardware crypto is disabled globally via macros at the top of this file */
/* The new wolfSSL uses NO_ESP32_CRYPT, NO_WOLFSSL_ESP32_CRYPT_HASH, etc. */

/* adjust wait-timeout count if you see timeout in rsa hw acceleration */
#define ESP_RSA_TIMEOUT_CNT    0x249F00
