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

#undef WOLFSSL_ESPIDF
#define WOLFSSL_ESPIDF
#define WOLFSSL_ESPWROOM32

#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048

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
/* when you want to use SHA384 */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define HAVE_ED25519

/* ALPN in wolfSSL is enabled by default, can be disabled with menuconfig */
#define HAVE_ALPN

#define HAVE_SNI

/* do not use wolfssl defined app_main function used to test esp-wolfssl */
#define NO_MAIN_DRIVER

/* you can disable folowing cipher suites by uncommenting following lines */
// #define NO_DSA
// #define NO_DH

/* These Flags are defined to make wolfssl not use some insecure cipher suites */
#define NO_MD4
#define NO_DES3
#define NO_RC4
#define NO_RABBIT
#define NO_OLD_TLS

/* Allows of x509 certs (for wolfssl_get_verify_result function) */
#define OPENSSL_EXTRA_X509_SMALL

/* Only requires the peer certificate to validate to a trusted certificate.
 * If peer sends additional certificates not in the chain they are allowed,
 * but not trusted */
#define WOLFSSL_ALT_CERT_CHAINS

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
#define WOLFSSL_SMALL_CERT_VERIFY

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
#if defined(WOLFSSL_ESPWROOM32) || defined(WOLFSSL_ESPWROOM32SE)
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
// #define WOLFSSL_ESP32WROOM32_CRYPT_DEBUG
/* #define WOLFSSL_ATECC_DEBUG */

/* date/time                               */
/* if it cannot adjust time in the device, */
/* enable macro below                      */
#define NO_ASN_TIME
#define XTIME time
#define XGMTIME(c, t) gmtime((c))

/* when you want not to use HW acceleration */
#if !defined(CONFIG_IDF_TARGET_ESP32)
    #define NO_ESP32WROOM32_CRYPT
#endif

/* Turn off the sha acceleration for esp32 */
#define NO_WOLFSSL_ESP32WROOM32_CRYPT_HASH
/* #define NO_WOLFSSL_ESP32WROOM32_CRYPT_AES */
/* #define NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI */

/* adjust wait-timeout count if you see timeout in rsa hw acceleration */
#define ESP_RSA_TIMEOUT_CNT    0x249F00
