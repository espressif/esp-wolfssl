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

/* wolfSSL's FREERTOS code path (settings.h) includes <freertos/FreeRTOS.h>
 * only when PLATFORMIO is defined and the bare "FreeRTOS.h" otherwise. Only
 * the former is on the ESP-IDF include path, so define PLATFORMIO to steer
 * wolfSSL headers to the IDF-style FreeRTOS include paths. */
#ifndef PLATFORMIO
#define PLATFORMIO
#endif

#define BENCH_EMBEDDED

/* ===== RSA 4096-bit certificate support ===== */
/* Modern CA roots use 4096-bit RSA keys (e.g. ISRG Root X1, used by
 * Let's Encrypt). FP_MAX_BITS must be at least 2x the largest key size. */
#define FP_MAX_BITS 8192
/* Allow unknown/undecoded X509v3 extensions - needed for modern CA certs */
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

/* misc.c is compiled as a standalone translation unit (it is NOT excluded in
 * CMakeLists.txt), so NO_INLINE must be defined: without it every other file
 * inlines the misc functions and the standalone misc.o would produce
 * duplicate definitions. */
#define NO_INLINE

/* you can disable following cipher suites by uncommenting following lines */
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
 * If the peer sends additional certificates not in the chain they are
 * allowed, but not trusted. Needed so that verification succeeds when the
 * application only provides the root CA while the server sends
 * leaf -> intermediate -> (cross-signed) root. */
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
/* Certificate date (notBefore/notAfter) validation is enabled and uses the
 * system clock via time()/gmtime(). The system time must be set (e.g. via
 * SNTP) before TLS connections are made, otherwise certificate validation
 * will fail with ASN_BEFORE_DATE_E / ASN_AFTER_DATE_E.
 * If the device cannot maintain wall-clock time, define NO_ASN_TIME to skip
 * date validation (NOT recommended: expired or not-yet-valid certificates
 * would be accepted). */
#define XTIME time
#define XGMTIME(c, t) gmtime((c))

/* Hardware crypto is disabled globally via macros at the top of this file */
/* The new wolfSSL uses NO_ESP32_CRYPT, NO_WOLFSSL_ESP32_CRYPT_HASH, etc. */

/* adjust wait-timeout count if you see timeout in rsa hw acceleration */
#define ESP_RSA_TIMEOUT_CNT    0x249F00

/* ===== Post-Quantum Cryptography (PQC) Support ===== */
/* Opt-in via menuconfig -> Component config -> wolfSSL -> WOLFSSL_HAVE_PQC.
 * These algorithms use native wolfSSL implementations (no external library
 * needed). Note that once enabled, the certificate parsing code references
 * the PQC routines, so they are linked in (~30 kB flash) even if the
 * application never uses a PQC algorithm — hence the opt-in.
 *
 * Note: PQC algorithms have larger memory requirements than classical crypto.
 * Consider using WOLFSSL_SMALL_STACK and increasing task stack sizes if needed.
 */
#ifdef CONFIG_WOLFSSL_HAVE_PQC

/* SHA-3 and SHAKE (required for PQC algorithms) */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* ML-KEM (formerly Kyber) - Post-Quantum Key Encapsulation Mechanism
 * Used for key exchange in hybrid TLS, standalone key encapsulation, etc.
 * WOLFSSL_HAVE_MLKEM enables ML-KEM, WOLFSSL_WC_MLKEM uses native implementation.
 * Security levels:
 *   - KYBER512:  NIST Level 1 (128-bit security)
 *   - KYBER768:  NIST Level 3 (192-bit security)
 *   - KYBER1024: NIST Level 5 (256-bit security)
 */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_KYBER512
#define WOLFSSL_KYBER768
#define WOLFSSL_KYBER1024

/* ML-DSA (formerly Dilithium) - Post-Quantum Digital Signature Algorithm
 * Used for signing/verification in certificates, authentication, etc.
 * HAVE_DILITHIUM enables Dilithium support, WOLFSSL_WC_DILITHIUM uses native impl.
 * Security levels:
 *   - LEVEL2: NIST Level 2 (128-bit security, smaller signatures)
 *   - LEVEL3: NIST Level 3 (192-bit security)
 *   - LEVEL5: NIST Level 5 (256-bit security, larger signatures)
 */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_LEVEL2
#define WOLFSSL_DILITHIUM_LEVEL3
#define WOLFSSL_DILITHIUM_LEVEL5

/* Optional: Enable verify-only mode to reduce code size if you only need
 * to verify signatures (not generate them). Useful for embedded devices
 * that only verify server certificates with PQC signatures.
 */
/* #define WOLFSSL_DILITHIUM_VERIFY_ONLY */

/* Optional: Other PQC signature algorithms (larger code/memory footprint)
 * Uncomment if needed:
 */
/* #define HAVE_FALCON */
/* #define HAVE_SPHINCS */

#endif /* CONFIG_WOLFSSL_HAVE_PQC */
