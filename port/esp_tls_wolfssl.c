/*
 * SPDX-FileCopyrightText: 2019-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "esp_tls.h"
#include "esp_tls_custom_stack.h"
#include "esp_tls_errors.h"
#include "esp_tls_private.h"
#include "esp_tls_error_capture_internal.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_private/startup_internal.h"
#include "sdkconfig.h"

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"

/* wolfSSL-specific error codes (not in esp_tls_errors.h for custom stack).
 * Offset 0x100 is far above the mbedTLS codes in esp_tls_errors.h (<= 0x1D),
 * so these cannot collide with framework-defined codes. */
#define ESP_ERR_WOLFSSL_CTX_SETUP_FAILED             (ESP_ERR_ESP_TLS_BASE + 0x100)
#define ESP_ERR_WOLFSSL_SSL_SETUP_FAILED             (ESP_ERR_ESP_TLS_BASE + 0x101)
#define ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED     (ESP_ERR_ESP_TLS_BASE + 0x102)
#define ESP_ERR_WOLFSSL_SSL_SET_HOSTNAME_FAILED      (ESP_ERR_ESP_TLS_BASE + 0x103)
#define ESP_ERR_WOLFSSL_SSL_CONF_ALPN_PROTOCOLS_FAILED (ESP_ERR_ESP_TLS_BASE + 0x104)
#define ESP_ERR_WOLFSSL_SSL_HANDSHAKE_FAILED         (ESP_ERR_ESP_TLS_BASE + 0x105)

#if CONFIG_ESP_TLS_CUSTOM_STACK

static unsigned char *global_cacert = NULL;
static unsigned int global_cacert_pem_bytes = 0;
static const char *TAG = "esp-tls-wolfssl";

static esp_err_t set_client_config(const char *hostname, size_t hostlen, esp_tls_cfg_t *cfg, esp_tls_t *tls);

#if defined(CONFIG_ESP_TLS_PSK_VERIFICATION)
#include "freertos/semphr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
static SemaphoreHandle_t tls_conn_lock;
/* Set while a PSK connection holds tls_conn_lock. Lets esp_wolfssl_cleanup()
 * release the lock only when it was actually taken (error before/during the
 * handshake); non-PSK connections must not give a mutex they never took. */
static bool tls_conn_lock_held = false;
static inline unsigned int esp_wolfssl_psk_client_cb(WOLFSSL* ssl, const char* hint, char* identity,
        unsigned int id_max_len, unsigned char* key,unsigned int key_max_len);
static esp_err_t esp_wolfssl_set_cipher_list(WOLFSSL_CTX *ctx);
#ifdef WOLFSSL_TLS13
#define PSK_MAX_ID_LEN 128
#else
#define PSK_MAX_ID_LEN 64
#endif
#define PSK_MAX_KEY_LEN 64

static char psk_id_str[PSK_MAX_ID_LEN];
static uint8_t psk_key_array[PSK_MAX_KEY_LEN];
static uint8_t psk_key_max_len = 0;
#endif /* CONFIG_ESP_TLS_PSK_VERIFICATION */

static esp_err_t set_server_config(esp_tls_cfg_server_t *cfg, esp_tls_t *tls);

static void wolfssl_print_error_msg(int error)
{
#if (CONFIG_LOG_DEFAULT_LEVEL_DEBUG || CONFIG_LOG_DEFAULT_LEVEL_VERBOSE)
    /* wolfSSL_ERR_error_string() assumes the caller buffer holds at least
     * WOLFSSL_MAX_ERROR_SZ bytes (200 on ESP-IDF). A smaller (or shared
     * static) buffer would risk overflow / races between tasks. */
    char error_buf[WOLFSSL_MAX_ERROR_SZ];
    ESP_LOGE(TAG, "(%d) : %s", error, ERR_error_string(error, error_buf));
#endif
}

typedef enum x509_file_type {
    FILE_TYPE_CA_CERT = 0,
    FILE_TYPE_SELF_CERT,
    FILE_TYPE_SELF_KEY,
} x509_file_type_t;

static inline ssize_t esp_tls_convert_wolfssl_err_to_ssize(int wolfssl_error)
{
    switch (wolfssl_error) {
        case WOLFSSL_ERROR_WANT_READ:
            return ESP_TLS_ERR_SSL_WANT_READ;
        case WOLFSSL_ERROR_WANT_WRITE:
            return ESP_TLS_ERR_SSL_WANT_WRITE;
        default:
            return wolfssl_error>0 ? -wolfssl_error: wolfssl_error;
    }
}

/* Bounded search for a PEM header. The input may be raw DER with no NUL
 * terminator, so strstr() on it could read past the end of the buffer. */
static bool esp_wolfssl_buf_has_pem_header(const unsigned char *buf, unsigned int len, const char *header)
{
    size_t header_len = strlen(header);
    if (buf == NULL || len < header_len) {
        return false;
    }
    for (unsigned int i = 0; i + header_len <= len; i++) {
        if (memcmp(buf + i, header, header_len) == 0) {
            return true;
        }
    }
    return false;
}

static esp_err_t esp_load_wolfssl_verify_buffer(esp_tls_t *tls, const unsigned char *cert_buf, unsigned int cert_len, x509_file_type_t type, int *err_ret)
{
    int wolf_fileformat = WOLFSSL_FILETYPE_DEFAULT;
    if (type == FILE_TYPE_SELF_KEY) {
        if (esp_wolfssl_buf_has_pem_header(cert_buf, cert_len, "-----BEGIN ")) {
            wolf_fileformat = WOLFSSL_FILETYPE_PEM;
        } else {
            wolf_fileformat = WOLFSSL_FILETYPE_ASN1;
        }
        if ((*err_ret = wolfSSL_CTX_use_PrivateKey_buffer( (WOLFSSL_CTX *)tls->priv_ctx, cert_buf, cert_len, wolf_fileformat)) == WOLFSSL_SUCCESS) {
            return ESP_OK;
        }
        ESP_LOGE(TAG, "Failed to load private key, format: %d, error: %d", wolf_fileformat, *err_ret);
        return ESP_FAIL;
    } else {
        /* Check for PEM format by looking for PEM header */
        if (esp_wolfssl_buf_has_pem_header(cert_buf, cert_len, "-----BEGIN CERTIFICATE-----")) {
            wolf_fileformat = WOLFSSL_FILETYPE_PEM;
        } else {
            wolf_fileformat = WOLFSSL_FILETYPE_ASN1;
        }
        if (type == FILE_TYPE_SELF_CERT) {
            if ((*err_ret = wolfSSL_CTX_use_certificate_chain_buffer_format( (WOLFSSL_CTX *)tls->priv_ctx, cert_buf, cert_len, wolf_fileformat)) == WOLFSSL_SUCCESS) {
                return ESP_OK;
            }
            ESP_LOGE(TAG, "Failed to load certificate, format: %d, error: %d", wolf_fileformat, *err_ret);
            return ESP_FAIL;
        } else if (type == FILE_TYPE_CA_CERT) {
            int load_ret;
            const unsigned char *cert_to_load = cert_buf;
            long cert_len_to_use;
            unsigned char *null_term_buf = NULL;

            if (wolf_fileformat == WOLFSSL_FILETYPE_PEM) {
                bool has_null_term = (cert_len > 0 && cert_buf[cert_len - 1] == '\0');

                if (has_null_term) {
                    cert_to_load = cert_buf;
                    cert_len_to_use = (long)(cert_len - 1);
                } else {
                    null_term_buf = (unsigned char *)malloc(cert_len + 1);
                    if (!null_term_buf) {
                        ESP_LOGE(TAG, "Failed to allocate memory for certificate buffer");
                        *err_ret = WOLFSSL_FAILURE;
                        return ESP_ERR_NO_MEM;
                    }
                    memcpy(null_term_buf, cert_buf, cert_len);
                    null_term_buf[cert_len] = '\0';
                    cert_to_load = null_term_buf;
                    cert_len_to_use = (long)cert_len;
                }
            } else {
                cert_len_to_use = (long)cert_len;
            }

            load_ret = wolfSSL_CTX_load_verify_buffer( (WOLFSSL_CTX *)tls->priv_ctx, cert_to_load, cert_len_to_use, wolf_fileformat);

            if (null_term_buf) {
                free(null_term_buf);
            }

            *err_ret = load_ret;
            if (load_ret == WOLFSSL_SUCCESS) {
                return ESP_OK;
            }
            ESP_LOGE(TAG, "Failed to load CA certificate, format: %d, error: %d", wolf_fileformat, load_ret);
            wolfssl_print_error_msg(load_ret);
            return ESP_FAIL;
        } else {
            return ESP_FAIL;
        }
    }
}

static void esp_wolfssl_cleanup(esp_tls_t *tls);

static esp_err_t esp_wolfssl_create_ssl_handle(void *user_ctx, const char *hostname, size_t hostlen, const void *cfg, esp_tls_t *tls, void *server_params)
{
    assert(cfg != NULL);
    assert(tls != NULL);

    esp_err_t esp_ret = ESP_FAIL;
    int ret;

    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "Init wolfSSL failed: 0x%04X", ret);
        wolfssl_print_error_msg(ret);
        goto exit;
    }

    if (tls->role == ESP_TLS_CLIENT) {
        esp_ret = set_client_config(hostname, hostlen, (esp_tls_cfg_t *)cfg, tls);
        if (esp_ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set client configurations, [0x%04X] (%s)", esp_ret, esp_err_to_name(esp_ret));
            goto exit;
        }
    } else if (tls->role == ESP_TLS_SERVER) {
        esp_ret = set_server_config((esp_tls_cfg_server_t *) cfg, tls);
        if (esp_ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set server configurations, [0x%04X] (%s)", esp_ret, esp_err_to_name(esp_ret));
            goto exit;
        }
    }
    else {
        ESP_LOGE(TAG, "tls->role is not valid");
        goto exit;
    }

    return ESP_OK;
exit:
    if (tls) {
        esp_wolfssl_cleanup(tls);
    }
    return esp_ret;
}

static esp_err_t set_client_config(const char *hostname, size_t hostlen, esp_tls_cfg_t *cfg, esp_tls_t *tls)
{
    int ret = WOLFSSL_FAILURE;

#ifdef WOLFSSL_TLS13
    tls->priv_ctx = (void *)wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
    tls->priv_ctx = (void *)wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif

    if (!tls->priv_ctx) {
        ESP_LOGE(TAG, "Set wolfSSL ctx failed");
        return ESP_ERR_WOLFSSL_CTX_SETUP_FAILED;
    }

    if (cfg->crt_bundle_attach != NULL) {
        /* The IDF certificate bundle is mbedTLS-specific (mbedtls parsing
         * callbacks + bundle format), so it cannot be attached to wolfSSL. */
        ESP_LOGE(TAG, "crt_bundle_attach is not supported by the wolfSSL backend; "
                      "use cacert_buf or esp_tls_set_global_ca_store() instead");
        return ESP_ERR_NOT_SUPPORTED;
    }

    if (cfg->use_global_ca_store == true) {
        if (global_cacert == NULL) {
            ESP_LOGE(TAG, "global_ca_store requested but not set; call esp_tls_set_global_ca_store() first");
            return ESP_ERR_INVALID_STATE;
        }
        if ((esp_load_wolfssl_verify_buffer(tls, global_cacert, global_cacert_pem_bytes, FILE_TYPE_CA_CERT, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load CA certificate from global store, error: %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
        wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)tls->priv_ctx, WOLFSSL_VERIFY_PEER, NULL);
    } else if (cfg->cacert_buf != NULL) {
        if ((esp_load_wolfssl_verify_buffer(tls, cfg->cacert_buf, cfg->cacert_bytes, FILE_TYPE_CA_CERT, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load CA certificate, error: %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
        wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)tls->priv_ctx, WOLFSSL_VERIFY_PEER, NULL);
#if defined(CONFIG_ESP_TLS_PSK_VERIFICATION)
    } else if (cfg->psk_hint_key) {
        if(cfg->psk_hint_key->key == NULL || cfg->psk_hint_key->hint == NULL || cfg->psk_hint_key->key_size <= 0) {
            ESP_LOGE(TAG, "Please provide appropriate key, keysize and hint to use PSK");
            return ESP_FAIL;
        }
        if (tls_conn_lock == NULL) {
            /* Mutex creation in the constructor failed (out of memory at
             * boot); taking a NULL semaphore would assert inside FreeRTOS. */
            ESP_LOGE(TAG, "TLS connection lock was never created, cannot use PSK");
            return ESP_ERR_INVALID_STATE;
        }
        if ((xSemaphoreTake(tls_conn_lock, 1000/portTICK_PERIOD_MS) != pdTRUE)) {
            ESP_LOGE(TAG, "Failed to acquire TLS connection lock");
            return ESP_ERR_TIMEOUT;
        }
        tls_conn_lock_held = true;
        /* hint must be strictly shorter than PSK_MAX_ID_LEN so that
         * psk_id_str stays NUL-terminated */
        if((cfg->psk_hint_key->key_size > PSK_MAX_KEY_LEN) || (strlen(cfg->psk_hint_key->hint) >= PSK_MAX_ID_LEN)) {
            ESP_LOGE(TAG, "PSK key length must be <= %d and identity hint length must be < %d", PSK_MAX_KEY_LEN, PSK_MAX_ID_LEN);
            return ESP_ERR_INVALID_ARG;
        }
        psk_key_max_len = cfg->psk_hint_key->key_size;
        memset(psk_key_array, 0, sizeof(psk_key_array));
        memset(psk_id_str, 0, sizeof(psk_id_str));
        memcpy(psk_key_array, cfg->psk_hint_key->key, psk_key_max_len);
        memcpy(psk_id_str, cfg->psk_hint_key->hint, strlen(cfg->psk_hint_key->hint));
        wolfSSL_CTX_set_psk_client_callback( (WOLFSSL_CTX *)tls->priv_ctx, esp_wolfssl_psk_client_cb);
        if(esp_wolfssl_set_cipher_list( (WOLFSSL_CTX *)tls->priv_ctx) != ESP_OK) {
            ESP_LOGE(TAG, "error in setting cipher-list");
            return ESP_FAIL;
        }
#endif /* CONFIG_ESP_TLS_PSK_VERIFICATION */
    } else {
#ifdef CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY
        wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)tls->priv_ctx, WOLFSSL_VERIFY_NONE, NULL);
#else
        ESP_LOGE(TAG, "No server verification option set in esp_tls_cfg_t structure. Check esp_tls API reference");
        return ESP_ERR_WOLFSSL_SSL_SETUP_FAILED;
#endif
    }

    if (cfg->clientcert_buf != NULL && cfg->clientkey_buf != NULL) {
        if ((esp_load_wolfssl_verify_buffer(tls,cfg->clientcert_buf, cfg->clientcert_bytes, FILE_TYPE_SELF_CERT, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Error in loading certificate verify buffer, returned %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
        if ((esp_load_wolfssl_verify_buffer(tls,cfg->clientkey_buf, cfg->clientkey_bytes, FILE_TYPE_SELF_KEY, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Error in loading private key verify buffer, returned %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
    } else if (cfg->clientcert_buf != NULL || cfg->clientkey_buf != NULL) {
        ESP_LOGE(TAG, "You have to provide both clientcert_buf and clientkey_buf for mutual authentication");
        return ESP_FAIL;
    }

    tls->priv_ssl =(void *)wolfSSL_new( (WOLFSSL_CTX *)tls->priv_ctx);
    if (!tls->priv_ssl) {
        ESP_LOGE(TAG, "Create wolfSSL failed");
        return ESP_ERR_WOLFSSL_SSL_SETUP_FAILED;
    }

    if (!cfg->skip_common_name) {
        char *use_host = NULL;
        if (cfg->common_name != NULL) {
            use_host = strdup(cfg->common_name);
        } else {
            use_host = strndup(hostname, hostlen);
        }
        if (use_host == NULL) {
            return ESP_ERR_NO_MEM;
        }
        if ((ret = (wolfSSL_check_domain_name( (WOLFSSL *)tls->priv_ssl, use_host))) != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "wolfSSL_check_domain_name returned %d", ret);
            free(use_host);
            return ESP_ERR_WOLFSSL_SSL_SET_HOSTNAME_FAILED;
        }
        /* Set SNI on the SSL object (already created above) rather than on the
         * CTX: CTX-level extensions are intended for SSL objects created
         * afterwards. */
        if ((ret = wolfSSL_UseSNI(tls->priv_ssl, WOLFSSL_SNI_HOST_NAME, use_host, strlen(use_host))) != WOLFSSL_SUCCESS) {
            ESP_LOGE(TAG, "wolfSSL_UseSNI failed, returned %d", ret);
            free(use_host);
            return ESP_ERR_WOLFSSL_SSL_SET_HOSTNAME_FAILED;
        }
        free(use_host);
    } else {
        /* skip_common_name only disables hostname *verification* of the peer
         * certificate; SNI must still be sent so the server presents the
         * certificate for the requested host (e.g. virtual hosts / CDNs).
         * See esp-idf PR #14684. */
        if (hostname != NULL && hostlen > 0) {
            if ((ret = wolfSSL_UseSNI(tls->priv_ssl, WOLFSSL_SNI_HOST_NAME, hostname, hostlen)) != WOLFSSL_SUCCESS) {
                ESP_LOGE(TAG, "wolfSSL_UseSNI failed, returned %d", ret);
                return ESP_ERR_WOLFSSL_SSL_SET_HOSTNAME_FAILED;
            }
        }
    }

    if (cfg->alpn_protos) {
#ifdef CONFIG_WOLFSSL_HAVE_ALPN
        char **alpn_list = (char **)cfg->alpn_protos;
        for (; *alpn_list != NULL; alpn_list ++) {
            if ((ret = wolfSSL_UseALPN( (WOLFSSL *)tls->priv_ssl, *alpn_list, strlen(*alpn_list), WOLFSSL_ALPN_FAILED_ON_MISMATCH)) != WOLFSSL_SUCCESS) {
                ESP_LOGE(TAG, "ALPN configuration failed, error: %d", ret);
                wolfssl_print_error_msg(ret);
                return ESP_ERR_WOLFSSL_SSL_CONF_ALPN_PROTOCOLS_FAILED;
            }
        }
#else
        ESP_LOGE(TAG, "ALPN not enabled in configuration");
        return ESP_FAIL;
#endif /* CONFIG_WOLFSSL_HAVE_ALPN */
    }

#ifdef CONFIG_WOLFSSL_HAVE_OCSP
    int ocsp_options = 0;
#ifdef ESP_TLS_OCSP_CHECKALL
    ocsp_options |= WOLFSSL_OCSP_CHECKALL;
#endif
    if ((ret = wolfSSL_CTX_EnableOCSP((WOLFSSL_CTX *)tls->priv_ctx, ocsp_options)) != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "wolfSSL_CTX_EnableOCSP failed, returned %d", ret);
        return ESP_ERR_WOLFSSL_CTX_SETUP_FAILED;
    }
    if ((ret = wolfSSL_CTX_EnableOCSPStapling((WOLFSSL_CTX *)tls->priv_ctx )) != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "wolfSSL_CTX_EnableOCSPStapling failed, returned %d", ret);
        return ESP_ERR_WOLFSSL_CTX_SETUP_FAILED;
    }
    if ((ret = wolfSSL_UseOCSPStapling((WOLFSSL *)tls->priv_ssl, WOLFSSL_CSR_OCSP, WOLFSSL_CSR_OCSP_USE_NONCE)) != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "wolfSSL_UseOCSPStapling failed, returned %d", ret);
        return ESP_ERR_WOLFSSL_SSL_SETUP_FAILED;
    }
#endif /* CONFIG_WOLFSSL_HAVE_OCSP */

    wolfSSL_set_fd((WOLFSSL *)tls->priv_ssl, tls->sockfd);
    return ESP_OK;
}

static esp_err_t set_server_config(esp_tls_cfg_server_t *cfg, esp_tls_t *tls)
{
    int ret = WOLFSSL_FAILURE;

#ifdef WOLFSSL_TLS13
    tls->priv_ctx = (void *)wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#else
    tls->priv_ctx = (void *)wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif

    if (!tls->priv_ctx) {
        ESP_LOGE(TAG, "Set wolfSSL ctx failed");
        return ESP_ERR_WOLFSSL_CTX_SETUP_FAILED;
    }

    if (cfg->cacert_buf != NULL) {
        if ((esp_load_wolfssl_verify_buffer(tls,cfg->cacert_buf, cfg->cacert_bytes, FILE_TYPE_CA_CERT, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load CA certificate, error: %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
        wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)tls->priv_ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)tls->priv_ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    if (cfg->servercert_buf != NULL && cfg->serverkey_buf != NULL) {
        if ((esp_load_wolfssl_verify_buffer(tls,cfg->servercert_buf, cfg->servercert_bytes, FILE_TYPE_SELF_CERT, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Error in loading certificate verify buffer, returned %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
        if ((esp_load_wolfssl_verify_buffer(tls,cfg->serverkey_buf, cfg->serverkey_bytes, FILE_TYPE_SELF_KEY, &ret)) != ESP_OK) {
            ESP_LOGE(TAG, "Error in loading private key verify buffer, returned %d", ret);
            wolfssl_print_error_msg(ret);
            return ESP_ERR_WOLFSSL_CERT_VERIFY_SETUP_FAILED;
        }
    } else {
        ESP_LOGE(TAG, "You have to provide both servercert_buf and serverkey_buf for https_server");
        return ESP_FAIL;
    }

    tls->priv_ssl =(void *)wolfSSL_new( (WOLFSSL_CTX *)tls->priv_ctx);
    if (!tls->priv_ssl) {
        ESP_LOGE(TAG, "Create wolfSSL failed");
        return ESP_ERR_WOLFSSL_SSL_SETUP_FAILED;
    }

    wolfSSL_set_fd((WOLFSSL *)tls->priv_ssl, tls->sockfd);
    return ESP_OK;
}

static int esp_wolfssl_handshake(void *user_ctx, esp_tls_t *tls, const esp_tls_cfg_t *cfg)
{
    int ret;
    ret = wolfSSL_connect( (WOLFSSL *)tls->priv_ssl);
    if (ret == WOLFSSL_SUCCESS) {
        tls->conn_state = ESP_TLS_DONE;
        return 1;
    } else {
        int err = wolfSSL_get_error( (WOLFSSL *)tls->priv_ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            ESP_LOGE(TAG, "wolfSSL_connect failed, error: %d", err);
            wolfssl_print_error_msg(err);
            /* Record the failure in the esp-tls error handle so that
             * esp_tls_get_and_clear_last_error() reports it to applications
             * (mirrors what the mbedTLS backend does). */
            ESP_INT_EVENT_TRACKER_CAPTURE(tls->error_handle, ESP_TLS_ERR_TYPE_CUSTOM_STACK, -err);
            ESP_INT_EVENT_TRACKER_CAPTURE(tls->error_handle, ESP_TLS_ERR_TYPE_ESP, ESP_ERR_WOLFSSL_SSL_HANDSHAKE_FAILED);

            if (cfg->crt_bundle_attach != NULL || cfg->cacert_buf != NULL || cfg->use_global_ca_store == true) {
                /* wolfSSL_get_verify_result() returns the native WOLFSSL_X509_V_*
                 * codes, so match against those (the OpenSSL-compat X509_V_*
                 * macros have different values for some entries, e.g.
                 * INVALID_CA, which would make those cases unreachable). */
                long flags = wolfSSL_get_verify_result( (WOLFSSL *)tls->priv_ssl);
                if (flags != WOLFSSL_X509_V_OK) {
                    ESP_INT_EVENT_TRACKER_CAPTURE(tls->error_handle, ESP_TLS_ERR_TYPE_CUSTOM_STACK_CERT_FLAGS, (int)flags);
                    switch (flags) {
                        case WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                            ESP_LOGE(TAG, "Certificate issuer not found in CA store");
                            break;
                        case WOLFSSL_X509_V_ERR_INVALID_CA:
                            ESP_LOGE(TAG, "Invalid CA certificate");
                            break;
                        case WOLFSSL_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                            ESP_LOGE(TAG, "Unable to verify certificate signature");
                            break;
                        case WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED:
                            ESP_LOGE(TAG, "Certificate has expired");
                            break;
                        case WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID:
                            ESP_LOGE(TAG, "Certificate not yet valid");
                            break;
                        default:
                            ESP_LOGE(TAG, "Certificate verification failed, error code: %ld", flags);
                            break;
                    }
                }
            }
            tls->conn_state = ESP_TLS_FAIL;
            return -1;
        }
        return 0;
    }
}

static ssize_t esp_wolfssl_read(void *user_ctx, esp_tls_t *tls, char *data, size_t datalen)
{
    ssize_t ret = wolfSSL_read( (WOLFSSL *)tls->priv_ssl, (unsigned char *)data, datalen);
    if (ret < 0) {
        int err = wolfSSL_get_error( (WOLFSSL *)tls->priv_ssl, ret);
        /* peer sent close notify */
        if (err == WOLFSSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            ESP_LOGE(TAG, "wolfSSL_read failed, error: %d", err);
            wolfssl_print_error_msg(err);
            ESP_INT_EVENT_TRACKER_CAPTURE(tls->error_handle, ESP_TLS_ERR_TYPE_CUSTOM_STACK, -err);
        }
        /* Convert the wolfSSL_get_error() code, NOT the wolfSSL_read() return
         * value (which is just -1 / WOLFSSL_FATAL_ERROR), so that WANT_READ /
         * WANT_WRITE are propagated to non-blocking callers correctly. */
        return esp_tls_convert_wolfssl_err_to_ssize(err);
    }
    return ret;
}

static ssize_t esp_wolfssl_write(void *user_ctx, esp_tls_t *tls, const char *data, size_t datalen)
{
    ssize_t ret = wolfSSL_write( (WOLFSSL *)tls->priv_ssl, (unsigned char *) data, datalen);
    if (ret <= 0) {
        int err = wolfSSL_get_error( (WOLFSSL *)tls->priv_ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            ESP_LOGE(TAG, "wolfSSL_write failed, error: %d", err);
            wolfssl_print_error_msg(err);
            ESP_INT_EVENT_TRACKER_CAPTURE(tls->error_handle, ESP_TLS_ERR_TYPE_CUSTOM_STACK, -err);
        }
        return esp_tls_convert_wolfssl_err_to_ssize(err);
    }
    return ret;
}

static void esp_wolfssl_conn_delete(void *user_ctx, esp_tls_t *tls)
{
    if (tls != NULL) {
        esp_wolfssl_cleanup(tls);
    }
}

static void esp_wolfssl_cleanup(esp_tls_t *tls)
{
    if (!tls) {
        return;
    }
#if defined(CONFIG_ESP_TLS_PSK_VERIFICATION)
    if (tls_conn_lock_held) {
        tls_conn_lock_held = false;
        xSemaphoreGive(tls_conn_lock);
    }
#endif /* CONFIG_ESP_TLS_PSK_VERIFICATION */
    if (tls->priv_ssl) {
        wolfSSL_shutdown( (WOLFSSL *)tls->priv_ssl);
        wolfSSL_free( (WOLFSSL *)tls->priv_ssl);
        tls->priv_ssl = NULL;
    }
    if (tls->priv_ctx) {
        wolfSSL_CTX_free( (WOLFSSL_CTX *)tls->priv_ctx);
        tls->priv_ctx = NULL;
    }
    /* Do NOT call wolfSSL_Cleanup() here. It tears down process-global wolfSSL
     * state (wolfCrypt mutexes, RNG, session cache). Calling it per connection
     * crashes any *other* wolfSSL connection that is concurrently open (e.g. a
     * second esp_tls client, or a server handling multiple clients) the moment
     * it next locks one of those now-freed global mutexes. wolfSSL_Init() is
     * reference-counted and safe to call per connection (see
     * esp_wolfssl_create_ssl_handle); the matching global teardown is simply
     * left to process exit, which is the norm for a long-running TLS backend. */
}

static void esp_wolfssl_net_init(void *user_ctx, esp_tls_t *tls)
{
    (void)user_ctx;
    (void)tls;
}

static void *esp_wolfssl_get_ssl_context(void *user_ctx, esp_tls_t *tls)
{
    (void)user_ctx;
    if (tls == NULL) {
        return NULL;
    }
    return (void*)tls->priv_ssl;
}

static ssize_t esp_wolfssl_get_bytes_avail(void *user_ctx, esp_tls_t *tls)
{
    (void)user_ctx;
    if (!tls) {
        return ESP_FAIL;
    }
    return wolfSSL_pending( (WOLFSSL *)tls->priv_ssl);
}

static esp_err_t esp_wolfssl_init_global_ca_store(void *user_ctx)
{
    return ESP_OK;
}

static void esp_wolfssl_free_global_ca_store(void *user_ctx);

static esp_err_t esp_wolfssl_set_global_ca_store(void *user_ctx, const unsigned char *cacert_pem_buf, const unsigned int cacert_pem_bytes)
{
    if (cacert_pem_buf == NULL) {
        ESP_LOGE(TAG, "cacert_pem_buf is null");
        return ESP_ERR_INVALID_ARG;
    }
    if (global_cacert != NULL) {
        esp_wolfssl_free_global_ca_store(user_ctx);
    }

    /* Plain malloc+memcpy rather than strndup: strndup() stops at the first
     * NUL byte, which would silently truncate DER (binary) certificates. The
     * extra NUL terminator keeps PEM parsing safe. */
    global_cacert = (unsigned char *)malloc(cacert_pem_bytes + 1);
    if (!global_cacert) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(global_cacert, cacert_pem_buf, cacert_pem_bytes);
    global_cacert[cacert_pem_bytes] = '\0';
    global_cacert_pem_bytes  = cacert_pem_bytes;

    return ESP_OK;
}

static void *esp_wolfssl_get_global_ca_store(void *user_ctx)
{
    return global_cacert;
}

static void esp_wolfssl_free_global_ca_store(void *user_ctx)
{
    if (global_cacert) {
        free(global_cacert);
        global_cacert = NULL;
        global_cacert_pem_bytes = 0;
    }
}

static const int *esp_wolfssl_get_ciphersuites_list(void *user_ctx)
{
    return NULL;
}

static int esp_wolfssl_server_session_create(void *user_ctx, esp_tls_cfg_server_t *cfg, int sockfd, esp_tls_t *tls)
{
    if (tls == NULL || cfg == NULL) {
        return -1;
    }
    tls->role = ESP_TLS_SERVER;
    tls->sockfd = sockfd;
    esp_tls_server_params_t server_params = {};
    server_params.set_server_cfg = &set_server_config;
    esp_err_t esp_ret = esp_wolfssl_create_ssl_handle(user_ctx, NULL, 0, cfg, tls, &server_params);
    if (esp_ret != ESP_OK) {
        ESP_LOGE(TAG, "create_ssl_handle failed, [0x%04X] (%s)", esp_ret, esp_err_to_name(esp_ret));
        tls->conn_state = ESP_TLS_FAIL;
        return -1;
    }
    /* The esp-tls framework only wires tls->read/tls->write on the CLIENT path
     * (esp_tls_conn_new_sync). For server sessions the backend must set them
     * itself, otherwise esp_tls_conn_read()/esp_tls_conn_write() see a NULL
     * pointer and return -1. (The mbedTLS backend does the same in its own
     * server_session_init.) These are the framework's custom-stack wrappers,
     * which dispatch into esp_wolfssl_read()/esp_wolfssl_write(). */
    tls->read = esp_tls_custom_stack_read;
    tls->write = esp_tls_custom_stack_write;
    int ret;
    while ((ret = wolfSSL_accept((WOLFSSL *)tls->priv_ssl)) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error((WOLFSSL *)tls->priv_ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
            ESP_LOGE(TAG, "wolfSSL_accept returned %d, error code: %d", ret, err);
            wolfssl_print_error_msg(err);
            tls->conn_state = ESP_TLS_FAIL;
            return -1;
        }
    }
    return 0;
}

static void esp_wolfssl_server_session_delete(void *user_ctx, esp_tls_t *tls)
{
    (void)user_ctx;
    if (tls != NULL) {
        esp_wolfssl_cleanup(tls);
    }
}

#if defined(CONFIG_ESP_TLS_PSK_VERIFICATION)
static esp_err_t esp_wolfssl_set_cipher_list(WOLFSSL_CTX *ctx)
{
    const char *defaultCipherList;
    int ret;
#if defined(HAVE_AESGCM) && !defined(NO_DH)
#ifdef WOLFSSL_TLS13
    defaultCipherList = "DHE-PSK-AES128-GCM-SHA256:"
                                    "TLS13-AES128-GCM-SHA256";
#else
    defaultCipherList = "DHE-PSK-AES128-GCM-SHA256";
#endif
#elif defined(HAVE_AESGCM) && defined(HAVE_ECC)
    /* wolfSSL's ESP-IDF defaults define NO_DH, so the DHE-PSK suite above is
     * unavailable in the default build. ECDHE-PSK (RFC 8442) provides forward
     * secrecy without DH and is built whenever ECC + AES-GCM + PSK are on.
     * Without this branch the fallback would be a static PSK suite, which is
     * not compiled in (WOLFSSL_STATIC_PSK is intentionally disabled), leaving
     * PSK connections with no usable cipher suite at all. */
#ifdef WOLFSSL_TLS13
    defaultCipherList = "ECDHE-PSK-AES128-GCM-SHA256:"
                                    "TLS13-AES128-GCM-SHA256";
#else
    defaultCipherList = "ECDHE-PSK-AES128-GCM-SHA256";
#endif
#elif defined(HAVE_NULL_CIPHER)
    defaultCipherList = "PSK-NULL-SHA256";
#else
    defaultCipherList = "PSK-AES128-CBC-SHA256";
#endif
    if ((ret = wolfSSL_CTX_set_cipher_list(ctx,defaultCipherList)) != WOLFSSL_SUCCESS) {
        /* Do not free ctx here: the caller still holds it in tls->priv_ctx and
         * esp_wolfssl_cleanup() frees it on the error path. Freeing it here as
         * well would be a double free. */
        ESP_LOGE(TAG, "Failed to set cipher list, error: %d", ret);
        wolfssl_print_error_msg(ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void __attribute__((constructor))
espt_tls_wolfssl_init_conn_lock (void)
{
    if ((tls_conn_lock = xSemaphoreCreateMutex()) == NULL) {
        ESP_EARLY_LOGE(TAG, "mutex for tls psk connection could not be created");
    }
}

static inline unsigned int esp_wolfssl_psk_client_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;

    unsigned int id_len = strlen(psk_id_str);
    if (id_len >= id_max_len || psk_key_max_len > key_max_len) {
        ESP_LOGE(TAG, "PSK identity or key does not fit in the wolfSSL buffers");
        return 0;
    }
    memcpy(identity, psk_id_str, id_len + 1);
    memcpy(key, psk_key_array, psk_key_max_len);
    tls_conn_lock_held = false;
    xSemaphoreGive(tls_conn_lock);
    return psk_key_max_len;
}
#endif /* CONFIG_ESP_TLS_PSK_VERIFICATION */

static const esp_tls_stack_ops_t esp_wolfssl_stack_ops = {
    .version = ESP_TLS_STACK_OPS_VERSION,
    .create_ssl_handle = esp_wolfssl_create_ssl_handle,
    .handshake = esp_wolfssl_handshake,
    .read = esp_wolfssl_read,
    .write = esp_wolfssl_write,
    .conn_delete = esp_wolfssl_conn_delete,
    .net_init = esp_wolfssl_net_init,
    .get_ssl_context = esp_wolfssl_get_ssl_context,
    .get_bytes_avail = esp_wolfssl_get_bytes_avail,
    .init_global_ca_store = esp_wolfssl_init_global_ca_store,
    .set_global_ca_store = esp_wolfssl_set_global_ca_store,
    .get_global_ca_store = esp_wolfssl_get_global_ca_store,
    .free_global_ca_store = esp_wolfssl_free_global_ca_store,
    .get_ciphersuites_list = esp_wolfssl_get_ciphersuites_list,
    .server_session_create = esp_wolfssl_server_session_create,
    .server_session_delete = esp_wolfssl_server_session_delete,
};

esp_err_t esp_wolfssl_register_stack(void)
{
    return esp_tls_register_stack(&esp_wolfssl_stack_ops, NULL);
}

/* Auto-register the wolfSSL stack with esp-tls during system init.
 * This runs before app_main(), so applications can use esp-tls APIs without
 * having to call esp_wolfssl_register_stack() explicitly. The SECONDARY
 * stage is the one intended for component-level init functions (the CORE
 * stage is reserved for ESP-IDF internals and its entries are validated
 * against an internal list in IDF CI). esp_tls_register_stack() only stores
 * a pointer, so it has no ordering requirements beyond running before
 * app_main(). */
ESP_SYSTEM_INIT_FN(esp_wolfssl_stack_auto_register, SECONDARY, BIT(0), 200)
{
    esp_err_t ret = esp_tls_register_stack(&esp_wolfssl_stack_ops, NULL);
    if (ret != ESP_OK) {
        ESP_EARLY_LOGE(TAG, "Failed to auto-register wolfSSL stack: %s", esp_err_to_name(ret));
    }
    return ret;
}

#endif /* CONFIG_ESP_TLS_CUSTOM_STACK */
