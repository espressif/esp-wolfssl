/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "esp_err.h"
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_ESP_TLS_CUSTOM_STACK

/**
 * @brief Indicates that the wolfSSL TLS backend is available in this build.
 *
 * Defined whenever this component is part of the build with the ESP-TLS custom
 * stack enabled (wolfSSL registers itself as that stack). Application code can
 * `#ifdef ESP_TLS_HAS_WOLFSSL` to feature-detect wolfSSL.
 *
 * This mirrors the ESP_TLS_HAS_WOLFSSL macro that ESP-IDF used to define in
 * esp_tls.h when wolfSSL was a built-in esp-tls backend
 * (CONFIG_ESP_TLS_USING_WOLFSSL). It is kept under the same name so code that
 * already feature-detects wolfSSL this way keeps working now that wolfSSL
 * lives in the esp-wolfssl component.
 */
#define ESP_TLS_HAS_WOLFSSL

/**
 * @brief Register wolfSSL as the custom TLS stack for ESP-TLS
 *
 * Calling this function is normally NOT needed: when this component is part
 * of the build, wolfSSL registers itself with ESP-TLS automatically during
 * system init (via ESP_SYSTEM_INIT_FN), before app_main() runs. This function
 * is provided for explicit/manual registration, e.g. to retry after the
 * automatic registration failed, or for code that wants a link-time
 * dependency on the wolfSSL backend.
 *
 * If called, it must be called before creating any TLS connections.
 *
 * @return
 *         - ESP_OK: wolfSSL stack registered successfully
 *         - ESP_ERR_INVALID_STATE: A stack is already registered
 *         - ESP_ERR_NOT_SUPPORTED: CONFIG_ESP_TLS_CUSTOM_STACK is not enabled
 */
esp_err_t esp_wolfssl_register_stack(void);

#endif /* CONFIG_ESP_TLS_CUSTOM_STACK */

#ifdef __cplusplus
}
#endif

