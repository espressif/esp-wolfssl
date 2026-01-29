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
 * @brief Register wolfSSL as the custom TLS stack for ESP-TLS
 *
 * This function registers wolfSSL as the TLS stack implementation for ESP-TLS.
 * It must be called before creating any TLS connections.
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

