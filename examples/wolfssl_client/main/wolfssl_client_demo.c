/* wolfSSL example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"

#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include <sys/socket.h>
#include <netdb.h>
#include "lwip/apps/sntp.h"
#include "protocol_examples_common.h"
#include <wolfssl/wolfcrypt/settings.h>
#include "wolfssl/ssl.h"
#include "esp_netif.h"

#if CONFIG_EXAMPLE_SERVER_CERT_VERIFY
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");
#endif

/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "api.github.com"
#define WEB_PORT (443)
#define WEB_URL "https://api.github.com/zen"

#define REQUEST "GET " WEB_URL " HTTP/1.0\r\n" \
                "Host: "WEB_SERVER"\r\n" \
                "User-Agent: esp-idf/1.0 esp32\r\n" \
                "\r\n"
/*
 * NOTE: To turn on debug logs for wolfSSL component and this example, uncomment
 * #define DEBUF_WOLFSSL in file components/wolfssl/port/user_settings.h
 */

#define WOLFSSL_DEMO_THREAD_NAME        "wolfssl_client"
#ifdef DEBUG_WOLFSSL
#define WOLFSSL_DEMO_THREAD_STACK_WORDS 8192
#else
#define WOLFSSL_DEMO_THREAD_STACK_WORDS 4096
#endif /* DEBUG_WOLFSSL */
#define WOLFSSL_DEMO_THREAD_PRORIOTY    6
#define WOLFSSL_DEMO_SNTP_SERVERS       "time.google.com"
#define WOLFSSL_CIPHER_LIST_MAX_SIZE    2048

static const char *TAG = "wolfssl_client";

const char send_data[] = REQUEST;
const int32_t send_bytes = sizeof(send_data);
char recv_data[1024] = {0};

#ifdef DEBUG_WOLFSSL
static void show_ciphers(void)
{
    char *ciphers = calloc(WOLFSSL_CIPHER_LIST_MAX_SIZE, sizeof(char));
    if (ciphers != NULL) {
        int ret = wolfSSL_get_ciphers(ciphers, WOLFSSL_CIPHER_LIST_MAX_SIZE);
        if (ret == WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "Available Ciphers: \n%s", ciphers);
        } else {
            ESP_LOGE(TAG, "Failed to get cipher list!");
        }
        free(ciphers);
    }
}
#endif

static void get_time()
{
    struct timeval now;
    int sntp_retry_cnt = 0;
    int sntp_retry_time = 0;

    sntp_setoperatingmode(0);
    sntp_setservername(0, WOLFSSL_DEMO_SNTP_SERVERS);
    sntp_init();

    while (1) {
        for (int32_t i = 0; (i < (SNTP_RECV_TIMEOUT / 100)) && now.tv_sec < 1657621503; i++) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
            gettimeofday(&now, NULL);
        }

        if (now.tv_sec < 1657621503) {
            sntp_retry_time = SNTP_RECV_TIMEOUT << sntp_retry_cnt;

            if (SNTP_RECV_TIMEOUT << (sntp_retry_cnt + 1) < SNTP_RETRY_TIMEOUT_MAX) {
                sntp_retry_cnt ++;
            }

            ESP_LOGI(TAG, "SNTP get time failed, retry after %d ms", sntp_retry_time);
            vTaskDelay(sntp_retry_time / portTICK_PERIOD_MS);
        } else {
            ESP_LOGI(TAG, "SNTP get time success");
            break;
        }
    }
}

static void wolfssl_client(void *pv)
{
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
    show_ciphers();
#endif /* DEBUG_WOLFSSL */
    int32_t ret = 0;

    const TickType_t xDelay = 500 / portTICK_PERIOD_MS;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;

    int32_t sockfd = -1;
    struct sockaddr_in sock_addr;
    struct hostent *entry = NULL;

    /* CA date verification need system time */
    get_time();

    while (1) {

        ESP_LOGI(TAG, "Setting hostname for TLS session...");
        /*get addr info for hostname*/
        do {
            entry = gethostbyname(WEB_SERVER);
            vTaskDelay(xDelay);
        } while (entry == NULL);

        ESP_LOGI(TAG, "Init wolfSSL...");
        ret = wolfSSL_Init();

        if (ret != WOLFSSL_SUCCESS) {
            ESP_LOGI(TAG, "Init wolfSSL failed:%d...", ret);
            goto failed1;
        }

        ESP_LOGI(TAG, "Set wolfSSL ctx ...");
/*
 * NOTE: To turn off TLS 1.3 only mode for wolfSSL component, comment
 * #define WOLFSSL_TLS13 in file ../components/wolfssl/port/user_settings.h
 */
#ifdef WOLFSSL_TLS13
        ctx = (void *)wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
        ctx = (void *)wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif
        if (!ctx) {
            ESP_LOGI(TAG, "Set wolfSSL ctx failed...");
            goto failed1;
        }

        ESP_LOGI(TAG, "Create socket ...");
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        if (sockfd < 0) {
            ESP_LOGI(TAG, "Create socket failed...");
            goto failed2;
        }

#if CONFIG_EXAMPLE_SERVER_CERT_VERIFY
        ESP_LOGI(TAG, "Loading the CA root certificate...");
        ret = wolfSSL_CTX_load_verify_buffer(ctx, server_root_cert_pem_start, server_root_cert_pem_end - server_root_cert_pem_start, WOLFSSL_FILETYPE_PEM);

        if (WOLFSSL_SUCCESS != ret) {
            ESP_LOGE(TAG, "Loading the CA root certificate failed...");
            goto failed3;
        }
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
#else
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
#endif

        memset(&sock_addr, 0, sizeof(sock_addr));
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(WEB_PORT);
        sock_addr.sin_addr.s_addr = ((struct in_addr *)(entry->h_addr))->s_addr;

        ESP_LOGI(TAG, "Connecting to %s:%d...", WEB_SERVER, WEB_PORT);
        ret = connect(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));

        if (ret) {
            ESP_LOGE(TAG, "Connecting to %s:%d failed: %d", WEB_SERVER, WEB_PORT, ret);
            goto failed3;
        }

        ESP_LOGI(TAG, "Create wolfSSL...");
        ssl = wolfSSL_new(ctx);
        if (!ssl) {
            ESP_LOGE(TAG, "Create wolfSSL failed...");
            goto failed3;
        }
        wolfSSL_set_fd(ssl, sockfd);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");
        ret = wolfSSL_connect(ssl);

        if (WOLFSSL_SUCCESS != ret) {
            ESP_LOGE(TAG, "Performing the SSL/TLS handshake failed:%d", ret);
            goto failed4;
        }

        ESP_LOGI(TAG, "Writing HTTPS request...");
        ret = wolfSSL_write(ssl, send_data, send_bytes);
        if (ret <= 0) {
            ESP_LOGE(TAG, "Writing HTTPS request failed:%d", ret);
            goto failed5;
        }

        ESP_LOGI(TAG, "Reading HTTPS response...");

        do {
            ret = wolfSSL_read(ssl, recv_data, sizeof(recv_data));
            if (ret <= 0) {
                ESP_LOGW(TAG, "Connection closed");
                break;
            }

            /* Print response directly to stdout as it is read */
            for (int i = 0; i < ret; i++) {
                printf("%c", recv_data[i]);
            }
            printf("\n");
        } while (1);

failed5:
        wolfSSL_shutdown(ssl);
failed4:
        wolfSSL_free(ssl);
failed3:
        close(sockfd);
failed2:
        wolfSSL_CTX_free(ctx);
failed1:
        wolfSSL_Cleanup();

        for (int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "Starting again!");
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
    xTaskCreate(wolfssl_client,
                WOLFSSL_DEMO_THREAD_NAME,
                WOLFSSL_DEMO_THREAD_STACK_WORDS,
                NULL,
                WOLFSSL_DEMO_THREAD_PRORIOTY,
                NULL);
}
