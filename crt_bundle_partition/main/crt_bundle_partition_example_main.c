/* Certificate bundle partition example
 *
 * Connects to multiple HTTPS servers and validates their certificates
 * using the certificate bundle stored in a flash partition.
 *
 * Based on the ESP-IDF https_x509_bundle example.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "crt_bundle_partition.h"

/* The first URLs are covered by the custom bundle in certs/, the others need the full certificate list */
#define CUSTOM_BUNDLE_URLS  2

static const char *web_urls[] = {
    "https://letsencrypt.org",
    "https://espressif.com",
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL || CONFIG_CRT_BUNDLE_PARTITION
    "https://www.identrust.com",
    "https://www.globalsign.com",
    "https://www.sectigo.com",
    "https://www.digicert.com",
    "https://www.godaddy.com",
    "https://rainmaker.espressif.com",  // Amazon
#endif
};

static const char *TAG = "example";

#if CONFIG_CRT_BUNDLE_PARTITION_OTA
#define OTA_URL_SIZE 256

/* The upgrade server is verified against the bundle in use, like any other server */
static void crt_bundle_upgrade(void)
{
    esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_CRT_BUNDLE_UPGRADE_URL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
    };

#ifdef CONFIG_EXAMPLE_CRT_BUNDLE_UPGRADE_URL_FROM_STDIN
    char url_buf[OTA_URL_SIZE] = {0};
    example_configure_stdin_stdout();
    fgets(url_buf, OTA_URL_SIZE, stdin);
    url_buf[strcspn(url_buf, "\r\n")] = '\0';
    config.url = url_buf;
#endif

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
    config.skip_cert_common_name_check = true;
#endif

    ESP_LOGI(TAG, "Attempting to download certificate bundle update from %s", config.url);
    esp_err_t err = crt_bundle_partition_ota(&config);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Certificate bundle upgrade successful (bundle version %" PRIu32 ")",
                 crt_bundle_partition_get_version());
    } else {
        ESP_LOGE(TAG, "Certificate bundle upgrade failed: %s (bundle version %" PRIu32 ")", esp_err_to_name(err),
                 crt_bundle_partition_get_version());
    }
}
#endif /* CONFIG_CRT_BUNDLE_PARTITION_OTA */

static void https_get_task(void *pvParameters)
{
    int num_urls = sizeof(web_urls) / sizeof(web_urls[0]);

#if CONFIG_CRT_BUNDLE_PARTITION
    /* Use the bundle from the primary partition, or from the secondary one if the primary is
     * rejected. If both are rejected, the bundle embedded in the application stays in use. */
    crt_bundle_partition_init();

#if CONFIG_CRT_BUNDLE_PARTITION_OTA
    /* Install a newer bundle image before the first connection */
    crt_bundle_upgrade();
#endif

    if (crt_bundle_partition_get_version() == 0) {
        /* Only the embedded bundle is available: connect to the servers it covers */
        num_urls = CUSTOM_BUNDLE_URLS;
    }
#endif

    while (1) {
        int conn_count = 0;
        ESP_LOGI(TAG, "Connecting to %d URLs", num_urls);

        for (int i = 0; i < num_urls; i++) {
            esp_tls_cfg_t cfg = {
                .crt_bundle_attach = esp_crt_bundle_attach,
            };

            esp_tls_t *tls = esp_tls_init();
            if (!tls) {
                ESP_LOGE(TAG, "Failed to allocate esp_tls handle!");
                goto end;
            }

            if (esp_tls_conn_http_new_sync(web_urls[i], &cfg, tls) == 1) {
                ESP_LOGI(TAG, "Connection established to %s", web_urls[i]);
                conn_count++;
            } else {
                ESP_LOGE(TAG, "Could not connect to %s", web_urls[i]);
            }

            esp_tls_conn_destroy(tls);
end:
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }

        ESP_LOGI(TAG, "Completed %d connections", conn_count);
        ESP_LOGI(TAG, "Starting over again...");
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

    /* The stack leaves room for the 4 KB signature sector that esp_ota (ESP-IDF v6.1) keeps on
     * the stack while it verifies a downloaded bundle image */
    xTaskCreate(&https_get_task, "https_get_task", 12288, NULL, 5, NULL);
}
