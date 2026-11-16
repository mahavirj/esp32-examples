/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#pragma once

#include <stdint.h>
#include "esp_err.h"
#include "esp_http_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Use the certificate bundle stored in the bundle partitions
 *
 * Validates the image in the primary partition and passes its bundle to esp_crt_bundle_set().
 * When the application is built with signed app verification, the signature appended to the
 * image is verified first; the CRC and the minimum version are checked after that. If the
 * primary partition is rejected, the secondary partition is validated and used in the same
 * way. Call it once before the first TLS connection.
 *
 * If both partitions are rejected nothing is changed, so esp_crt_bundle_attach() keeps
 * using the bundle embedded in the application.
 *
 * @return
 *  - ESP_OK on success
 *  - otherwise the reason the last partition tried was rejected: ESP_ERR_NOT_FOUND (no
 *    partition or no image), ESP_ERR_INVALID_VERSION, ESP_ERR_INVALID_CRC,
 *    ESP_ERR_INVALID_SIZE, or a signature verification error
 */
esp_err_t crt_bundle_partition_init(void);

/**
 * @brief Version of the active partition bundle, 0 if the embedded bundle is in use
 */
uint32_t crt_bundle_partition_get_version(void);

/**
 * @brief Download a newer bundle image and install it in both partitions
 *
 * Available with CONFIG_CRT_BUNDLE_PARTITION_OTA.
 *
 * The image is downloaded into the secondary partition with esp_https_ota. When the application
 * is built with signed app verification, esp_ota verifies its signature at the end of the
 * download (CONFIG_SECURE_SIGNED_DATA_PARTITION). The header, CRC and minimum version
 * are then checked as at startup, and the image must have a higher bundle version than the one
 * in use. TLS is then switched to the new bundle, the image is copied to the primary partition
 * and the primary partition is used from then on.
 *
 * If the image is rejected, the secondary partition is restored from the primary one and the
 * bundle in use does not change. If the secondary partition is the one in use, because the
 * primary was rejected at startup, the primary is first repaired from it.
 *
 * No TLS connection other than the download itself should be in progress while this
 * function runs. With signed app verification, call it from a task with at least 12 KB of
 * stack: esp_ota in ESP-IDF v6.1 keeps the 4 KB signature sector on the stack.
 *
 * @param http_config HTTP client configuration for the image URL
 *
 * @return ESP_OK on success, otherwise the download, validation or flash error
 */
esp_err_t crt_bundle_partition_ota(const esp_http_client_config_t *http_config);

#ifdef __cplusplus
}
#endif
