/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <string.h>
#include <inttypes.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_check.h"
#include "esp_crc.h"
#include "esp_efuse.h"
#include "esp_partition.h"
#include "spi_flash_mmap.h"
#include "esp_crt_bundle.h"
#include "esp_secure_boot.h"
#if CONFIG_CRT_BUNDLE_PARTITION_OTA
#include "esp_https_ota.h"
#endif
#include "crt_bundle_partition.h"

/* Image layout: see gen_crt_bundle_partition.py */
#define CBP_MAGIC           0x50424345 /* "ECBP" */
#define CBP_HEADER_VERSION  1
#define CBP_ALIGN_UP(x, a)  (((x) + (a) - 1) & ~((a) - 1))

typedef struct {
    uint32_t magic;
    uint16_t header_version;
    uint16_t header_size;
    uint32_t bundle_version;
    uint32_t bundle_len;
    uint8_t reserved[12];
    uint32_t crc32;         /* header up to this field, followed by the bundle */
} cbp_header_t;

_Static_assert(sizeof(cbp_header_t) == 32, "certificate bundle partition header must be 32 bytes");

/*
 * The primary partition is the one used at startup. The secondary partition is its backup,
 * and the staging area for updates: the primary is only ever written with a copy of an image
 * that has already been validated in the secondary.
 */
enum { PRIMARY, SECONDARY };
static const char *const s_labels[] = { "crt_bundle_0", "crt_bundle_1" };
static const char *const s_roles[] = { "primary", "secondary" };

/* A bundle partition mapped into memory */
typedef struct {
    int idx;                /* PRIMARY or SECONDARY */
    const esp_partition_t *part;
    const uint8_t *map;
    esp_partition_mmap_handle_t handle;
    cbp_header_t hdr;       /* filled by slot_validate() */
} cbp_slot_t;

static const char *TAG = "crt_bundle_part";

/* The partition whose bundle is in use; part is NULL while the embedded bundle is in use.
 * Its mapping is kept: esp_crt_bundle holds a pointer into it. */
static cbp_slot_t s_active;

static size_t signature_size(void)
{
#if CONFIG_CRT_BUNDLE_PARTITION_VERIFY_SIGNATURE
    return esp_secure_boot_sig_block_size();
#else
    return 0;
#endif
}

static esp_err_t slot_map(int idx, cbp_slot_t *slot)
{
    slot->idx = idx;
    /* Subtype "undefined" is the one esp_ota verifies the signature of, see crt_bundle_partition_ota() */
    slot->part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_UNDEFINED, s_labels[idx]);
    if (slot->part == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    /* Mapped reads always go through flash decryption, so the partition has to be encrypted as well */
    ESP_RETURN_ON_FALSE(slot->part->encrypted || !esp_efuse_is_flash_encryption_enabled(), ESP_ERR_NOT_SUPPORTED, TAG,
                        "partition '%s' must be marked encrypted when flash encryption is enabled", s_labels[idx]);
    const void *map;
    esp_err_t err = esp_partition_mmap(slot->part, 0, slot->part->size, ESP_PARTITION_MMAP_DATA, &map, &slot->handle);
    slot->map = map;
    return err;
}

/* Header, bundle and padding; the signature sector (Secure Boot V2) follows at the next 4 KB boundary */
static size_t signed_length(const cbp_header_t *hdr)
{
    return CBP_ALIGN_UP(sizeof(*hdr) + hdr->bundle_len, SPI_FLASH_SEC_SIZE);
}

/* Validate the image in a mapped partition. Nothing in it is trusted before the signature is verified.
 * @p verify_signature is false only for an image whose signature esp_ota has just verified. */
static esp_err_t slot_validate(cbp_slot_t *slot, bool verify_signature)
{
    cbp_header_t *hdr = &slot->hdr;
    memcpy(hdr, slot->map, sizeof(*hdr));

    /* The header is only needed here to locate the signature, which then authenticates the header itself */
    if (hdr->magic != CBP_MAGIC || hdr->header_version != CBP_HEADER_VERSION || hdr->header_size != sizeof(*hdr)) {
        return ESP_ERR_NOT_FOUND;
    }
    if (hdr->bundle_len == 0 || hdr->bundle_len > slot->part->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (signed_length(hdr) + signature_size() > slot->part->size) {
        return ESP_ERR_INVALID_SIZE;
    }

#if CONFIG_CRT_BUNDLE_PARTITION_VERIFY_SIGNATURE
    if (verify_signature) {
        esp_err_t err = esp_secure_boot_verify_signature(slot->part->address, signed_length(hdr));
        if (err != ESP_OK) {
            return err;
        }
    }
#endif

    uint32_t crc = esp_crc32_le(0, slot->map, offsetof(cbp_header_t, crc32));
    crc = esp_crc32_le(crc, slot->map + sizeof(*hdr), hdr->bundle_len);
    if (crc != hdr->crc32) {
        return ESP_ERR_INVALID_CRC;
    }
    if (hdr->bundle_version < CONFIG_CRT_BUNDLE_PARTITION_MIN_VERSION) {
        return ESP_ERR_INVALID_VERSION;
    }
    return ESP_OK;
}

/* Hand the bundle of a validated partition to esp_crt_bundle and make it the active one.
 * On success the slot's mapping is owned by s_active, otherwise it is released. */
static esp_err_t slot_activate(const cbp_slot_t *slot)
{
    esp_err_t err = esp_crt_bundle_set(slot->map + sizeof(slot->hdr), slot->hdr.bundle_len);
    if (err != ESP_OK) {
        esp_partition_munmap(slot->handle);
        return err;
    }
    if (s_active.part != NULL) {
        esp_partition_munmap(s_active.handle);
    }
    s_active = *slot;
    ESP_LOGI(TAG, "using certificate bundle version %" PRIu32 " from %s partition '%s'%s", slot->hdr.bundle_version,
             s_roles[slot->idx], s_labels[slot->idx], signature_size() ? " (signature verified)" : "");
    return ESP_OK;
}

#if CONFIG_CRT_BUNDLE_PARTITION_OTA
/* Make the other partition an exact copy of the active one and leave it mapped in @p copy */
static esp_err_t mirror_active(cbp_slot_t *copy)
{
    esp_err_t err = slot_map(!s_active.idx, copy);
    if (err != ESP_OK) {
        return err;
    }
    if (copy->part->size != s_active.part->size) {
        err = ESP_ERR_INVALID_SIZE;
    } else if (memcmp(copy->map, s_active.map, copy->part->size) != 0) {
        ESP_LOGI(TAG, "copying %s partition to %s partition", s_roles[s_active.idx], s_roles[copy->idx]);
        err = esp_partition_copy(copy->part, 0, s_active.part, 0, SIZE_MAX);
        if (err == ESP_OK && memcmp(copy->map, s_active.map, copy->part->size) != 0) {
            err = ESP_ERR_INVALID_CRC;
        }
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to copy %s partition to %s partition: %s", s_roles[s_active.idx], s_roles[copy->idx],
                 esp_err_to_name(err));
        esp_partition_munmap(copy->handle);
        return err;
    }
    copy->hdr = s_active.hdr;
    return ESP_OK;
}

/* The secondary partition is active: copy it to the primary and use the primary from now on */
static esp_err_t promote_to_primary(void)
{
    cbp_slot_t primary;
    esp_err_t err = mirror_active(&primary);
    return (err == ESP_OK) ? slot_activate(&primary) : err;
}

/* The primary partition is active: make the secondary its backup again */
static void restore_secondary(void)
{
    cbp_slot_t secondary;
    if (mirror_active(&secondary) == ESP_OK) {
        esp_partition_munmap(secondary.handle);
    }
}
#endif /* CONFIG_CRT_BUNDLE_PARTITION_OTA */

esp_err_t crt_bundle_partition_init(void)
{
    static bool s_tried;
    if (s_active.part != NULL) {
        return ESP_OK;
    }
    if (s_tried) {
        /* Both partitions were already rejected; only an update can change that */
        return ESP_ERR_NOT_FOUND;
    }
    s_tried = true;

    esp_err_t err = ESP_ERR_NOT_FOUND;
    for (int idx = PRIMARY; idx <= SECONDARY; idx++) {
        cbp_slot_t slot;
        err = slot_map(idx, &slot);
        if (err == ESP_OK) {
            err = slot_validate(&slot, true);
            if (err == ESP_OK) {
                err = slot_activate(&slot);
            } else {
                esp_partition_munmap(slot.handle);
            }
        }
        if (err == ESP_OK) {
            return ESP_OK;
        }
        ESP_LOGW(TAG, "%s partition '%s' rejected: %s", s_roles[idx], s_labels[idx], esp_err_to_name(err));
    }
    ESP_LOGW(TAG, "no valid bundle partition, using the embedded bundle");
    return err;
}

uint32_t crt_bundle_partition_get_version(void)
{
    return (s_active.part != NULL) ? s_active.hdr.bundle_version : 0;
}

#if CONFIG_CRT_BUNDLE_PARTITION_OTA
/* Download an image into the secondary partition. With signed app verification, esp_ota verifies
 * the signature (CONFIG_SECURE_SIGNED_DATA_PARTITION) when the download is finished. */
static esp_err_t staging_download(const esp_http_client_config_t *http_config, const esp_partition_t *staging,
                                  size_t *image_len)
{
    esp_https_ota_config_t ota_config = {
        .http_config = http_config,
        .partition.staging = staging,
    };
    esp_https_ota_handle_t handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &handle);
    if (err != ESP_OK) {
        return err;
    }
    do {
        err = esp_https_ota_perform(handle);
    } while (err == ESP_ERR_HTTPS_OTA_IN_PROGRESS);
    if (err == ESP_OK && !esp_https_ota_is_complete_data_received(handle)) {
        err = ESP_ERR_INVALID_SIZE;
    }
    if (err != ESP_OK) {
        esp_https_ota_abort(handle);
        return err;
    }
    *image_len = esp_https_ota_get_image_len_read(handle);
    return esp_https_ota_finish(handle);
}

esp_err_t crt_bundle_partition_ota(const esp_http_client_config_t *http_config)
{
    /* Without a valid partition the update simply installs the first image */
    crt_bundle_partition_init();

    /* The secondary partition is about to be overwritten. If it is the one in use, because the
     * primary was rejected at startup, repair the primary from it and switch over first. */
    if (s_active.part != NULL && s_active.idx == SECONDARY) {
        ESP_RETURN_ON_ERROR(promote_to_primary(), TAG, "cannot repair the primary partition");
    }

    cbp_slot_t staging;
    ESP_RETURN_ON_ERROR(slot_map(SECONDARY, &staging), TAG, "secondary partition not available");

    const uint32_t active_version = crt_bundle_partition_get_version();
    size_t image_len = 0;
    ESP_LOGI(TAG, "downloading new bundle image into secondary partition '%s'", s_labels[SECONDARY]);
    esp_err_t err = staging_download(http_config, staging.part, &image_len);
    if (err == ESP_OK) {
#if CONFIG_SECURE_SIGNED_DATA_PARTITION || CONFIG_APP_UPDATE_SECURE_SIGNED_DATA_PARTITION
        /* esp_ota verified the signature found in the last sector of the download */
        err = slot_validate(&staging, false);
#else
        /* esp_ota did not verify it (the option has another name in this ESP-IDF version) */
        err = slot_validate(&staging, true);
#endif
    }
    if (err == ESP_OK && image_len != signed_length(&staging.hdr) + signature_size()) {
        /* The signature is not where the header says it is: startup validation would not find it */
        ESP_LOGE(TAG, "image size %u does not match its header", (unsigned)image_len);
        err = ESP_ERR_INVALID_SIZE;
    }
    if (err == ESP_OK && staging.hdr.bundle_version <= active_version) {
        ESP_LOGE(TAG, "new bundle version %" PRIu32 " is not newer than active version %" PRIu32,
                 staging.hdr.bundle_version, active_version);
        err = ESP_ERR_INVALID_VERSION;
    }
    if (err != ESP_OK) {
        esp_partition_munmap(staging.handle);
    } else {
        /* Switch TLS to the new bundle before the primary partition is overwritten */
        err = slot_activate(&staging);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bundle update rejected: %s", esp_err_to_name(err));
        if (s_active.part != NULL) {
            /* Discard whatever was downloaded */
            restore_secondary();
        }
        return err;
    }

    /* Install the new image in the primary partition. If this is interrupted while the primary is
     * being rewritten, the next startup rejects the primary and uses the secondary. */
    return promote_to_primary();
}
#endif /* CONFIG_CRT_BUNDLE_PARTITION_OTA */
