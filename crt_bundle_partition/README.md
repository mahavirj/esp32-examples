# Certificate Bundle in Flash Partitions

Requires **ESP-IDF v6.1**.

ESP-IDF normally embeds the trusted root certificate bundle (`esp_crt_bundle`) in the application image, so the root
list can only change with an application update. This example keeps the full list in its own flash partitions instead:

- The bundle is stored in two identical data partitions, `crt_bundle_0` (primary) and `crt_bundle_1` (secondary).
- The application embeds only a small fallback bundle (the certificates in `certs`).
- The partition image is signed with the application signing key and verified before it is used.
- The partitions can be updated over the air without touching the application.

The example then connects to a list of HTTPS servers, as the ESP-IDF `protocols/https_x509_bundle` example does.

## How it works

- **Image:** generated at build time and written to both partitions by `idf.py flash`. It contains the full root list
  from the [espressif/esp_crt_bundle_data](https://components.espressif.com/components/espressif/esp_crt_bundle_data)
  managed component plus the certificates from `certs`, so a certificate trusted by the embedded bundle stays trusted.
- **Startup:** `crt_bundle_partition_init()` validates the primary partition and passes its bundle to
  `esp_crt_bundle_set()`. If the primary is rejected, the secondary is validated and used. If both are rejected, the
  embedded bundle stays in use and the example connects only to the servers it covers.
- **Signature:** when the application is built with Secure Boot V2 signed app verification, the image is signed at
  build time with the application signing key. At every startup the signature is verified first; the CRC32 and the
  minimum bundle version are checked after that. Without signed app verification only the CRC32 protects the image.
- **Update:** `crt_bundle_partition_ota()` uses `esp_https_ota` with a staging partition, as the ESP-IDF
  `system/ota/partitions_ota` example does:
  - The secondary partition is the staging partition. The primary partition is only written with a copy of an image
    that has already been validated in the secondary one.
  - With signed app verification, `esp_ota` verifies the signature of the downloaded image
    (`CONFIG_SECURE_SIGNED_DATA_PARTITION`, selected automatically). This is why the partitions have the `undefined`
    subtype.
  - The header, CRC32 and minimum version of the staged image are then checked as at startup. Its size must match its
    header and it must have a higher bundle version than the one in use.
  - TLS is switched to the new bundle, the image is copied to the primary partition, and the primary is used again.
  - A rejected image is discarded by restoring the secondary partition from the primary one.
  - If the secondary partition is the one in use, the primary is repaired from it before the download.

## Build and run

Set the Wi-Fi or Ethernet connection under "Example Connection Configuration" in `idf.py menuconfig`, then:

```
idf.py set-target <target>
idf.py -p PORT flash monitor
```

`sdkconfig.defaults` enables the bundle partitions without a signature. Two more configuration fragments can be added:

| Fragment | Adds |
| -------- | ---- |
| `sdkconfig.signed` | Signed image, using signed apps without hardware Secure Boot (RSA scheme) and the key `signing_key.pem` |
| `sdkconfig.ota` | Over-the-air update of the partitions at startup |

```
espsecure generate-signing-key --version 2 --scheme rsa3072 signing_key.pem
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.signed;sdkconfig.ota" set-target <target>
idf.py -p PORT flash monitor
```

On ESP32 a signed image needs chip revision v3.0 or later (`CONFIG_ESP32_REV_MIN_3`).

```
I (4141) crt_bundle_part: using certificate bundle version 1 from primary partition 'crt_bundle_0' (signature verified)
I (4141) example: Attempting to download certificate bundle update from https://192.168.0.3:8070/crt_bundle.bin
I (4141) crt_bundle_part: downloading new bundle image into secondary partition 'crt_bundle_1'
I (4261) crt_bundle_part: using certificate bundle version 2 from secondary partition 'crt_bundle_1' (signature verified)
I (4271) crt_bundle_part: copying secondary partition to primary partition
I (4311) crt_bundle_part: using certificate bundle version 2 from primary partition 'crt_bundle_0' (signature verified)
I (4311) example: Certificate bundle upgrade successful (bundle version 2)
I (4321) example: Connecting to 8 URLs
```

## Configuration

| Option | Needed when |
| ------ | ----------- |
| `CONFIG_CRT_BUNDLE_PARTITION` | always (set in `sdkconfig.defaults`) |
| `CONFIG_PARTITION_TABLE_CUSTOM` with `partitions_crt_bundle.csv` | always; the build fails with a message if a partition is missing |
| Signed app verification with a Secure Boot V2 scheme, `CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES` and a signing key | for a signed image |
| `encrypted` flag on both partitions in the CSV | flash encryption is enabled |
| `CONFIG_CRT_BUNDLE_PARTITION_OTA` | the application updates the partitions over the air |
| `CONFIG_EXAMPLE_CRT_BUNDLE_UPGRADE_URL` | with the option above: URL of the image, as in the ESP-IDF `simple_ota_example`; `FROM_STDIN` reads it from the console |
| `CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK` | the update server certificate does not carry the server name, for example a local test server |
| `CONFIG_CRT_BUNDLE_PARTITION_VERSION` | building an image for an update: it must be higher than the installed one |
| `CONFIG_CRT_BUNDLE_PARTITION_MIN_VERSION` | retiring older signed images, see Limitations |

The partitions are 128 KB each. An image is the bundle rounded up to 4 KB plus a 4 KB signature sector: about 60 KB for
the current list and about 100 KB at the default `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS` of 200, which also
limits the bundle accepted from a partition.

The update server is verified against the certificate bundle in use, like the other servers of this example. For a
server with a private or self-signed certificate, add its root certificate to `certs`. The image to host is
`build/crt_bundle.bin` from a build with a higher `CONFIG_CRT_BUNDLE_PARTITION_VERSION`.

`idf.py crt_bundle_0-flash` and `idf.py crt_bundle_1-flash` write a single partition.

## Image format

All fields are little-endian.

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0x00 | 4  | Magic `ECBP` |
| 0x04 | 2  | Header version (1) |
| 0x06 | 2  | Header size (32) |
| 0x08 | 4  | Bundle version, monotonic |
| 0x0C | 4  | Bundle length |
| 0x10 | 12 | Reserved |
| 0x1C | 4  | CRC32 of bytes 0x00..0x1B and the bundle |
| 0x20 | N  | Bundle, unchanged `esp_crt_bundle` format |
| ...  |    | 0xFF padding to a 4 KB boundary |
| ...  | 4096 | Signature sector from `espsecure sign-data` (signed images only) |

To build an image by hand (`IDF_PATH` must be set):

```
python components/crt_bundle_partition/gen_crt_bundle_partition.py --input <certificate files or folders> \
    --bundle-version 2 --output crt_bundle_v2.bin
espsecure sign-data --version 2 --keyfile signing_key.pem --output crt_bundle_v2_signed.bin crt_bundle_v2.bin
python components/crt_bundle_partition/gen_crt_bundle_partition.py --info crt_bundle_v2_signed.bin
```

## Limitations

- **Replay of older signed images.** A network attacker cannot downgrade the bundle: an update must be signed and newer
  than the bundle in use. Someone who can write the flash can put an older signed image back, and startup accepts it
  as long as its version is not below `CONFIG_CRT_BUNDLE_PARTITION_MIN_VERSION`. That minimum is compiled into the
  application, so it only helps on a device with Secure Boot and application anti-rollback
  (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`), where an older application with a lower minimum cannot be put back either.
  The partition table of this example has a single factory application and does not demonstrate that.
- If power is lost after the new image is validated but before the primary partition starts being rewritten, the next
  startup uses the old image from the primary and the update has to be repeated.
- The example tries the update at every startup and downloads the image before it can compare versions. An application
  should check for a newer version first.
- No other TLS connection should be in progress during an update.
- With signed app verification, run the update from a task with at least 12 KB of stack: `esp_ota` in ESP-IDF v6.1
  keeps the 4 KB signature sector on the stack.
- Only the Secure Boot V2 signature schemes are supported.
- From ESP-IDF v6.2 the `esp_ota` option is named `CONFIG_APP_UPDATE_SECURE_SIGNED_DATA_PARTITION`; the `select` in
  `components/crt_bundle_partition/Kconfig` has to be changed for those versions.
- Not tested: flash encryption, hardware Secure Boot with eFuse keys, and real hardware. The example was built with
  ESP-IDF v6.1 for ESP32-C6 and ESP32-C3 and verified on an emulated ESP32-C6 with signed apps without hardware Secure
  Boot. It was not built for the Xtensa targets with v6.1.
