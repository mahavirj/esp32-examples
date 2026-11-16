if(CONFIG_CRT_BUNDLE_PARTITION)
    set(srcs "crt_bundle_partition.c")
endif()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS "include"
                       REQUIRES esp_http_client
                       PRIV_REQUIRES esp_partition spi_flash mbedtls bootloader_support esp_rom efuse esp_https_ota)

if(NOT CONFIG_CRT_BUNDLE_PARTITION)
    return()
endif()

# Build one partition image and flash it to both partitions with `idf.py flash`. The
# certificate data comes from the esp_crt_bundle_data managed component when the project
# depends on it, otherwise from the snapshot shipped with ESP-IDF.
idf_build_get_property(crt_dir ESP_CRT_BUNDLE_DATA_DIR)
if(NOT crt_dir)
    idf_build_get_property(idf_path IDF_PATH)
    set(crt_dir ${idf_path}/components/mbedtls/esp_crt_bundle)
endif()
message(STATUS "Certificate bundle partition data: ${crt_dir}")

idf_build_get_property(python PYTHON)
idf_build_get_property(build_dir BUILD_DIR)
idf_build_get_property(project_dir PROJECT_DIR)
set(gen_tool ${COMPONENT_DIR}/gen_crt_bundle_partition.py)
set(primary crt_bundle_0)
set(secondary crt_bundle_1)
set(unsigned_image ${build_dir}/crt_bundle-unsigned.bin)
set(image ${build_dir}/crt_bundle.bin)

partition_table_get_partition_info(primary_size "--partition-name ${primary}" "size")
partition_table_get_partition_info(secondary_size "--partition-name ${secondary}" "size")
if(NOT primary_size OR NOT primary_size STREQUAL secondary_size)
    fail_at_build_time(crt_bundle_partition_image
        "Partitions '${primary}' and '${secondary}' of the same size must be in the partition table."
        "Select partitions_crt_bundle.csv as the custom partition table.")
    return()
endif()

# The full default list, plus what the embedded bundle adds to it, so that a certificate
# trusted by the embedded bundle stays trusted once the partition bundle replaces it
set(inputs ${crt_dir}/cacrt_all.pem)
if(NOT CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
    list(APPEND inputs ${crt_dir}/cacrt_local.pem)
endif()
if(CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE)
    get_filename_component(custom_bundle_path
        ${CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH} ABSOLUTE BASE_DIR "${project_dir}")
    list(APPEND inputs ${custom_bundle_path})
endif()

set(gen_cmd ${python} ${gen_tool}
    --input ${inputs}
    --bundle-version ${CONFIG_CRT_BUNDLE_PARTITION_VERSION}
    --max-certs ${CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS}
    --partition-size ${primary_size})

if(CONFIG_CRT_BUNDLE_PARTITION_VERIFY_SIGNATURE AND CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES)
    # Sign with the application signing key, the same way the build signs the app image
    idf_component_get_property(espsecure_py_cmd esptool_py ESPSECUREPY_CMD)
    get_filename_component(signing_key "${CONFIG_SECURE_BOOT_SIGNING_KEY}" ABSOLUTE BASE_DIR "${project_dir}")
    set(gen_output ${unsigned_image})
    set(sign_cmd COMMAND ${espsecure_py_cmd} sign-data --version 2 --keyfile ${signing_key}
                 -o ${image} ${unsigned_image})
else()
    if(CONFIG_CRT_BUNDLE_PARTITION_VERIFY_SIGNATURE)
        message(WARNING "Signed binaries are not built by the project: sign ${image} with "
                        "`espsecure sign-data` before flashing it, or the application rejects it.")
    endif()
    set(gen_output ${image})
endif()

add_custom_command(OUTPUT ${image}
    COMMAND ${gen_cmd} --output ${gen_output}
    ${sign_cmd}
    DEPENDS ${gen_tool} ${inputs} ${signing_key}
    VERBATIM)

add_custom_target(crt_bundle_partition_image ALL DEPENDS ${image})
set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${image} ${unsigned_image})

# Adds the image to `idf.py flash` and creates a `<partition>-flash` target for each partition
esp_partition_register_target(${primary} ${image} FLASH_IN_PROJECT DEPENDS crt_bundle_partition_image)
esp_partition_register_target(${secondary} ${image} FLASH_IN_PROJECT DEPENDS crt_bundle_partition_image)
