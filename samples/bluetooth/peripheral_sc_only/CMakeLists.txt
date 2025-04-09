# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral_sc_only)

target_sources(app PRIVATE
  src/main.c
)

zephyr_library_include_directories(${ZEPHYR_BASE}/samples/bluetooth)

#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

add_library(tfm_app_rot_partition_dp STATIC)

target_include_directories(tfm_app_rot_partition_dp
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/dummy_partition
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/dummy_partition
)

target_sources(tfm_app_rot_partition_dp
    PRIVATE
        dummy_partition.c
)

# The generated sources
target_sources(tfm_app_rot_partition_dp
    PRIVATE
        ${CMAKE_BINARY_DIR}/dummy_partition/auto_generated/intermedia_tfm_dummy_partition.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/dummy_partition/auto_generated/load_info_tfm_dummy_partition.c
)

target_link_libraries(tfm_app_rot_partition_dp
    PRIVATE
        platform_s
        tfm_sprt
        psa_crypto_config
)

target_link_libraries(tfm_spm
    PRIVATE
        tfm_app_rot_partition_dp
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_dp
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_DUMMY_PARTITION
)




