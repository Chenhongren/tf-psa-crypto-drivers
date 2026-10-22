# Copyright (c) 2026 ITE Corporation. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(IT51XXX_PSA_TARGET_NAME ${ITE_IT51XXX_TARGET_NAME}_psa_driver_api)
set(tfpsacrypto_target ${TF_PSA_CRYPTO_TARGET_PREFIX}tfpsacrypto)

add_library(${IT51XXX_PSA_TARGET_NAME} STATIC EXCLUDE_FROM_ALL)

target_sources(${IT51XXX_PSA_TARGET_NAME}
    PRIVATE
        it51xxx_crypto.c
        it51xxx_crypto_rsa.c
)

target_include_directories(${IT51XXX_PSA_TARGET_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        "$<TARGET_PROPERTY:${tfpsacrypto_target},INCLUDE_DIRECTORIES>"
)

target_include_directories(${IT51XXX_PSA_TARGET_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

if(TARGET ${TF_PSA_CRYPTO_TARGET_PREFIX}tfpsacrypto)
    message(STATUS "${TF_PSA_CRYPTO_TARGET_PREFIX}tfpsacrypto target exists")
else()
    message(STATUS "${TF_PSA_CRYPTO_TARGET_PREFIX}tfpsacrypto target does not exist yet")
endif()

target_link_libraries(${IT51XXX_PSA_TARGET_NAME}
    PUBLIC
        ${tfpsacrypto_target}
)

target_link_libraries(${tfpsacrypto_target}
    PRIVATE
        ${IT51XXX_PSA_TARGET_NAME}
)

get_target_property(ite_debug_includes
    ${tfpsacrypto_target}
    INCLUDE_DIRECTORIES
)

message(STATUS "ITE INCLUDE_DIRECTORIES: ${ite_debug_includes}")
