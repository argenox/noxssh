cmake_minimum_required(VERSION 3.16)

project(noxssh VERSION 0.2.25 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
if(CMAKE_CONFIGURATION_TYPES)
    foreach(cfg ${CMAKE_CONFIGURATION_TYPES})
        string(TOUPPER "${cfg}" cfg_upper)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg_upper} "${CMAKE_SOURCE_DIR}/bin")
    endforeach()
endif()

if(NOT EXISTS "${CMAKE_SOURCE_DIR}/noxtls/CMakeLists.txt")
    message(FATAL_ERROR
        "Missing submodule noxtls at repo root. "
        "Run: git submodule update --init --recursive")
endif()

# Ensure NoxTLS always resolves from repo root (avoid stale cache paths like netnox/noxtls).
set(NOXTLS_PROJECT_ROOT "${CMAKE_SOURCE_DIR}/noxtls" CACHE PATH "NoxTLS source root" FORCE)

# Build only noxtls as library dependencies for SSH.
set(BUILD_APPLICATIONS OFF CACHE BOOL "Build NetNox/noxtls demo applications" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "Build NetNox/noxtls unit tests" FORCE)
set(BUILD_PROTOCOLS OFF CACHE BOOL "Build NetNox protocol libraries" FORCE)
set(BUILD_NOXTLS ON CACHE BOOL "Build NoxTLS" FORCE)

add_subdirectory(noxtls EXCLUDE_FROM_ALL)

add_library(netnox_ssh
    common/noxssh_common.c
)
target_include_directories(netnox_ssh
    PUBLIC
        ${CMAKE_SOURCE_DIR}/common
        ${CMAKE_SOURCE_DIR}/noxtls
        ${CMAKE_SOURCE_DIR}/noxtls/noxtls-lib
        ${CMAKE_SOURCE_DIR}/noxtls/noxtls-lib/common
        ${CMAKE_SOURCE_DIR}/noxtls/noxtls-lib/mdigest
        ${CMAKE_SOURCE_DIR}/noxtls/noxtls-lib/encryption
        ${CMAKE_SOURCE_DIR}/noxtls/noxtls-lib/pkc
        ${CMAKE_SOURCE_DIR}/noxtls/noxtls-lib/drbg
)
target_link_libraries(netnox_ssh
    PUBLIC
        noxtls_hash
        noxtls_pkc
        noxtls_encryption
        noxtls_drbg
        noxtls_common
)
# Ensure AES-CTR API prototypes are visible when building the SSH layer.
target_compile_definitions(netnox_ssh
    PRIVATE
        NOXTLS_FEATURE_AES=1
        NOXTLS_FEATURE_AES_CTR=1
)
add_subdirectory(client)
