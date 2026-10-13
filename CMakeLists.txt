cmake_minimum_required(VERSION 3.16)

file(READ "${CMAKE_SOURCE_DIR}/client/version.h" _noxssh_version_h)
string(REGEX MATCH "NOXSSH_VERSION_STRING \"([^\"]+)\"" _ "${_noxssh_version_h}")
if(NOT CMAKE_MATCH_1)
    message(FATAL_ERROR "Could not parse NOXSSH_VERSION_STRING from client/version.h")
endif()
set(NOXSSH_VERSION "${CMAKE_MATCH_1}")
string(REPLACE "." ";" _noxssh_version_parts "${NOXSSH_VERSION}")
list(LENGTH _noxssh_version_parts _noxssh_version_part_count)
if(NOT _noxssh_version_part_count EQUAL 3)
    message(FATAL_ERROR "Invalid NOXSSH_VERSION_STRING format: ${NOXSSH_VERSION}")
endif()
list(GET _noxssh_version_parts 0 _noxssh_version_major)
list(GET _noxssh_version_parts 1 _noxssh_version_minor)
list(GET _noxssh_version_parts 2 _noxssh_version_patch)

project(noxssh VERSION ${_noxssh_version_major}.${_noxssh_version_minor}.${_noxssh_version_patch} LANGUAGES C)

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
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(netnox_ssh PRIVATE common/noxssh_server.c)
endif()
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
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(server)
endif()

option(NOXSSH_BUILD_TESTS "Build noxssh unit tests" ON)
if(NOXSSH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(FILES
    README.md
    LICENSE.md
    COPYING.md
    DESTINATION share/doc/noxssh
)

if(UNIX AND NOT APPLE)
    set(CPACK_GENERATOR "DEB")
    set(CPACK_PACKAGE_NAME "noxssh")
    set(CPACK_PACKAGE_VENDOR "Argenox Technologies LLC")
    set(CPACK_PACKAGE_CONTACT "info@argenox.com")
    set(CPACK_PACKAGE_VERSION "${NOXSSH_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Lightweight SSH client built on NoxTLS")
    set(CPACK_PACKAGE_DESCRIPTION
        "NoxSSH is a lightweight SSH-2 client with password and Ed25519 public key authentication, host key verification, and OpenSSH-style configuration support.")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING.md")
    set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
    include(CPack)
endif()
