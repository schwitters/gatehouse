cmake_minimum_required(VERSION 3.24)
enable_testing()

project(gatehouse VERSION 0.6.0 LANGUAGES CXX)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

option(GATEHOUSE_ENABLE_ASAN "Enable AddressSanitizer" OFF)

# ----------------------------
# Warnings/Hardening: apply ONLY to our targets
# ----------------------------
add_library(gatehouse_warnings INTERFACE)

target_compile_options(gatehouse_warnings INTERFACE
  -Wall -Wextra -Wpedantic
  -Wconversion -Wsign-conversion
  -Wshadow
  -Wformat=2
  -Wnull-dereference
  -fno-omit-frame-pointer
)

if (GATEHOUSE_ENABLE_ASAN)
  target_compile_options(gatehouse_warnings INTERFACE -fsanitize=address,undefined)
  target_link_options(gatehouse_warnings INTERFACE -fsanitize=address,undefined)
endif()

# ----------------------------
# Crow + Boost configuration (requested)
# ----------------------------
add_definitions(-DCROW_USE_BOOST)
add_definitions(-DCROW_ENABLE_STATIC_FILE=1)
add_definitions(-DBOOST_ASIO_NO_DEPRECATED)
set(CROW_USE_BOOST ON)

set(CROW_INSTALL OFF CACHE BOOL "" FORCE)

include(FetchContent)

set(CROW_PATCH_SCRIPT "${CMAKE_BINARY_DIR}/patch_crow.cmake")
file(WRITE "${CROW_PATCH_SCRIPT}" "
    message(STATUS \"Patching Crow: Removing Boost conflict...\")
    set(TARGET_FILE \"CMakeLists.txt\")
    if(EXISTS \"\${TARGET_FILE}\")
        file(READ \"\${TARGET_FILE}\" file_content)
        string(REPLACE
            \"add_library(Boost::system ALIAS Boost::headers)\"
            \"# PATCHED BY MINERP: add_library(Boost::system ALIAS Boost::headers)\"
            file_content
            \"\${file_content}\"
        )
        file(WRITE \"\${TARGET_FILE}\" \"\${file_content}\")
    endif()
")

FetchContent_Declare(
  crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG v1.3.0
  PATCH_COMMAND ${CMAKE_COMMAND} -P "${CROW_PATCH_SCRIPT}"
)
FetchContent_MakeAvailable(crow)

# ----------------------------
# Dependencies
# ----------------------------
find_package(SQLite3 REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(COM_ERR REQUIRED com_err)
pkg_check_modules(KADM5 REQUIRED kadm-client)
pkg_check_modules(KRB5 REQUIRED krb5)
pkg_check_modules(LDAP REQUIRED ldap)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# ----------------------------
# Main target
# ----------------------------
add_executable(gatehouse
  src/main.cc
  src/app/http_server.cc
  src/app/http_utils.cc
  src/app/server_context.cc
  src/app/routes_misc.cc
  src/app/routes_auth.cc
  src/app/routes_portal.cc
  src/app/routes_invite.cc
  src/app/routes_admin.cc
  src/app/routes_guacamole.cc
  src/app/auth.cc
  src/app/email_sender.cc
  src/infra/invite_repo.cc
  src/infra/invite_session_repo.cc
  src/infra/invite_otp_repo.cc
  src/infra/ldif_directory.cc
  src/core/result.cc
  src/core/sha256.cc

  src/core/hex.cc
  src/core/random.cc
  src/core/time.cc
  src/core/url.cc

  src/infra/sqlite_db.cc
  src/infra/migrate.cc
  src/infra/session_repo.cc
  src/infra/krb5_client.cc
  src/infra/kadm5_client.cc
  src/infra/ldap_directory.cc
  src/infra/ticket_vault_read.cc
  src/infra/xrdp_otp_repo.cc
  src/infra/cred_fetch_token_repo.cc
  src/infra/ticket_vault_repo.cc
  src/core/crypto_aead.cc
  src/core/aes_cbc.cc
)


target_include_directories(gatehouse
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(gatehouse
  PRIVATE
    gatehouse_warnings
    Crow::Crow
    SQLite::SQLite3
)

target_compile_definitions(gatehouse PRIVATE
  GATEHOUSE_VERSION="0.0.11"
)

# Treat dependency headers as SYSTEM to suppress their warnings.
get_target_property(_crow_inc Crow::Crow INTERFACE_INCLUDE_DIRECTORIES)
if (_crow_inc)
  target_include_directories(gatehouse SYSTEM PRIVATE ${_crow_inc})
endif()

get_target_property(_sqlite_inc SQLite::SQLite3 INTERFACE_INCLUDE_DIRECTORIES)
if (_sqlite_inc)
  target_include_directories(gatehouse SYSTEM PRIVATE ${_sqlite_inc})
endif()
message(STATUS    "Libraries:  ${COM_ERR_LIBRARIES}")
message(STATUS    "Includes:   ${COM_ERR_INCLUDE_DIRS}")

# MIT Kerberos (pkg-config)
target_include_directories(gatehouse SYSTEM PRIVATE ${KRB5_INCLUDE_DIRS} ${KADM5_INCLUDE_DIRS} ${COM_ERR_INCLUDE_DIRS})
target_link_directories(gatehouse PRIVATE ${KRB5_LIBRARY_DIRS} ${KADM5_LIBRARY_DIRS})
target_link_libraries(gatehouse PRIVATE
   ${KRB5_LIBRARIES}
   ${KADM5_LIBRARIES}
   ${COM_ERR_LIBRARIES}
)
target_link_options(gatehouse PRIVATE -Wl,--no-as-needed -lcom_err)
target_compile_options(gatehouse PRIVATE ${KRB5_CFLAGS_OTHER})

target_link_libraries(gatehouse PRIVATE OpenSSL::Crypto)

# OpenLDAP (pkg-config)
target_include_directories(gatehouse SYSTEM PRIVATE ${LDAP_INCLUDE_DIRS})
target_link_directories(gatehouse PRIVATE ${LDAP_LIBRARY_DIRS})
target_link_libraries(gatehouse PRIVATE ${LDAP_LIBRARIES})
target_compile_options(gatehouse PRIVATE ${LDAP_CFLAGS_OTHER})
target_link_libraries(gatehouse PRIVATE CURL::libcurl)

# ----------------------------
# Core static library (no I/O, no Kerberos/LDAP — for unit tests)
# ----------------------------
add_library(gatehouse_core_lib STATIC
  src/core/result.cc
  src/core/crypto_aead.cc
  src/core/hex.cc
  src/core/random.cc
  src/core/sha256.cc
  src/core/time.cc
  src/core/url.cc
)
target_include_directories(gatehouse_core_lib PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(gatehouse_core_lib
  PUBLIC  OpenSSL::Crypto
  PRIVATE gatehouse_warnings
)

# ----------------------------
# Google Test (fetched at configure time)
# ----------------------------
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

# ----------------------------
# Unit test executable
# ----------------------------
add_executable(gatehouse_tests
  tests/core_result_test.cc
  tests/core_hex_test.cc
  tests/core_sha256_test.cc
  tests/core_url_test.cc
  tests/core_aead_test.cc
  tests/core_random_test.cc
)
target_link_libraries(gatehouse_tests PRIVATE
  gatehouse_core_lib
  GTest::gtest_main
  gatehouse_warnings
)
include(GoogleTest)
gtest_discover_tests(gatehouse_tests)

# ── Installation ──────────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS gatehouse DESTINATION ${CMAKE_INSTALL_SBINDIR})
# SQL migration files — read at runtime relative to WorkingDirectory=/usr/share/gatehouse
install(DIRECTORY db/ DESTINATION /usr/share/gatehouse/db
        FILES_MATCHING PATTERN "*.sql")
install(FILES data/gatehouse.service DESTINATION /lib/systemd/system/)
