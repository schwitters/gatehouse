cmake_minimum_required(VERSION 3.24)

project(gatehouse LANGUAGES CXX)

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
  src/app/auth.cc
  src/app/email_sender.cc
  src/infra/invite_repo.cc
  src/infra/invite_session_repo.cc
  src/infra/ldif_directory.cc
  src/core/sha256.cc

  src/core/hex.cc
  src/core/random.cc
  src/core/time.cc
  src/core/url.cc

  src/infra/sqlite_db.cc
  src/infra/migrate.cc
  src/infra/session_repo.cc
  src/infra/krb5_client.cc
  src/infra/ldap_directory.cc
  src/infra/ticket_vault_read.cc
  src/infra/xrdp_otp_repo.cc
  src/infra/cred_fetch_token_repo.cc
  src/infra/ticket_vault_repo.cc
  src/core/crypto_aead.cc
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

# MIT Kerberos (pkg-config)
target_include_directories(gatehouse SYSTEM PRIVATE ${KRB5_INCLUDE_DIRS})
target_link_directories(gatehouse PRIVATE ${KRB5_LIBRARY_DIRS})
target_link_libraries(gatehouse PRIVATE ${KRB5_LIBRARIES})
target_compile_options(gatehouse PRIVATE ${KRB5_CFLAGS_OTHER})

target_link_libraries(gatehouse PRIVATE OpenSSL::Crypto)

# OpenLDAP (pkg-config)
target_include_directories(gatehouse SYSTEM PRIVATE ${LDAP_INCLUDE_DIRS})
target_link_directories(gatehouse PRIVATE ${LDAP_LIBRARY_DIRS})
target_link_libraries(gatehouse PRIVATE ${LDAP_LIBRARIES})
target_compile_options(gatehouse PRIVATE ${LDAP_CFLAGS_OTHER})
target_link_libraries(gatehouse PRIVATE CURL::libcurl)
