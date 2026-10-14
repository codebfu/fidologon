cmake_minimum_required(VERSION 3.25)

# Statically link the C runtime everywhere: the credential provider is loaded by
# LogonUI and must not depend on a redistributable being installed.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(fidologon_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Version stamped into the binaries' VERSIONINFO resources (set by the build script / CI).
set(FIDOLOGON_VERSION "0.0.0" CACHE STRING "Product version (major.minor.patch)")
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ver_match "${FIDOLOGON_VERSION}")
if(NOT _ver_match)
  message(FATAL_ERROR "FIDOLOGON_VERSION must look like major.minor.patch, got '${FIDOLOGON_VERSION}'")
endif()
set(FIDOLOGON_VERSION_MAJOR ${CMAKE_MATCH_1})
set(FIDOLOGON_VERSION_MINOR ${CMAKE_MATCH_2})
set(FIDOLOGON_VERSION_PATCH ${CMAKE_MATCH_3})

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
add_compile_options(/W4 /permissive- /utf-8 /guard:cf /sdl)
add_link_options(/guard:cf /DYNAMICBASE /NXCOMPAT)

# --- libfido2 and its dependencies (installed by vcpkg, x64-windows-static) ---
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_path(FIDO2_INCLUDE_DIR fido.h REQUIRED)
find_library(FIDO2_LIBRARY NAMES fido2_static fido2 REQUIRED)
find_library(CBOR_LIBRARY NAMES cbor REQUIRED)

add_library(fido2_vendor INTERFACE)
target_include_directories(fido2_vendor INTERFACE ${FIDO2_INCLUDE_DIR})
target_link_libraries(fido2_vendor INTERFACE
  ${FIDO2_LIBRARY} ${CBOR_LIBRARY} OpenSSL::Crypto ZLIB::ZLIB
  hid setupapi bcrypt webauthn ws2_32 crypt32 user32 advapi32)

configure_file(common/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/generated/version.h @ONLY)

add_subdirectory(core)
add_subdirectory(credential_provider)
add_subdirectory(native_api)
add_subdirectory(lock)

enable_testing()
add_subdirectory(tests)
