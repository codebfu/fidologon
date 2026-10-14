set(FIDOLOGON_CORE_SOURCES
  src/accounts.cpp
  src/attestation.cpp
  src/authenticator.cpp
  src/bytes.cpp
  src/crypto.cpp
  src/device_presence.cpp
  src/enrollment.cpp
  src/errors.cpp
  src/fido2_authenticator.cpp
  src/record_store.cpp
)

# Production library: no simulated authenticator, no test hooks.
add_library(fidologon_core STATIC ${FIDOLOGON_CORE_SOURCES})

# Test variant: adds the simulated authenticator and the hooks guarded by FIDOLOGON_TESTING.
# Never linked into shipped binaries.
add_library(fidologon_core_testing STATIC ${FIDOLOGON_CORE_SOURCES} src/fake_authenticator.cpp)
target_compile_definitions(fidologon_core_testing PUBLIC FIDOLOGON_TESTING)

foreach(target fidologon_core fidologon_core_testing)
  target_include_directories(${target} PUBLIC include)
  target_link_libraries(${target} PUBLIC fido2_vendor bcrypt advapi32 netapi32 ole32 cfgmgr32 crypt32)
endforeach()
