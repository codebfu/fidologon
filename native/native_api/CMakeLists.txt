# Shipped DLL: production core, no test hooks.
add_library(fidologon_native SHARED
  api.cpp
  resources.rc
)
target_link_libraries(fidologon_native PRIVATE fidologon_core)

# Same DLL name with the test hooks and the simulated authenticator, used only by the .NET tests.
# Built into its own folder so it can never be picked up by packaging.
add_library(fidologon_native_testing SHARED
  api.cpp
  resources.rc
)
target_link_libraries(fidologon_native_testing PRIVATE fidologon_core_testing)
set_target_properties(fidologon_native_testing PROPERTIES
  OUTPUT_NAME "fidologon_native"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native_api_testing"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native_api_testing"
  PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native_api_testing")

foreach(target fidologon_native fidologon_native_testing)
  target_include_directories(${target}
    PUBLIC include
    PRIVATE ${CMAKE_SOURCE_DIR}/common ${CMAKE_BINARY_DIR}/generated)
endforeach()
