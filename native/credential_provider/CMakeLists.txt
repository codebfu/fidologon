set(FIDOLOGON_CP_SOURCES
  common.cpp
  credential.cpp
  filter.cpp
  kerb_logon.cpp
  provider.cpp
)

# Logic shared by the DLL and the tests (production and test variants, see core/CMakeLists.txt).
add_library(fidologon_cp_impl STATIC ${FIDOLOGON_CP_SOURCES})
target_link_libraries(fidologon_cp_impl PUBLIC fidologon_core)
add_library(fidologon_cp_impl_testing STATIC ${FIDOLOGON_CP_SOURCES})
target_link_libraries(fidologon_cp_impl_testing PUBLIC fidologon_core_testing)
foreach(target fidologon_cp_impl fidologon_cp_impl_testing)
  target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${target} PUBLIC secur32 credui ole32 uuid cfgmgr32)
endforeach()

add_library(fidologon_cp SHARED
  dll.cpp
  exports.def
  resources.rc
)
set_target_properties(fidologon_cp PROPERTIES OUTPUT_NAME "FidoLogonCredentialProvider")
# The resource compiler does not report the bitmaps it embeds: rebuild when the tile image changes.
set_source_files_properties(resources.rc PROPERTIES OBJECT_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tile_image.bmp;${CMAKE_CURRENT_SOURCE_DIR}/tile_image.png")
target_include_directories(fidologon_cp PRIVATE
  ${CMAKE_SOURCE_DIR}/common
  ${CMAKE_BINARY_DIR}/generated)
target_link_libraries(fidologon_cp PRIVATE fidologon_cp_impl)
