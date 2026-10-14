add_executable(fidologon_lock WIN32
  main.cpp
  resources.rc
)
set_target_properties(fidologon_lock PROPERTIES OUTPUT_NAME "FidoLogon.Lock")
target_include_directories(fidologon_lock PRIVATE ${CMAKE_SOURCE_DIR}/common ${CMAKE_BINARY_DIR}/generated)
target_link_libraries(fidologon_lock PRIVATE user32)
