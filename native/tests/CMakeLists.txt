add_executable(fidologon_tests
  main.cpp
  test_credential_provider.cpp
  test_attestation.cpp
  test_crypto.cpp
  test_enrollment.cpp
  test_store.cpp
)
target_link_libraries(fidologon_tests PRIVATE fidologon_cp_impl_testing)
add_dependencies(fidologon_tests fidologon_cp)

add_test(NAME fidologon_tests COMMAND fidologon_tests $<TARGET_FILE:fidologon_cp>)
