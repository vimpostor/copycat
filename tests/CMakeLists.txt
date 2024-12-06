add_executable(tests tests_general.c)

add_executable(benchmark benchmark.c)
target_link_libraries(benchmark m)

add_test(NAME test COMMAND "${BIN_TARGET}" -- $<TARGET_FILE:tests>)
set_property(TEST test PROPERTY ENVIRONMENT "COPYCAT=/tmp/a /tmp/b")
