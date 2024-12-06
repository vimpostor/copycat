cmake_minimum_required(VERSION 3.21)
project(copycat VERSION 0.1)

set(LIB_TARGET "${PROJECT_NAME}")
set(BIN_TARGET "${PROJECT_NAME}-bin")

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include_directories("src/lib" "src/bin")

file(GLOB_RECURSE LIB_SRCS "src/lib/*.c")
file(GLOB_RECURSE BIN_SRCS "src/bin/*.c")

add_library(${LIB_TARGET} SHARED ${LIB_SRCS})
add_executable(${BIN_TARGET} ${BIN_SRCS})
set_target_properties(${BIN_TARGET} PROPERTIES RUNTIME_OUTPUT_NAME "${PROJECT_NAME}")
target_link_libraries(${BIN_TARGET} ${LIB_TARGET})

# install
include(GNUInstallDirs)
install(TARGETS ${LIB_TARGET})
install(TARGETS ${BIN_TARGET})
install(DIRECTORY "${CMAKE_SOURCE_DIR}/doc/man/" TYPE MAN)

# testing
if (BUILD_TESTING)
	enable_testing()
	add_subdirectory(tests)
endif()
