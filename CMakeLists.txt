project(copycat)
cmake_minimum_required(VERSION 3.21)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include_directories("src")

file(GLOB_RECURSE SRCS "src/*.c")
file(GLOB_RECURSE HDRS "src/*.h")

add_library(${PROJECT_NAME} SHARED ${SRCS})

# install
include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}")
