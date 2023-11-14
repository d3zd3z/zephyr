# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(hello_world)

target_sources(app PRIVATE src/main.c)

set(BUILD_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/target/thumbv7em-none-eabi/debug)

# Using ExternalProject from cmake isn't particularly useful, since the only real functionality we
# want out of it is to invoke a build program, which it would like to be make.

set(CARGO_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust/target-hello)
set(RUST_LIBRARY ${CARGO_TARGET_DIR}/thumbv7em-none-eabi/release/librust_hello.a)

add_custom_command(
  OUTPUT ${RUST_LIBRARY}
  COMMAND cargo build --release
    --target thumbv7em-none-eabi
    --target-dir ${CARGO_TARGET_DIR}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(
  librust_hello ALL
  DEPENDS ${RUST_LIBRARY}
)

add_dependencies(app librust_hello)
target_link_libraries(app PUBLIC ${RUST_LIBRARY})
