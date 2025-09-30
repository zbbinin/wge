file(GLOB local_source
  *.h
  *.cc
)

add_library(jit_compiler ${local_source})

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(jit_compiler PRIVATE spdlog::spdlog_header_only)

find_package(LLVM CONFIG REQUIRED)
target_include_directories(jit_compiler PRIVATE ${LLVM_INCLUDE_DIRS})