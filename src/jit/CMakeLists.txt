file(GLOB local_source
  *.h
  *.cc
)

add_library(jit ${local_source})

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(jit PRIVATE spdlog::spdlog_header_only)

find_package(LLVM CONFIG REQUIRED)
target_include_directories(jit PRIVATE ${LLVM_INCLUDE_DIRS})