file(GLOB local_source
  *.h
  *.cc
)

add_library(jit ${local_source})

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(jit PRIVATE spdlog::spdlog_header_only)