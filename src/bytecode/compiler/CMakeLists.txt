file(GLOB local_source
  *.h
  *.cc
)

add_library(compiler ${local_source})

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(compiler PRIVATE spdlog::spdlog_header_only)