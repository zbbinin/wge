file(GLOB local_source
  *.h
  *.cc
)

add_library(bytecode ${local_source})

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(bytecode PRIVATE spdlog::spdlog_header_only)