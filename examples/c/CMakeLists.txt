# Builds misb_dump against an installed misb (`make install`):
#
#   cmake -S examples/c -B build -DCMAKE_PREFIX_PATH=/usr/local
#   cmake --build build
#
# -DMISB_STATIC=ON links the static library instead.
cmake_minimum_required(VERSION 3.10)
project(misb_examples C)

option(MISB_STATIC "Link misb statically" OFF)
find_package(misb 0.2 REQUIRED)

add_executable(misb_dump misb_dump.c)
if(MISB_STATIC)
  target_link_libraries(misb_dump PRIVATE misb::misb_static)
else()
  target_link_libraries(misb_dump PRIVATE misb::misb)
endif()
