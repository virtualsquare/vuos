cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=314")

include_directories(${VU_HEADERS} ${CMAKE_CURRENT_SOURCE_DIR})

set(VU_MOD_TARGET vufuse)
file(GLOB_RECURSE VUFUSE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(${VU_MOD_TARGET} SHARED ${VUFUSE_SOURCES})
set_target_properties(${VU_MOD_TARGET} PROPERTIES PREFIX "")
target_link_libraries(${VU_MOD_TARGET} stropt volatilestream execs)

install(TARGETS ${VU_MOD_TARGET} LIBRARY DESTINATION ${MODULES_INSTALL_PATH})
