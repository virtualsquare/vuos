cmake_minimum_required(VERSION 2.6)

include_directories(${VU_HEADERS})

set(VU_MOD_TARGET vumisc)
file(GLOB_RECURSE VUMISC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(${VU_MOD_TARGET} SHARED ${VUMISC_SOURCES})
set_target_properties(${VU_MOD_TARGET} PROPERTIES PREFIX "")

target_link_libraries(${VU_MOD_TARGET} vumod)

install(TARGETS ${VU_MOD_TARGET} LIBRARY DESTINATION ${MODULES_INSTALL_PATH})
