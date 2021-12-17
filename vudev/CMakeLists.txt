cmake_minimum_required(VERSION 3.13)

include_directories(${VU_HEADERS})

set(VU_MOD_TARGET vudev)
file(GLOB_RECURSE VUDEV_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(${VU_MOD_TARGET} SHARED ${VUDEV_SOURCES})
set_target_properties(${VU_MOD_TARGET} PROPERTIES PREFIX "")
target_link_libraries(${VU_MOD_TARGET} stropt)

install(TARGETS ${VU_MOD_TARGET} LIBRARY DESTINATION ${MODULES_INSTALL_PATH})
