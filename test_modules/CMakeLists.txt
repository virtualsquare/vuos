cmake_minimum_required(VERSION 3.13)

include_directories(${VU_HEADERS})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

file(GLOB VU_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

foreach(VU_MOD ${VU_MODULES})
    string(REPLACE ".c" "" VU_MOD_FILE ${VU_MOD})
    get_filename_component(VU_MOD_TARGET ${VU_MOD_FILE} NAME)
    add_library(${VU_MOD_TARGET} SHARED ${VU_MOD})
    set_target_properties(${VU_MOD_TARGET} PROPERTIES PREFIX "")
    install(TARGETS ${VU_MOD_TARGET} LIBRARY DESTINATION ${MODULES_INSTALL_PATH})
endforeach(VU_MOD)

target_link_libraries(unrealinfofs vumod)
