cmake_minimum_required(VERSION 3.13)

include_directories(${VU_HEADERS} ${VU_DYN_HEADER_PATH})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

file(GLOB VUNET_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

foreach(VUNET_MOD ${VUNET_MODULES})
    string(REGEX REPLACE "\.c$" "" VUNET_MOD_FILE ${VUNET_MOD})
    get_filename_component(VUNET_MOD_TARGET ${VUNET_MOD_FILE} NAME)
    add_library(${VUNET_MOD_TARGET} SHARED ${VUNET_MOD})
    set_target_properties(${VUNET_MOD_TARGET} PROPERTIES PREFIX "")
    install(TARGETS ${VUNET_MOD_TARGET} LIBRARY DESTINATION ${MODULES_INSTALL_PATH})
endforeach(VUNET_MOD)

target_link_libraries(vunetvdestack vdeplug)
