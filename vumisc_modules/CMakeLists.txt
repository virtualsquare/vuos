cmake_minimum_required(VERSION 2.6)

include_directories(${VU_HEADERS} ${VU_DYN_HEADER_PATH})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

file(GLOB VUMISC_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

foreach(VUMISC_MOD ${VUMISC_MODULES})
    string(REPLACE ".c" "" VUMISC_MOD_FILE ${VUMISC_MOD})
    get_filename_component(VUMISC_MOD_TARGET ${VUMISC_MOD_FILE} NAME)
    add_library(${VUMISC_MOD_TARGET} SHARED ${VUMISC_MOD})
    set_target_properties(${VUMISC_MOD_TARGET} PROPERTIES PREFIX "")
    install(TARGETS ${VUMISC_MOD_TARGET} LIBRARY DESTINATION ${MODULES_INSTALL_PATH})
endforeach(VUMISC_MOD)

# target_link_libraries(vumiscmod modlib)
