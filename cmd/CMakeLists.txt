cmake_minimum_required(VERSION 2.6)

include_directories(${VU_HEADERS})
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

file(GLOB VU_CMDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

foreach(VU_CMD ${VU_CMDS})
    string(REPLACE ".c" "" VU_CMD_FILE ${VU_CMD})
		get_filename_component(VU_CMD_TARGET ${VU_CMD_FILE} NAME)
    add_executable(${VU_CMD_TARGET} ${VU_CMD})
    install(TARGETS ${VU_CMD_TARGET} RUNTIME DESTINATION bin)
endforeach(VU_CMD)

target_link_libraries(vumount stropt)
target_link_libraries(vustack stropt)
