cmake_minimum_required(VERSION 3.7)

set(RONN_ORGANIZATION "VirtualSquare-VUOS")
set(RONN_ARGS --organization=${RONN_ORGANIZATION})

# ### ronn pages

file(GLOB VU_RONN_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.[1-8].ronn)
set(VU_MAN_FILES)
foreach(VU_RONN_PATH IN LISTS VU_RONN_PAGES)
# VU_RONNPAGE: basename of VU_RONN_PATH
	get_filename_component(VU_RONNPAGE ${VU_RONN_PATH} NAME)
# VU_MANPAGE: VU_RONNPAGE without the suffix
	string(REGEX REPLACE "\.ronn$" "" VU_MANPAGE ${VU_RONNPAGE})
	list(APPEND VU_MAN_FILES ${VU_MANPAGE})
endforeach(VU_RONN_PATH)

add_custom_target(${PROJECT_NAME}_manpages ALL make RONN_ARGS="${RONN_ARGS}"  ${VU_MAN_FILES}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

### man pages
file(GLOB VU_MAN_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.[1-8])
foreach(VU_MAN_PATH IN LISTS VU_MAN_PAGES)
	get_filename_component(VU_MANPAGE ${VU_MAN_PATH} NAME)
	string(REGEX REPLACE ".*\\." "" MAN_CHAPTER ${VU_MANPAGE})
	install(FILES ${VU_MAN_PATH} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_CHAPTER})
endforeach(VU_MAN_PATH)
