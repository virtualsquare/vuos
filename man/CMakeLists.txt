cmake_minimum_required(VERSION 3.7)

set (RONN_ORGANIZATION "VirtualSquare")
set (ROFF_COMMENT "^\.\\\\\"")

### ronn pages
unset(RONN CACHE)
find_program(RONN ronn)
if(NOT RONN)
	message(WARNING "ronn is missing: man pages will not be created")
else(NOT RONN)

	file(GLOB VU_RONN_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.[1-8].ronn)
	set(VU_MAN_FILES)
	foreach(VU_RONN_PATH IN LISTS VU_RONN_PAGES)
# VU_RONNPAGE: basename of VU_RONN_PATH
		get_filename_component(VU_RONNPAGE ${VU_RONN_PATH} NAME)
# VU_MANPAGE: VU_RONNPAGE without the suffix
		string(REGEX REPLACE "\.ronn$" "" VU_MANPAGE ${VU_RONNPAGE})
# VU_BUILD_NAMEPAGE path of the manpage in the build hierarchy
		set(VU_BUILD_NAMEPAGE ${CMAKE_CURRENT_BINARY_DIR}/${VU_MANPAGE})
# create the man page (prepend comments: include licence)
		add_custom_command(OUTPUT ${VU_BUILD_NAMEPAGE}
			COMMAND grep "${ROFF_COMMENT}" ${VU_RONN_PATH} > ${VU_BUILD_NAMEPAGE} || exit 0
			COMMAND ronn -r --organization=${RONN_ORGANIZATION} --pipe ${VU_RONN_PATH} >> ${VU_BUILD_NAMEPAGE}
			DEPENDS ${VU_RONN_PATH}
    	COMMENT "Building manpage ${VU_MANPAGE}"
			VERBATIM)
		list(APPEND MAN_FILES ${VU_BUILD_NAMEPAGE})
	endforeach(VU_RONN_PATH)

	add_custom_target(${PROJECT_NAME}_man ALL DEPENDS ${MAN_FILES})

	foreach(MAN_CHAPTER IN ITEMS 1 2 3 4 5 6 7 8)
# split the MAN_FILES in chapter lists
		set(MAN_FILES_CHAPTER ${MAN_FILES})
		list(FILTER MAN_FILES_CHAPTER INCLUDE REGEX "\\.${MAN_CHAPTER}$")
		install(FILES ${MAN_FILES_CHAPTER} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_CHAPTER})
	endforeach(MAN_CHAPTER)

endif(NOT RONN)

### man pages
file(GLOB VU_MAN_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.[1-8])
foreach(VU_MAN_PATH IN LISTS VU_MAN_PAGES)
# do not install placeholders of ronn-generated pages (target of symlinks)
	if(NOT EXISTS ${VU_MAN_PATH}.ronn)
# VU_MANPAGE is the basename of VU_MAN_PATH
		get_filename_component(VU_MANPAGE ${VU_MAN_PATH} NAME)
		string(REGEX REPLACE ".*\\." "" MAN_CHAPTER ${VU_MANPAGE})
		install(FILES ${VU_MAN_PATH} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${MAN_CHAPTER})
	endif()
endforeach(VU_MAN_PATH)
