cmake_minimum_required(VERSION 3.13)
project("vuos"
		VERSION 0.1.0
		DESCRIPTION ""
		HOMEPAGE_URL "https://github.com/virtualsquare/vuos"
		LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(LIBS_REQUIRED stropt volatilestream execs vdeplug fuse)
set(HEADERS_REQUIRED stropt.h strcase.h volatilestream.h execs.h libvdeplug.h fuse.h pthread.h)
set(CMAKE_REQUIRED_DEFINITIONS -D_FILE_OFFSET_BITS=64)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)
unset(CMAKE_REQUIRED_DEFINITIONS)

set(CMAKE_C_FLAGS
		"-ggdb -Wall -Wextra -pedantic -std=gnu11 -Wno-unused-parameter")
add_definitions(-D_GNU_SOURCE)

execute_process(COMMAND echo ${add_definitions} RESULT_VARIABLE rv)
execute_process(COMMAND pwd RESULT_VARIABLE rv)

set(MODULES_INSTALL_PATH ${CMAKE_INSTALL_FULL_LIBDIR}/vu/modules)
set(CONFIGURATION_DIR_PATH ${CMAKE_INSTALL_FULL_SYSCONFDIR})
set(HEADERS_INSTALL_PATH ${CMAKE_INSTALL_FULL_INCLUDEDIR})
set(VU_HEADERS ${PROJECT_SOURCE_DIR}/include)
set(VU_DYN_SOURCE_PATH ${CMAKE_BINARY_DIR}/umvu_dynsrc)
set(VU_DYN_HEADER_PATH ${CMAKE_BINARY_DIR}/include)

set(VU_SYSCALL_DEFS ${VU_DYN_HEADER_PATH}/syscall_defs.h)
set(R_TABLE_H ${VU_DYN_HEADER_PATH}/r_table.h)
set(VU_SYSNAMES ${VU_DYN_SOURCE_PATH}/syscall_names.c)
set(VU_ARCHTABLE ${VU_DYN_SOURCE_PATH}/arch_table.c)
set(VU_SYSTABLE ${VU_DYN_SOURCE_PATH}/syscall_table.c)
set(VU_DYN_SOURCES ${VU_SYSNAMES} ${VU_ARCHTABLE} ${VU_SYSTABLE})

execute_process(COMMAND mkdir -p ${VU_DYN_SOURCE_PATH})

foreach(DYN ${VU_DYN_SOURCES})
	execute_process(COMMAND touch -d 20000101 ${DYN})
endforeach(DYN)

configure_file( ${VU_HEADERS}/config.h.in ${VU_DYN_HEADER_PATH}/config.h )

add_subdirectory(scripts)
add_subdirectory(umvu)
add_subdirectory(cmd)
add_subdirectory(test_modules)
add_subdirectory(libvumod)
add_subdirectory(vufuse)
add_subdirectory(vudev)
add_subdirectory(vudevfuse)
add_subdirectory(include)
add_subdirectory(vunet)
add_subdirectory(vufs)
add_subdirectory(vubinfmt)
add_subdirectory(vumisc)
add_subdirectory(vunet_modules)
add_subdirectory(vufuse_modules)
add_subdirectory(vudev_modules)
add_subdirectory(vumisc_modules)
add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")
