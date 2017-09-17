cmake_minimum_required(VERSION 2.6)

set(VU_SYSCALL_CONF ${PROJECT_SOURCE_DIR}/vu_syscalls.conf)
set(VU_SCRIPT_PATH ${PROJECT_SOURCE_DIR}/scripts)

add_custom_target(Dynamic_Sources ALL
		DEPENDS ${VU_SYSCALL_DEFS} ${VU_ARCHTABLE} ${VU_SYSTABLE} ${R_TABLE_H})
add_custom_command(OUTPUT ${VU_DYN_HEADER_PATH}
		COMMAND mkdir ${VU_DYN_HEADER_PATH})
add_custom_command(OUTPUT ${VU_DYN_SOURCE_PATH}
		COMMAND mkdir ${VU_DYN_SOURCE_PATH})

# syscall_defs.h
add_custom_command(OUTPUT ${VU_SYSCALL_DEFS}
		COMMAND ${VU_SCRIPT_PATH}/syscall_defs_gen.py ${VU_SYSCALL_CONF} > ${VU_SYSCALL_DEFS}
		COMMENT "Populating VU syscall list"
		DEPENDS ${VU_SYSCALL_CONF} ${VU_DYN_HEADER_PATH})

# syscall_table.c
add_custom_command(OUTPUT ${R_TABLE_H}
		COMMAND ${VU_SCRIPT_PATH}/r_table_gen.py > ${R_TABLE_H}
		COMMENT "Generating r_table"
		DEPENDS ${VU_DYN_HEADER_PATH})

# arch_table.c
add_custom_command(OUTPUT ${VU_ARCHTABLE}
		COMMAND ${VU_SCRIPT_PATH}/archtable_gen.py ${ARCH} ${VU_SYSCALL_CONF} > ${VU_ARCHTABLE}
		COMMENT "Generating architecture table"
		DEPENDS ${VU_SYSCALL_CONF} ${VU_DYN_SOURCE_PATH})

# syscall_table.c
add_custom_command(OUTPUT ${VU_SYSTABLE}
		COMMAND ${VU_SCRIPT_PATH}/syscall_table_gen.py ${VU_SYSCALL_CONF} > ${VU_SYSTABLE}
		COMMENT "Generating VU syscall table"
		DEPENDS ${VU_SYSCALL_CONF} ${VU_DYN_SOURCE_PATH})
