cmake_minimum_required(VERSION 3.16)
project(sql_ragel LANGUAGES C)

# 顶层构建：rules/ragel/*.rl --ragel--> C 状态机 -> libragel_sql.a
# sql_scan 链接库并跑 test.sh 验证
#
#   cmake -S . -B build && cmake --build build -j
#   cmake --build build --target validate_ragel

add_compile_options(-Wall -Wextra)

find_program(RAGEL ragel)
if(NOT RAGEL)
    message(FATAL_ERROR "找不到 ragel（例如 apt install ragel）")
endif()

set(RULES_DIR ${PROJECT_SOURCE_DIR}/rules/ragel)
set(GEN_DIR   ${CMAKE_BINARY_DIR}/ragel/gen)
set(BIN_DIR   ${CMAKE_BINARY_DIR}/ragel)
file(MAKE_DIRECTORY ${GEN_DIR})

# ------------------------------------------------------------
# 1. ragel 生成：.rl -> .c（中间产物，只进 build/）
# ------------------------------------------------------------
add_custom_command(
    OUTPUT ${GEN_DIR}/sql_tokens.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/sql_tokens.c ${RULES_DIR}/sql_tokens.rl
    DEPENDS ${RULES_DIR}/sql_tokens.rl ${RULES_DIR}/sql_tokens.h
    COMMENT "ragel: sql_tokens.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/rule_sql.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/rule_sql.c ${RULES_DIR}/rule_sql.rl
    DEPENDS ${RULES_DIR}/rule_sql.rl ${RULES_DIR}/sql_tokens.h
    COMMENT "ragel: rule_sql.c"
    VERBATIM
)

# ------------------------------------------------------------
# 2. 规则库（sql_tokens + rule_sql）
# ------------------------------------------------------------
add_library(ragel_sql STATIC ${GEN_DIR}/sql_tokens.c ${GEN_DIR}/rule_sql.c)
target_include_directories(ragel_sql
    PUBLIC ${RULES_DIR}
    PRIVATE ${GEN_DIR}
)
set_target_properties(ragel_sql PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${BIN_DIR}
)

# ------------------------------------------------------------
# 3. 驱动
# ------------------------------------------------------------
add_executable(sql_scan sql_scan.c)
target_include_directories(sql_scan PRIVATE ${RULES_DIR})
target_link_libraries(sql_scan PRIVATE ragel_sql)
set_target_properties(sql_scan PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
)

# ------------------------------------------------------------
# 4. 测试
# ------------------------------------------------------------
add_custom_target(validate_ragel
    COMMAND ${PROJECT_SOURCE_DIR}/test.sh $<TARGET_FILE:sql_scan>
    DEPENDS sql_scan
    COMMENT "validate: sql_tokens + rule_sql"
    VERBATIM
)
