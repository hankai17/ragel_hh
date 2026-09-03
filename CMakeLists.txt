cmake_minimum_required(VERSION 3.16)
project(sql_ragel LANGUAGES C)

# 顶层构建：rules/ragel/*.rl --ragel--> C 状态机 -> libragel_sql.a
# 驱动：sql_scan + examples/sqli_scan + examples/log4j_scan
# 验证：test.sh + examples/test_sqli.sh + examples/test_log4j.sh
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
    DEPENDS ${RULES_DIR}/rule_sql.rl ${RULES_DIR}/sql_tokens.h ${RULES_DIR}/rule_shared.rl
    COMMENT "ragel: rule_sql.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/sqli_rules.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/sqli_rules.c ${RULES_DIR}/sqli_rules.rl
    DEPENDS ${RULES_DIR}/sqli_rules.rl ${RULES_DIR}/sqli_rules.h ${RULES_DIR}/rule_shared.rl
    COMMENT "ragel: sqli_rules.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/log4j_lookup.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/log4j_lookup.c ${RULES_DIR}/log4j_lookup.rl
    DEPENDS ${RULES_DIR}/log4j_lookup.rl ${RULES_DIR}/log4j_lookup.h
    COMMENT "ragel: log4j_lookup.c"
    VERBATIM
)

# ------------------------------------------------------------
# 2. 规则库（sql_tokens + rule_sql + sqli_rules + log4j_lookup）
# ------------------------------------------------------------
add_library(ragel_sql STATIC
    ${GEN_DIR}/sql_tokens.c
    ${GEN_DIR}/rule_sql.c
    ${GEN_DIR}/sqli_rules.c
    ${GEN_DIR}/log4j_lookup.c
)
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
set_target_properties(sql_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(sqli_scan ${PROJECT_SOURCE_DIR}/examples/sqli_scan.c)
target_include_directories(sqli_scan PRIVATE ${RULES_DIR})
target_link_libraries(sqli_scan PRIVATE ragel_sql)
set_target_properties(sqli_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(log4j_scan ${PROJECT_SOURCE_DIR}/examples/log4j_scan.c)
target_include_directories(log4j_scan PRIVATE ${RULES_DIR})
target_link_libraries(log4j_scan PRIVATE ragel_sql)
set_target_properties(log4j_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

# ------------------------------------------------------------
# 4. 测试
# ------------------------------------------------------------
add_custom_target(validate_ragel
    COMMAND ${PROJECT_SOURCE_DIR}/test.sh $<TARGET_FILE:sql_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_sqli.sh $<TARGET_FILE:sqli_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_log4j.sh $<TARGET_FILE:log4j_scan>
    DEPENDS sql_scan sqli_scan log4j_scan
    COMMENT "validate: sql 骨架 + sqli + log4j"
    VERBATIM
)
