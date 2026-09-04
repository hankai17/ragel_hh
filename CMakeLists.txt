cmake_minimum_required(VERSION 3.16)
project(sql_ragel LANGUAGES C)

# 顶层构建：rules/{sql,log4j,xss}/*.rl --ragel--> C 状态机 -> libragel_sql.a
# 驱动：sql_scan + examples/{sqli,log4j,xss}_scan
# 验证：test.sh + examples/test_{sqli,log4j,xss}.sh
#
#   cmake -S . -B build && cmake --build build -j
#   cmake --build build --target validate_ragel

add_compile_options(-Wall -Wextra)

find_program(RAGEL ragel)
if(NOT RAGEL)
    message(FATAL_ERROR "找不到 ragel（例如 apt install ragel）")
endif()

set(SQL_DIR   ${PROJECT_SOURCE_DIR}/rules/sql)
set(LOG4J_DIR ${PROJECT_SOURCE_DIR}/rules/log4j)
set(XSS_DIR   ${PROJECT_SOURCE_DIR}/rules/xss)
set(GEN_DIR   ${CMAKE_BINARY_DIR}/ragel/gen)
set(BIN_DIR   ${CMAKE_BINARY_DIR}/ragel)
file(MAKE_DIRECTORY ${GEN_DIR})

# ------------------------------------------------------------
# 1. ragel 生成：.rl -> .c（中间产物，只进 build/）
# ------------------------------------------------------------
add_custom_command(
    OUTPUT ${GEN_DIR}/sql_tokens.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/sql_tokens.c ${SQL_DIR}/sql_tokens.rl
    DEPENDS ${SQL_DIR}/sql_tokens.rl ${SQL_DIR}/sql_tokens.h
    COMMENT "ragel: sql_tokens.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/sql_syntax.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/sql_syntax.c ${SQL_DIR}/sql_syntax.rl
    DEPENDS ${SQL_DIR}/sql_syntax.rl ${SQL_DIR}/sql_tokens.h ${SQL_DIR}/sql_shared.rl
    COMMENT "ragel: sql_syntax.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/sqli_rules.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/sqli_rules.c ${SQL_DIR}/sqli_rules.rl
    DEPENDS ${SQL_DIR}/sqli_rules.rl ${SQL_DIR}/sqli_rules.h ${SQL_DIR}/sql_shared.rl
    COMMENT "ragel: sqli_rules.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/log4j_lookup.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/log4j_lookup.c ${LOG4J_DIR}/log4j_lookup.rl
    DEPENDS ${LOG4J_DIR}/log4j_lookup.rl ${LOG4J_DIR}/log4j_lookup.h
    COMMENT "ragel: log4j_lookup.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/xss_tokens.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/xss_tokens.c ${XSS_DIR}/xss_tokens.rl
    DEPENDS ${XSS_DIR}/xss_tokens.rl ${XSS_DIR}/xss_tokens.h
    COMMENT "ragel: xss_tokens.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/xss_rules.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/xss_rules.c ${XSS_DIR}/xss_rules.rl
    DEPENDS ${XSS_DIR}/xss_rules.rl ${XSS_DIR}/xss_rules.h ${XSS_DIR}/xss_shared.rl
    COMMENT "ragel: xss_rules.c"
    VERBATIM
)

# ------------------------------------------------------------
# 2. 规则库（sql + log4j + xss）
# ------------------------------------------------------------
add_library(ragel_sql STATIC
    ${GEN_DIR}/sql_tokens.c
    ${GEN_DIR}/sql_syntax.c
    ${GEN_DIR}/sqli_rules.c
    ${GEN_DIR}/log4j_lookup.c
    ${GEN_DIR}/xss_tokens.c
    ${GEN_DIR}/xss_rules.c
)
target_include_directories(ragel_sql
    PUBLIC ${SQL_DIR} ${LOG4J_DIR} ${XSS_DIR}
    PRIVATE ${GEN_DIR}
)
set_target_properties(ragel_sql PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${BIN_DIR}
)

# ------------------------------------------------------------
# 3. 驱动
# ------------------------------------------------------------
add_executable(sql_scan sql_scan.c)
target_include_directories(sql_scan PRIVATE ${SQL_DIR})
target_link_libraries(sql_scan PRIVATE ragel_sql)
set_target_properties(sql_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(sqli_scan ${PROJECT_SOURCE_DIR}/examples/sqli_scan.c)
target_include_directories(sqli_scan PRIVATE ${SQL_DIR})
target_link_libraries(sqli_scan PRIVATE ragel_sql)
set_target_properties(sqli_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(log4j_scan ${PROJECT_SOURCE_DIR}/examples/log4j_scan.c)
target_include_directories(log4j_scan PRIVATE ${LOG4J_DIR})
target_link_libraries(log4j_scan PRIVATE ragel_sql)
set_target_properties(log4j_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(xss_scan ${PROJECT_SOURCE_DIR}/examples/xss_scan.c)
target_include_directories(xss_scan PRIVATE ${XSS_DIR})
target_link_libraries(xss_scan PRIVATE ragel_sql)
set_target_properties(xss_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

# ------------------------------------------------------------
# 4. 测试
# ------------------------------------------------------------
add_custom_target(validate_ragel
    COMMAND ${PROJECT_SOURCE_DIR}/test.sh $<TARGET_FILE:sql_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_sqli.sh $<TARGET_FILE:sqli_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_log4j.sh $<TARGET_FILE:log4j_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_xss.sh $<TARGET_FILE:xss_scan>
    DEPENDS sql_scan sqli_scan log4j_scan xss_scan
    COMMENT "validate: sql 骨架 + sqli + log4j + xss"
    VERBATIM
)
