cmake_minimum_required(VERSION 3.16)
project(sql_ragel LANGUAGES C)

# 目录约定：
#   src/{sql,log4j,html5,js}/   词法层 + 共享片段 + 语法骨架（基础设施）
#   rules/{html5_xss,sqli}/     检测规则库（规则 .rl + 头文件 + 语料）
# 顶层构建：.rl --ragel--> C 状态机 -> libragel_sql.a
# 驱动：sql_scan + examples/{sqli,log4j,html5_xss,js}_scan
# 验证：test.sh + examples/test_{sqli,log4j,html5_xss,js}.sh
#
#   cmake -S . -B build && cmake --build build -j
#   cmake --build build --target validate_ragel

add_compile_options(-Wall -Wextra)

find_program(RAGEL ragel)
if(NOT RAGEL)
    message(FATAL_ERROR "找不到 ragel（例如 apt install ragel）")
endif()

set(SQL_DIR   ${PROJECT_SOURCE_DIR}/src/sql)
set(LOG4J_DIR ${PROJECT_SOURCE_DIR}/src/log4j)
set(HTML5_DIR ${PROJECT_SOURCE_DIR}/src/html5)
set(JS_DIR    ${PROJECT_SOURCE_DIR}/src/js)
set(HTML5_XSS_DIR ${PROJECT_SOURCE_DIR}/rules/html5_xss)
set(SQLI_DIR      ${PROJECT_SOURCE_DIR}/rules/sqli)
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
    COMMAND ${RAGEL} -C -I${SQL_DIR} -o ${GEN_DIR}/sqli_rules.c ${SQLI_DIR}/sqli_rules.rl
    DEPENDS ${SQLI_DIR}/sqli_rules.rl ${SQLI_DIR}/sqli_rules.h ${SQL_DIR}/sql_shared.rl
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
    OUTPUT ${GEN_DIR}/html5_tokens.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/html5_tokens.c ${HTML5_DIR}/html5_tokens.rl
    DEPENDS ${HTML5_DIR}/html5_tokens.rl ${HTML5_DIR}/html5_tokens.h
    COMMENT "ragel: html5_tokens.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/html5_xss_rules.c
    COMMAND ${RAGEL} -C -I${HTML5_DIR} -o ${GEN_DIR}/html5_xss_rules.c ${HTML5_XSS_DIR}/html5_xss_rules.rl
    DEPENDS ${HTML5_XSS_DIR}/html5_xss_rules.rl ${HTML5_XSS_DIR}/html5_xss_rules.h ${HTML5_DIR}/html5_shared.rl
    COMMENT "ragel: html5_xss_rules.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/js_tokens.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/js_tokens.c ${JS_DIR}/js_tokens.rl
    DEPENDS ${JS_DIR}/js_tokens.rl ${JS_DIR}/js_tokens.h
    COMMENT "ragel: js_tokens.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${GEN_DIR}/js_syntax.c
    COMMAND ${RAGEL} -C -o ${GEN_DIR}/js_syntax.c ${JS_DIR}/js_syntax.rl
    DEPENDS ${JS_DIR}/js_syntax.rl ${JS_DIR}/js_tokens.h ${JS_DIR}/js_shared.rl
    COMMENT "ragel: js_syntax.c"
    VERBATIM
)

# ------------------------------------------------------------
# 2. 规则库（html5_xss + sqli）+ 基础设施（src/）
# ------------------------------------------------------------
add_library(ragel_sql STATIC
    ${GEN_DIR}/sql_tokens.c
    ${GEN_DIR}/sql_syntax.c
    ${GEN_DIR}/sqli_rules.c
    ${GEN_DIR}/log4j_lookup.c
    ${GEN_DIR}/html5_tokens.c
    ${GEN_DIR}/html5_xss_rules.c
    ${GEN_DIR}/js_tokens.c
    ${GEN_DIR}/js_syntax.c
    ${JS_DIR}/js_danger.c
)
target_include_directories(ragel_sql
    PUBLIC ${SQL_DIR} ${LOG4J_DIR} ${HTML5_DIR} ${JS_DIR}
           ${HTML5_XSS_DIR} ${SQLI_DIR}
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
target_include_directories(sqli_scan PRIVATE ${SQL_DIR} ${SQLI_DIR})
target_link_libraries(sqli_scan PRIVATE ragel_sql)
set_target_properties(sqli_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(log4j_scan ${PROJECT_SOURCE_DIR}/examples/log4j_scan.c)
target_include_directories(log4j_scan PRIVATE ${LOG4J_DIR})
target_link_libraries(log4j_scan PRIVATE ragel_sql)
set_target_properties(log4j_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(html5_xss_scan ${PROJECT_SOURCE_DIR}/examples/html5_xss_scan.c)
target_include_directories(html5_xss_scan PRIVATE ${HTML5_XSS_DIR} ${HTML5_DIR})
target_link_libraries(html5_xss_scan PRIVATE ragel_sql)
set_target_properties(html5_xss_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(js_scan ${PROJECT_SOURCE_DIR}/examples/js_scan.c)
target_include_directories(js_scan PRIVATE ${JS_DIR})
target_link_libraries(js_scan PRIVATE ragel_sql)
set_target_properties(js_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

# ------------------------------------------------------------
# 4. 测试
# ------------------------------------------------------------
add_custom_target(validate_ragel
    COMMAND ${PROJECT_SOURCE_DIR}/test.sh $<TARGET_FILE:sql_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_sqli.sh $<TARGET_FILE:sqli_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_log4j.sh $<TARGET_FILE:log4j_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_html5_xss.sh $<TARGET_FILE:html5_xss_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/examples/test_js.sh $<TARGET_FILE:js_scan>
    DEPENDS sql_scan sqli_scan log4j_scan html5_xss_scan js_scan
    COMMENT "validate: sql 骨架 + sqli + log4j + html5_xss + js"
    VERBATIM
)
