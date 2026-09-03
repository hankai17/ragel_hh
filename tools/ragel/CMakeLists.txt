# ============================================================
# Ragel 后端构建（tools/ragel/）— 由顶层 add_subdirectory 引入
# ------------------------------------------------------------
# 组件：
#   sql_scan    SQLTokens + RuleSQL 骨架扫描（规则代表 8 条）
#   sqli_scan   sqli_rules 24 条攻击规则全量扫描（对齐 ANTLR 语义）
#   log4j_scan  log4j 查找表达式分类扫描（JNDI/SENSITIVE/CHAIN/EXPR）
#   validate_ragel  三套规则校验（test.sh / test_sqli.sh / test_log4j.sh）
#
# 布局约定：
#   规则源（rl + 共享头） 顶层 rules/ragel/（生成 .c 亦源于此）
#   驱动 / 测试脚本       本目录 tools/ragel/
#   生成物 / 二进制       顶层 build/ragel/（gen/ + 可执行）
# 也可直接 cd tools/ragel && make（输出同目录，二者产物一致）。
# ============================================================

find_program(RAGEL ragel)
if(NOT RAGEL)
    message(WARNING
        "ragel not found — skipping Ragel targets (sql_scan/sqli_scan/"
        "log4j_scan/validate_ragel). Install ragel, or run: "
        "cd tools/ragel && make")
    return()
endif()

set(RAGEL_RULES_DIR ${PROJECT_SOURCE_DIR}/rules/ragel)
set(RAGEL_GEN_DIR ${CMAKE_BINARY_DIR}/ragel/gen)
set(RAGEL_BIN_DIR ${CMAKE_BINARY_DIR}/ragel)

file(MAKE_DIRECTORY ${RAGEL_GEN_DIR})

set(RAGEL_CFLAGS -O2 -Wall -Wextra)

# ------------------------------------------------------------
# 生成：rules/ragel/*.rl -> build/ragel/gen/*.c
# ------------------------------------------------------------
add_custom_command(
    OUTPUT ${RAGEL_GEN_DIR}/sql_tokens.c
    COMMAND ${RAGEL} -C -o ${RAGEL_GEN_DIR}/sql_tokens.c
            ${RAGEL_RULES_DIR}/sql_tokens.rl
    DEPENDS ${RAGEL_RULES_DIR}/sql_tokens.rl ${RAGEL_RULES_DIR}/sql_tokens.h
    COMMENT "ragel generate sql_tokens.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${RAGEL_GEN_DIR}/rule_sql.c
    COMMAND ${RAGEL} -C -o ${RAGEL_GEN_DIR}/rule_sql.c
            ${RAGEL_RULES_DIR}/rule_sql.rl
    DEPENDS ${RAGEL_RULES_DIR}/rule_sql.rl ${RAGEL_RULES_DIR}/sql_tokens.h
    COMMENT "ragel generate rule_sql.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${RAGEL_GEN_DIR}/sqli_rules.c
    COMMAND ${RAGEL} -C -o ${RAGEL_GEN_DIR}/sqli_rules.c
            ${RAGEL_RULES_DIR}/sqli_rules.rl
    DEPENDS ${RAGEL_RULES_DIR}/sqli_rules.rl ${RAGEL_RULES_DIR}/sql_tokens.h
    COMMENT "ragel generate sqli_rules.c"
    VERBATIM
)
add_custom_command(
    OUTPUT ${RAGEL_GEN_DIR}/log4j_lookup.c
    COMMAND ${RAGEL} -C -o ${RAGEL_GEN_DIR}/log4j_lookup.c
            ${RAGEL_RULES_DIR}/log4j_lookup.rl
    DEPENDS ${RAGEL_RULES_DIR}/log4j_lookup.rl ${RAGEL_RULES_DIR}/log4j_lookup.h
    COMMENT "ragel generate log4j_lookup.c"
    VERBATIM
)

# ------------------------------------------------------------
# 扫描器可执行（二进制统一输出到 build/ragel/）
# ------------------------------------------------------------
add_executable(sql_scan
    ${CMAKE_CURRENT_SOURCE_DIR}/sql_scan.c
    ${RAGEL_GEN_DIR}/sql_tokens.c
    ${RAGEL_GEN_DIR}/rule_sql.c
)
set_target_properties(sql_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${RAGEL_BIN_DIR})
target_include_directories(sql_scan PRIVATE ${RAGEL_RULES_DIR} ${RAGEL_GEN_DIR})

add_executable(sqli_scan
    ${CMAKE_CURRENT_SOURCE_DIR}/sqli_scan.c
    ${RAGEL_GEN_DIR}/sql_tokens.c
    ${RAGEL_GEN_DIR}/rule_sql.c
    ${RAGEL_GEN_DIR}/sqli_rules.c
)
set_target_properties(sqli_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${RAGEL_BIN_DIR})
target_include_directories(sqli_scan PRIVATE ${RAGEL_RULES_DIR} ${RAGEL_GEN_DIR})

add_executable(log4j_scan
    ${CMAKE_CURRENT_SOURCE_DIR}/log4j_scan.c
    ${RAGEL_GEN_DIR}/log4j_lookup.c
)
set_target_properties(log4j_scan PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${RAGEL_BIN_DIR})
target_include_directories(log4j_scan PRIVATE ${RAGEL_RULES_DIR} ${RAGEL_GEN_DIR})

# ------------------------------------------------------------
# 规则校验（对齐 ANTLR 侧 misc/*.sh 的断言语料）
# ------------------------------------------------------------
add_custom_target(validate_ragel
    COMMAND ${PROJECT_SOURCE_DIR}/tools/ragel/test.sh
            $<TARGET_FILE:sql_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/tools/ragel/test_sqli.sh
            $<TARGET_FILE:sqli_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/tools/ragel/test_log4j.sh
            $<TARGET_FILE:log4j_scan>
    DEPENDS sql_scan sqli_scan log4j_scan
    COMMENT "validate ragel rules (RuleSQL skeleton / sqli 24 / log4j)"
    VERBATIM
)
