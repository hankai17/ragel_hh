cmake_minimum_required(VERSION 3.16)

# ============================================================
# Ragel 规则引擎 — 顶层构建入口（项目以 Ragel 为主）
# ------------------------------------------------------------
# 规则唯一真源：rules/ragel/（.rl + 契约头）
#   sql_tokens     词法                 -> lex_sql()
#   rule_sql       SQL 表达式/语句骨架   -> sql_match_expr/select/const + 语义谓词
#   sqli_rules     24 条 SQLi 攻击规则   -> sql_match_sqli_*()
#   log4j_lookup   log4j ${...} 识别     -> log4j_scan()
#
# 构建期用 ragel 把 .rl 生成 C 状态机（中间产物，仅存 build/，不入库），
# 再编成两个规则库，供调用方（含本仓库驱动）链接：
#   libragel_sql.a    sql_tokens + rule_sql + sqli_rules（SQL 检测）
#   libragel_log4j.a  log4j_lookup（log4j 检测）
# 契约头（rules/ragel/*.h）随库发布：调用方 include 头 + 链接库即可，
# 不需要 ragel、不需要接触任何生成物 —— 即"规则怎么给别人调用"的答案：
#   给别人 = 库 + 头文件；给开发 = .rl（唯一真源）。
#
# 驱动 / 自测（dogfooding，链接上面的库）：
#   sql_scan   词法 + 骨架扫描
#   sqli_scan  24 条规则全量扫描（位于 rules/ragel/sqli_scan.c）
#   log4j_scan log4j 查找分类
#
#   cmake -S . -B build && cmake --build build -j
#   cmake --build build --target validate_ragel
# 也可直接 make（等价产物，见 Makefile）。
# ============================================================

project(rule_engine LANGUAGES C)

# 构建类型：默认 Debug；Release 用 -O3
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

add_compile_options(-Wall -Wextra)

# ------------------------------------------------------------
# 依赖：ragel
# ------------------------------------------------------------
find_program(RAGEL ragel)
if(NOT RAGEL)
    message(FATAL_ERROR
        "ragel not found — install it (e.g. apt install ragel)")
endif()

# 可选：把规则库编成动态库（.so/.dylib）而非静态库
option(RAGEL_BUILD_SHARED "build ragel rule libs as shared libraries" OFF)

# ------------------------------------------------------------
# 目录约定
# ------------------------------------------------------------
set(RAGEL_RULES_DIR ${PROJECT_SOURCE_DIR}/rules/ragel)
set(RAGEL_GEN_DIR  ${CMAKE_BINARY_DIR}/ragel/gen)   # .rl 生成的中间 C
set(RAGEL_BIN_DIR  ${CMAKE_BINARY_DIR}/ragel)       # 可执行 + 库产物
file(MAKE_DIRECTORY ${RAGEL_GEN_DIR})

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
# 规则库（对外交付主体：.rl 生成物 + 契约头打包）
# ------------------------------------------------------------
if(RAGEL_BUILD_SHARED)
    set(RAGEL_SQL_TYPE    SHARED)
    set(RAGEL_LOG4J_TYPE  SHARED)
else()
    set(RAGEL_SQL_TYPE    STATIC)
    set(RAGEL_LOG4J_TYPE  STATIC)
endif()

add_library(ragel_sql ${RAGEL_SQL_TYPE}
    ${RAGEL_GEN_DIR}/sql_tokens.c
    ${RAGEL_GEN_DIR}/rule_sql.c
    ${RAGEL_GEN_DIR}/sqli_rules.c
)
# PUBLIC include：把契约头所在 rules/ragel 传给调用方
target_include_directories(ragel_sql
    PUBLIC ${RAGEL_RULES_DIR}
    PRIVATE ${RAGEL_GEN_DIR}
)

add_library(ragel_log4j ${RAGEL_LOG4J_TYPE}
    ${RAGEL_GEN_DIR}/log4j_lookup.c
)
target_include_directories(ragel_log4j
    PUBLIC ${RAGEL_RULES_DIR}
    PRIVATE ${RAGEL_GEN_DIR}
)

set_target_properties(ragel_sql ragel_log4j PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${RAGEL_BIN_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${RAGEL_BIN_DIR}
)

# ------------------------------------------------------------
# 驱动（示例调用方，链接规则库验证可发布性）
# ------------------------------------------------------------
add_executable(sql_scan sql_scan.c)
target_include_directories(sql_scan PRIVATE ${RAGEL_RULES_DIR})
target_link_libraries(sql_scan PRIVATE ragel_sql)

add_executable(sqli_scan ${RAGEL_RULES_DIR}/sqli_scan.c)
target_include_directories(sqli_scan PRIVATE ${RAGEL_RULES_DIR})
target_link_libraries(sqli_scan PRIVATE ragel_sql)

add_executable(log4j_scan log4j_scan.c)
target_include_directories(log4j_scan PRIVATE ${RAGEL_RULES_DIR})
target_link_libraries(log4j_scan PRIVATE ragel_log4j)

set_target_properties(sql_scan sqli_scan log4j_scan PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${RAGEL_BIN_DIR}
)

# ------------------------------------------------------------
# 规则校验（根目录 test*.sh）
# ------------------------------------------------------------
add_custom_target(validate_ragel
    COMMAND ${PROJECT_SOURCE_DIR}/test.sh        $<TARGET_FILE:sql_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/test_sqli.sh   $<TARGET_FILE:sqli_scan>
    COMMAND ${PROJECT_SOURCE_DIR}/test_log4j.sh  $<TARGET_FILE:log4j_scan>
    DEPENDS sql_scan sqli_scan log4j_scan
    COMMENT "validate ragel rules (skeleton / sqli 24 / log4j)"
    VERBATIM
)

# ------------------------------------------------------------
# 安装（对外发布：include + lib）
#   cmake --install build --prefix /usr/local
# ------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ragel_sql ragel_log4j
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES
    ${RAGEL_RULES_DIR}/sql_tokens.h
    ${RAGEL_RULES_DIR}/rule_sql.h
    ${RAGEL_RULES_DIR}/sqli_rules.h
    ${RAGEL_RULES_DIR}/log4j_lookup.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ragel_rules
)
