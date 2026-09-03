cmake_minimum_required(VERSION 3.16)

# ============================================================
# 编译型规则引擎仓库 — 顶层构建入口
# ------------------------------------------------------------
# 两套独立的规则实现（高内聚低耦合，规则语法按引擎分目录）：
#   tools/antlr4   ANTLR4 后端（.g4 -> rulec -> .so 插件 -> engine 判定）
#   tools/ragel    Ragel 后端（.rl -> 生成 C 状态机 -> sql_scan /
#                  sqli_scan / log4j_scan 扫描判定）
# 规则文件：
#   rules/antlr4/  *.g4 规则（sql / xss / log4j / _shared 共享骨架）
#   rules/ragel/   *.rl 规则 + 共享头（sql_tokens / rule_sql / sqli_rules /
#                  log4j_lookup）
# 公共依赖：misc/（antlr jar、校验/演示脚本、设计文档）；产物 build/。
#
#   cmake -S . -B build && cmake --build build -j
#   cmake --build build --target demo             # antlr4 端到端演示
#   cmake --build build --target validate         # antlr4 sqli 规则校验
#   cmake --build build --target validate_ragel   # ragel 三套规则校验
# ============================================================

project(rule_engine LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------------------------------------------------
# 构建类型：默认 Debug（可调试）；Release 为高性能优化版
#   cmake -S . -B build
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
# ------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Release 高性能：-O3 + LTO（插件编译选项在子目录继承使用）
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(RULE_PLUGIN_OPT "-O3 -DNDEBUG -flto")
else()
    set(RULE_PLUGIN_OPT "-g -O0")
endif()

add_compile_options(-Wall -Wextra)

# ------------------------------------------------------------
# 两个后端实现（各自自带 CMakeLists，规则/实现/产物互不耦合）
# ------------------------------------------------------------
add_subdirectory(tools/antlr4)
add_subdirectory(tools/ragel)
