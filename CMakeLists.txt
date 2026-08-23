cmake_minimum_required(VERSION 3.16)

project(rule_engine LANGUAGES C CXX)

# ------------------------------------------------------------
# 全局编译选项
# ------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------------------------------------------------
# 构建类型：默认 Debug（可调试）；Release 为高性能优化版
#   cmake -S . -B build                     # Debug（默认）
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
# ------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Release 高性能：-O3 + LTO（引擎/编译器）
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(RULE_PLUGIN_OPT "-O3 -DNDEBUG -flto")
else()
    set(RULE_PLUGIN_OPT "-g -O0")
endif()

add_compile_options(-Wall -Wextra)

# ------------------------------------------------------------
# ANTLR4 C++ 运行时
# find_path/find_library 按 CMake 标准前缀自动搜索
# （/usr、/usr/local 等）；如需指定安装位置用
#   cmake -DANTLR4_RUNTIME_DIR=/opt/antlr ...
# ------------------------------------------------------------

set(ANTLR4_RUNTIME_DIR "" CACHE PATH "ANTLR4 C++ runtime install prefix (optional)")

if(ANTLR4_RUNTIME_DIR)
    # 显式指定前缀：只在该前缀下查找
    find_path(ANTLR4_RUNTIME_INC_FOUND
        antlr4-runtime.h
        HINTS ${ANTLR4_RUNTIME_DIR}/include
        PATH_SUFFIXES antlr4-runtime
        NO_DEFAULT_PATH)
    find_library(ANTLR4_RUNTIME_LIB_FOUND
        antlr4-runtime
        HINTS ${ANTLR4_RUNTIME_DIR}/lib
        NO_DEFAULT_PATH)
else()
    # 默认：按 CMake 标准前缀搜索（/usr、/usr/local 等）
    find_path(ANTLR4_RUNTIME_INC_FOUND
        antlr4-runtime.h
        PATH_SUFFIXES antlr4-runtime)
    find_library(ANTLR4_RUNTIME_LIB_FOUND antlr4-runtime)
endif()

if(NOT ANTLR4_RUNTIME_INC_FOUND OR NOT ANTLR4_RUNTIME_LIB_FOUND)
    message(FATAL_ERROR
        "ANTLR4 C++ runtime not found under /usr, /usr/local. "
        "Install it or pass -DANTLR4_RUNTIME_DIR=<prefix>")
endif()

get_filename_component(ANTLR4_RUNTIME_LIB_DIR_FOUND
    ${ANTLR4_RUNTIME_LIB_FOUND} DIRECTORY)

include_directories(${ANTLR4_RUNTIME_INC_FOUND} ${CMAKE_CURRENT_SOURCE_DIR})
link_directories(${ANTLR4_RUNTIME_LIB_DIR_FOUND})
set(CMAKE_BUILD_RPATH ${ANTLR4_RUNTIME_LIB_DIR_FOUND})

# ------------------------------------------------------------
# ANTLR 生成：MiniSQL 解析器（构建时自动生成，不入库）
# ------------------------------------------------------------

find_program(JAVA_EXECUTABLE java)
if(NOT JAVA_EXECUTABLE)
    message(FATAL_ERROR
        "java not found — required to generate ANTLR parsers at build time")
endif()

set(MINISQL_GEN_DIR ${CMAKE_BINARY_DIR}/gen/minisql)
set(MINISQL_GEN_SOURCES
    ${MINISQL_GEN_DIR}/MiniSQLLexer.cpp
    ${MINISQL_GEN_DIR}/MiniSQLParser.cpp
)

add_custom_command(
    OUTPUT ${MINISQL_GEN_SOURCES}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${MINISQL_GEN_DIR}
    COMMAND ${JAVA_EXECUTABLE} -jar
            ${CMAKE_CURRENT_SOURCE_DIR}/misc/antlr-4.13.2-complete.jar
            -Dlanguage=Cpp -no-listener -o ${MINISQL_GEN_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/MiniSQL.g4
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/MiniSQL.g4
            ${CMAKE_CURRENT_SOURCE_DIR}/misc/antlr-4.13.2-complete.jar
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "generate MiniSQL lexer/parser (ANTLR)"
    VERBATIM
)

# ------------------------------------------------------------
# 目标 1：主引擎
# ------------------------------------------------------------

add_executable(engine
    engine.cc
    ${MINISQL_GEN_SOURCES}
)
set_property(TARGET engine
    PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
target_include_directories(engine PRIVATE ${MINISQL_GEN_DIR})
target_link_libraries(engine PRIVATE antlr4-runtime ${CMAKE_DL_LIBS})

# ------------------------------------------------------------
# 目标 2：规则编译器 rulec
# ------------------------------------------------------------

add_executable(rulec
    rule_compiler.cc
)
set_property(TARGET rulec
    PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
target_link_libraries(rulec PRIVATE antlr4-runtime)

# ------------------------------------------------------------
# 目标 3：规则插件（每条 .g4 编译为独立 .so）
# ------------------------------------------------------------

file(GLOB RULE_FILES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/sqli/*.g4
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/xss/*.g4
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/log4j/*.g4
)

file(GLOB SHARED_G4 CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/_shared/*.g4
)

set(PLUGIN_OUT_DIR ${CMAKE_BINARY_DIR}/plugins)
file(MAKE_DIRECTORY ${PLUGIN_OUT_DIR})

set(PLUGIN_SOS "")
foreach(rule_file ${RULE_FILES})
    get_filename_component(rule_name ${rule_file} NAME_WE)
    set(plugin_so ${PLUGIN_OUT_DIR}/lib${rule_name}.so)
    add_custom_command(
        OUTPUT ${plugin_so}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${PLUGIN_OUT_DIR}
        COMMAND $<TARGET_FILE:rulec>
                --include ${CMAKE_CURRENT_SOURCE_DIR}
                -o ${PLUGIN_OUT_DIR}
                --antlr-jar ${CMAKE_CURRENT_SOURCE_DIR}/misc/antlr-4.13.2-complete.jar
                --antlr-inc ${ANTLR4_RUNTIME_INC_FOUND}
                --antlr-lib ${ANTLR4_RUNTIME_LIB_DIR_FOUND}
                --shared-dir ${CMAKE_CURRENT_SOURCE_DIR}/rules/_shared
                --plugin-opt "${RULE_PLUGIN_OPT}"
                ${rule_file}
        DEPENDS rulec
                ${rule_file}
                ${CMAKE_CURRENT_SOURCE_DIR}/rule_plugin.h
                ${SHARED_G4}
        COMMENT "compile rule ${rule_file} -> ${plugin_so}"
        VERBATIM
    )
    list(APPEND PLUGIN_SOS ${plugin_so})
endforeach()

add_custom_target(plugins ALL DEPENDS ${PLUGIN_SOS})

# ------------------------------------------------------------
# 目标 4：端到端演示
# ------------------------------------------------------------

add_custom_target(demo
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/misc/demo.sh
            $<TARGET_FILE:engine>
            ${PLUGIN_OUT_DIR}
    DEPENDS engine plugins
    COMMENT "run end-to-end demo (benign / SQLi / XSS samples)"
    VERBATIM
)

# ------------------------------------------------------------
# 目标 5：规则校验（正/负样本断言）
# ------------------------------------------------------------

add_custom_target(validate
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/misc/validate_sqli.sh
            $<TARGET_FILE:engine>
            ${PLUGIN_OUT_DIR}
    DEPENDS engine plugins
    COMMENT "validate sqli rules against positive/negative samples"
    VERBATIM
)

# ------------------------------------------------------------
# 目标 5b：log4j 规则校验 + 正则对比
# ------------------------------------------------------------

add_custom_target(validate_log4j
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/misc/validate_log4j.sh
            $<TARGET_FILE:engine>
            ${PLUGIN_OUT_DIR}
    DEPENDS engine plugins
    COMMENT "validate log4j rules against positive/negative samples"
    VERBATIM
)

add_custom_target(compare_log4j
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/misc/compare_log4j_regex.sh
            $<TARGET_FILE:engine>
            ${PLUGIN_OUT_DIR}
    DEPENDS engine plugins
    COMMENT "compare log4j rules vs typical WAF regex signatures"
    VERBATIM
)

# ------------------------------------------------------------
# 目标 6：最小动态库调用示例（纯 C，dlopen 调用插件接口）
#   运行：./build/example_call_plugin [可选测试串]
# ------------------------------------------------------------

add_executable(example_call_plugin examples/call_plugin.c)
target_link_libraries(example_call_plugin PRIVATE ${CMAKE_DL_LIBS})
