cmake_minimum_required(VERSION 3.16)
project(bot_client_inspector)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(XGBOOST_ROOT "$ENV{XGBOOST_ROOT}" CACHE PATH "XGBoost root directory")
if(NOT XGBOOST_ROOT)
    set(XGBOOST_ROOT "$ENV{HOME}/snort_src/xgboost")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 REQUIRED snort)

add_library(bot_client_inspector MODULE
    src/bot_client_inspector.cc
)

target_include_directories(bot_client_inspector PRIVATE
    ${SNORT3_INCLUDE_DIRS}
    ${XGBOOST_ROOT}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_directories(bot_client_inspector PRIVATE
    ${XGBOOST_ROOT}/lib
)

target_link_libraries(bot_client_inspector PRIVATE
    xgboost
)

target_compile_options(bot_client_inspector PRIVATE
    ${SNORT3_CFLAGS_OTHER}
    -fvisibility=default
)

set_target_properties(bot_client_inspector PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)
