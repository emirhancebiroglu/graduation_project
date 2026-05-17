cmake_minimum_required(VERSION 3.16)
project(ddos_aggregator)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(XGBOOST_ROOT "$ENV{XGBOOST_ROOT}" CACHE PATH "XGBoost root directory")
if(NOT XGBOOST_ROOT)
    set(XGBOOST_ROOT "$ENV{HOME}/snort_src/xgboost")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 REQUIRED snort)

add_library(ddos_aggregator MODULE
    src/ddos_inspector.cc
)

target_include_directories(ddos_aggregator PRIVATE
    ${SNORT3_INCLUDE_DIRS}
    ${XGBOOST_ROOT}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/src
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_directories(ddos_aggregator PRIVATE
    ${XGBOOST_ROOT}/lib
)

target_link_libraries(ddos_aggregator PRIVATE
    xgboost
)

target_compile_options(ddos_aggregator PRIVATE
    ${SNORT3_CFLAGS_OTHER}
    -fvisibility=default
)

set_target_properties(ddos_aggregator PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)
