cmake_minimum_required(VERSION 3.16)
project(portscan_inspector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# XGBoost
set(XGBOOST_ROOT "$ENV{XGBOOST_ROOT}" CACHE PATH "XGBoost root directory")
if(NOT XGBOOST_ROOT)
    set(XGBOOST_ROOT "$ENV{HOME}/snort_src/xgboost")
endif()

# Snort3 via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 REQUIRED snort)

add_library(portscan_inspector MODULE
    src/portscan_inspector.cc
)

target_include_directories(portscan_inspector PRIVATE
    ${SNORT3_INCLUDE_DIRS}
    ${XGBOOST_ROOT}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_directories(portscan_inspector PRIVATE
    ${XGBOOST_ROOT}/lib
)

target_link_libraries(portscan_inspector PRIVATE
    xgboost
)

target_compile_options(portscan_inspector PRIVATE
    ${SNORT3_CFLAGS_OTHER}
    -fvisibility=default
)

set_target_properties(portscan_inspector PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)