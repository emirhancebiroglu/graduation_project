cmake_minimum_required(VERSION 3.16)
project(xgb_inspector CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----- Snort3 -----
find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 REQUIRED snort>=3.0.0)
include_directories(${SNORT3_INCLUDE_DIRS})

# ----- XGBoost -----
# XGBoost kaynak dizini (git clone ile indirilmiş)
# Varsayılan: ~/snort_src/xgboost
# Override: cmake -DXGBOOST_ROOT=/path/to/xgboost ..
set(XGBOOST_ROOT "$ENV{HOME}/snort_src/xgboost" CACHE PATH
    "XGBoost source/install root directory")

# Header: <xgboost/c_api.h>
set(XGBOOST_INCLUDE_DIR "${XGBOOST_ROOT}/include")

# Library: libxgboost.so
# XGBoost build genellikle lib/ altına koyar
set(XGBOOST_LIB_DIR "${XGBOOST_ROOT}/lib")

# ----- Plugin kaynak dosyaları -----
set(XGB_INSPECTOR_SOURCES
    src/xgb_inspector.cc
)

add_library(xgb_inspector SHARED ${XGB_INSPECTOR_SOURCES})

target_include_directories(xgb_inspector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${XGBOOST_INCLUDE_DIR}
)

# ----- Link -----
target_link_libraries(xgb_inspector
    ${SNORT3_LIBRARIES}
    "${XGBOOST_LIB_DIR}/libxgboost.so"
    dl
    pthread
)

# Plugin prefix'ini kaldır
set_target_properties(xgb_inspector PROPERTIES
    PREFIX ""
    OUTPUT_NAME "xgb_inspector"
)

install(TARGETS xgb_inspector
    LIBRARY DESTINATION lib/snort_extra
)

# ----- Bilgi mesajı -----
message(STATUS "Snort3 include:    ${SNORT3_INCLUDE_DIRS}")
message(STATUS "XGBoost root:      ${XGBOOST_ROOT}")
message(STATUS "XGBoost include:   ${XGBOOST_INCLUDE_DIR}")
message(STATUS "XGBoost lib:       ${XGBOOST_LIB_DIR}")
message(STATUS "Plugin output:     ${CMAKE_CURRENT_BINARY_DIR}/xgb_inspector.so")
