cmake_minimum_required(VERSION 3.16)
project(dos_inspector CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----- Snort3 -----
find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 REQUIRED snort>=3.0.0)
include_directories(${SNORT3_INCLUDE_DIRS})

# ----- XGBoost -----
set(XGBOOST_ROOT "$ENV{HOME}/snort_src/xgboost" CACHE PATH
    "XGBoost source/install root directory")
set(XGBOOST_INCLUDE_DIR "${XGBOOST_ROOT}/include")
set(XGBOOST_LIB_DIR "${XGBOOST_ROOT}/lib")

# ----- Plugin kaynak dosyaları -----
set(DOS_INSPECTOR_SOURCES
    src/dos_inspector.cc
)

add_library(dos_inspector SHARED ${DOS_INSPECTOR_SOURCES})

target_include_directories(dos_inspector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${XGBOOST_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# ----- Link -----
target_link_libraries(dos_inspector
    ${SNORT3_LIBRARIES}
    "${XGBOOST_LIB_DIR}/libxgboost.so"
    dl
    pthread
)

# Plugin prefix'ini kaldır
set_target_properties(dos_inspector PROPERTIES
    PREFIX ""
    OUTPUT_NAME "dos_inspector"
)

install(TARGETS dos_inspector
    LIBRARY DESTINATION lib/snort_extra
)

message(STATUS "Snort3 include:    ${SNORT3_INCLUDE_DIRS}")
message(STATUS "XGBoost root:      ${XGBOOST_ROOT}")
message(STATUS "XGBoost include:   ${XGBOOST_INCLUDE_DIR}")
message(STATUS "XGBoost lib:       ${XGBOOST_LIB_DIR}")
message(STATUS "Plugin output:     ${CMAKE_CURRENT_BINARY_DIR}/dos_inspector.so")
