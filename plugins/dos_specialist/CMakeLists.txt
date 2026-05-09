cmake_minimum_required(VERSION 3.10)
project(dos_specialist_plugin)

# ---------------------------------------------------------------
# Snort3 ve XGBoost include/lib path'leri
# Ortama göre değiştir (xgb_inspector/CMakeLists.txt ile aynı mantık)
# ---------------------------------------------------------------
set(SNORT3_INCLUDE_DIR "/usr/local/include/snort" CACHE PATH "Snort3 include dir")
set(XGBOOST_INCLUDE_DIR "/usr/local/include"      CACHE PATH "XGBoost include dir")
set(XGBOOST_LIB_DIR     "/usr/local/lib"          CACHE PATH "XGBoost lib dir")

# ---------------------------------------------------------------
# Shared library (.so) — Snort3 dinamik plugin formatı
# ---------------------------------------------------------------
add_library(dos_specialist SHARED
    src/dos_specialist_inspector.cc
)

target_include_directories(dos_specialist PRIVATE
    ${SNORT3_INCLUDE_DIR}
    ${XGBOOST_INCLUDE_DIR}
    src/
)

target_link_directories(dos_specialist PRIVATE
    ${XGBOOST_LIB_DIR}
)

target_link_libraries(dos_specialist PRIVATE
    xgboost
)

# C++17 (Snort3 gereksinimi)
set_target_properties(dos_specialist PROPERTIES
    CXX_STANDARD          17
    CXX_STANDARD_REQUIRED ON
    PREFIX                ""          # libdos_specialist.so değil dos_specialist.so
    POSITION_INDEPENDENT_CODE ON
)

# Build tipi varsayılan Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

target_compile_options(dos_specialist PRIVATE
    -Wall -Wextra -O2
)