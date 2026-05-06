cmake_minimum_required(VERSION 3.16)
project(ml_inspector CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----- Snort3 -----
find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT3 REQUIRED snort>=3.0.0)
include_directories(${SNORT3_INCLUDE_DIRS})

# ----- libml / TFLite yolları -----
# libml_static.a: TFLite runtime + flatbuffers içeriyor
set(LIBML_ROOT "/home/emirhan/snort_src/libml")
set(LIBML_BUILD "${LIBML_ROOT}/build")

# TFLite C API header'ı
set(TFLITE_INCLUDE_DIR
    "${LIBML_ROOT}/vendor/tensorflow"
)

# libml header'ı (BinaryClassifier — ileride kullanılabilir)
set(LIBML_INCLUDE_DIR "${LIBML_ROOT}/src")

# ----- Plugin kaynak dosyaları -----
set(ML_INSPECTOR_SOURCES
    src/ml_inspector.cc
)

add_library(ml_inspector SHARED ${ML_INSPECTOR_SOURCES})

target_include_directories(ml_inspector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${TFLITE_INCLUDE_DIR}
    ${LIBML_INCLUDE_DIR}
)

# ----- Link -----
# libml_static.a: TFLite + flatbuffers + abseil dahil
# dl: TFLite dynamic ops için
# pthread: TFLite thread pool için
target_link_libraries(ml_inspector
    ${SNORT3_LIBRARIES}
    "${LIBML_BUILD}/libml_static.a"
    dl
    pthread
)

# Plugin prefix'ini kaldır
set_target_properties(ml_inspector PROPERTIES
    PREFIX ""
    OUTPUT_NAME "ml_inspector"
)

install(TARGETS ml_inspector
    LIBRARY DESTINATION lib/snort_extra
)

# ----- Bilgi mesajı -----
message(STATUS "Snort3 include: ${SNORT3_INCLUDE_DIRS}")
message(STATUS "libml root:     ${LIBML_ROOT}")
message(STATUS "TFLite headers: ${TFLITE_INCLUDE_DIR}")
message(STATUS "Plugin output:  ${CMAKE_CURRENT_BINARY_DIR}/ml_inspector.so")