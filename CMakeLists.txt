cmake_minimum_required(VERSION 3.20)
project(safeanar LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MINGW)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

file(GLOB CRYPTOPP_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cryptopp/*.cpp
)

list(FILTER CRYPTOPP_SOURCES EXCLUDE REGEX ".*/(bench[0-9]+|datatest|dlltest|fipsalgt|fipstest|regtest[0-9]+|test|validat[0-9]+)\\.cpp$")

add_library(cryptopp_vendor STATIC
    ${CRYPTOPP_SOURCES}
)
target_include_directories(cryptopp_vendor PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cryptopp
)
target_compile_definitions(cryptopp_vendor PUBLIC
    CRYPTOPP_DISABLE_ASM=1
)

add_library(libsafeanar STATIC
    src/anar_key.cpp
    src/crypto_engine.cpp
    src/key_generator.cpp
    src/protocol_factory.cpp
    src/stream_packer.cpp
    src/secure_delete.cpp
)
target_include_directories(libsafeanar PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(libsafeanar PUBLIC
    cryptopp_vendor
)

add_executable(safeanar main.cpp)
target_link_libraries(safeanar PRIVATE libsafeanar)

add_executable(anar_key_adapter
    src/anar_key_adapter.cpp
)
target_link_libraries(anar_key_adapter PRIVATE libsafeanar)

add_executable(phase2_crypto_adapter
    src/phase2_crypto_adapter.cpp
)
target_link_libraries(phase2_crypto_adapter PRIVATE libsafeanar)

add_executable(phase3_stream_adapter
    src/phase3_stream_adapter.cpp
)
target_link_libraries(phase3_stream_adapter PRIVATE libsafeanar)
