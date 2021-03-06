cmake_minimum_required(VERSION 3.3)
project(CryptoProtocolClient)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories("/usr/local/opt/openssl/include")
link_directories("/usr/local/opt/openssl/lib")

set(SOURCE_FILES_CLIENT
        CryptoProtocol/Client/client.c
        CryptoProtocol/crypto/crypto.c)
set(SOURCE_FILES_SERVER
        CryptoProtocol/crypto/crypto.c
        CryptoProtocol/crypto/crypto.h
        CryptoProtocol/Server/server.c)
set(SOURCE_FILES_DEBUG
        CryptoProtocol/crypto/crypto.c
        CryptoProtocol/crypto/crypto.h
        CryptoProtocol/main.c)

add_executable(CryptoProtocolDebug ${SOURCE_FILES_DEBUG})
include_directories("/usr/local/opt/openssl/include")
target_link_libraries(CryptoProtocolDebug "/usr/local/opt/openssl/lib/libcrypto.a")
target_link_libraries(CryptoProtocolDebug "/usr/local/opt/openssl/lib/libssl.a")

add_executable(CryptoProtocolClient ${SOURCE_FILES_CLIENT})
add_executable(CryptoProtocolServer ${SOURCE_FILES_SERVER})

target_link_libraries(CryptoProtocolServer "libcrypto.a")
target_link_libraries(CryptoProtocolServer "libssl.a")

target_link_libraries(CryptoProtocolClient "libcrypto.a")
target_link_libraries(CryptoProtocolClient "libssl.a")