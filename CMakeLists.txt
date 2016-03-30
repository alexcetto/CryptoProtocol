cmake_minimum_required(VERSION 3.3)
project(CryptoProtocolClient)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories("/usr/local/opt/openssl/include")
link_directories("/usr/local/opt/openssl/lib")

set(SOURCE_FILES_CLIENT
        CryptoProtocol/Client/client.c)

set(SOURCE_FILES_SERVER
        CryptoProtocol/Server/server.c
        CryptoProtocol/crypto/crypto.c)

add_executable(CryptoProtocolClient ${SOURCE_FILES_CLIENT})
add_executable(CryptoProtocolServer ${SOURCE_FILES_SERVER})

target_link_libraries(CryptoProtocolServer "libcrypto.a")
target_link_libraries(CryptoProtocolServer "libssl.a")