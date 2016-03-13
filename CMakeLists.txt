cmake_minimum_required(VERSION 3.3)
project(CryptoProtocolClient)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES_CLIENT
    CryptoProtocol/Client/client.c)
set(SOURCE_FILES_SERVER
        CryptoProtocol/Server/server.c)

add_executable(CryptoProtocolClient ${SOURCE_FILES_CLIENT})
add_executable(CryptoProtocolServer ${SOURCE_FILES_SERVER})