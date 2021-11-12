cmake_minimum_required(VERSION 3.10)

# set the project name
project(testCurl)

# add the executable
find_library(SSL_LIB libssl.so REQUIRED)
find_library(CRYPTO_LIB libcrypto.so REQUIRED)
find_library(CURL_LIB libcurl.so REQUIRED)
find_library(JSONC_LIB libjson-c.so REQUIRED)
add_executable(testCurl testCurl.c base64.c openssltest.c)
target_link_libraries(testCurl ${JSONC_LIB} ${CURL_LIB} ${SSL_LIB} ${CRYPTO_LIB})
