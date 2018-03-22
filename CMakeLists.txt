cmake_minimum_required(VERSION 3.6)
project(libpcap)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

set(SOURCE_FILES main.c pcap_payload.c pcap_payload.h file_sys.c file_sys.h)
add_executable(libpcap ${SOURCE_FILES})
target_link_libraries(libpcap ${PCAP_LIBRARY})