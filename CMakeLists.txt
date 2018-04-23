cmake_minimum_required(VERSION 3.6)
project(libpcap)

set(CMAKE_CXX_STANDARD 11)

set(NDPI_INCLUDE_DIR /usr/local/include/libndpi-2.3.0/libndpi)
set(NDPI_LINK_DIR /usr/local/lib/libndpi.*)

include(FindPCAP.cmake)

include_directories(${NDPI_INCLUDE_DIR})
link_libraries(${NDPI_LINK_DIR})

find_package( Threads )

set(SOURCE_FILES main.c pcap_payload.c pcap_payload.h file_sys.c file_sys.h proc.c proc.h khash.h)
add_executable(libpcap ${SOURCE_FILES})

target_link_libraries(libpcap ${CMAKE_THREAD_LIBS_INIT} )
target_link_libraries(libpcap ${PCAP_LIBRARY})
target_link_libraries(libpcap libndpi)

