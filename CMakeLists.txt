cmake_minimum_required(VERSION 3.10)
project(tcp_state_analyzer C)

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIB NAMES pcap wpcap)

if(NOT PCAP_INCLUDE_DIR)
  message(FATAL_ERROR "pcap.h not found. Install libpcap-dev (Linux) or Npcap SDK (Windows) and set include paths.")
endif()

include_directories(${PCAP_INCLUDE_DIR})

add_executable(tcp_state_analyzer tcp_state_analyzer.c)
if(PCAP_LIB)
  target_link_libraries(tcp_state_analyzer PRIVATE ${PCAP_LIB})
endif()
