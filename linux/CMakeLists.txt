cmake_minimum_required(VERSION 3.10)
project(tcp_state_analyzer C)

add_executable(tcp_state_analyzer tcp_state_analyzer.c)
find_package(Threads REQUIRED)
target_link_libraries(tcp_state_analyzer PRIVATE Threads::Threads)

# Try to find libpcap
find_path(PCAP_INCLUDE pcap.h)
find_library(PCAP_LIB pcap wpcap)
if(PCAP_INCLUDE AND PCAP_LIB)
  target_include_directories(tcp_state_analyzer PRIVATE ${PCAP_INCLUDE})
  target_link_libraries(tcp_state_analyzer PRIVATE ${PCAP_LIB})
endif()
