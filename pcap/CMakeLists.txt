# to compile as a lib:
#add_library(event_pcap event_pcap.c)
#target_link_libraries(event_pcap event pcap)

add_executable(event_pcap_main event_pcap.c main.c)
target_link_libraries(event_pcap_main event pcap)
