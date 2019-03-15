#ifndef __EVENT_PCAP_H__
#define __EVENT_PCAP_H__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

struct event_pcap_config {
    char * iface;
    char * filter;
    int    bufferlen;
    int    snaplen;
};

struct event_pcap_packet {
    const struct pcap_pkthdr * pkthdr;
    const u_char             * full_packet;
    const u_char             * payload;
    size_t                     payload_len;

    uint8_t l1_type;
    uint8_t l2_type;
    uint8_t l3_type;
    size_t  l1_len;
    size_t  l2_len;
    size_t  l3_len;

    union {
        const struct sll_header   * sll;
        const struct ether_header * eth;
    } l1;

    union {
        const struct ip      * ip;
        const struct ip6_hdr * ip6;
    } l2;

    union {
        const struct udphdr * udp;
        const struct tcphdr * tcp;
    } l3;

    const u_char * l1_payload;
    const u_char * l2_payload;
    const u_char * l3_payload;
};

struct event_pcap * event_pcap_new(struct event_base *,
                                   struct event_pcap_config *);
int                 event_pcap_setcb(struct event_pcap *,
                                     void (* cb)(struct event_pcap_packet *, void *), void *);
int                 event_pcap_start(struct event_pcap *);
#endif

