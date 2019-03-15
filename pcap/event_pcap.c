#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <event2/event.h>

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
#include <unistd.h>

#include <pcap/pcap.h>
#include <pcap/sll.h>

#include "event_pcap.h"

struct event_pcap {
    struct event_pcap_config * config;
    struct event_base        * base;
    struct event             * event;
    int                        pcap_fd;
    pcap_t                   * pcap;
    void                       (* callback)(struct event_pcap_packet *, void *);
    void                     * userdata;
};

static void
ev_pcap_packet_handler_(u_char                   * arg,
                        const struct pcap_pkthdr * pkthdr,
                        const u_char             * packet)
{
    struct event_pcap         * cap;
    bpf_u_int32                 length;
    bpf_u_int32                 caplen;
    u_int16_t                   ether_type;
    const u_char              * orig_packet;
    const struct ip           * ip_p;
    const struct ether_header * eth_p;
    const struct sll_header   * sll_p;
    const struct udphdr       * udp;
    const struct tcphdr       * tcp;
    uint16_t                    toff;
    uint32_t                    ip_hl;
    int                         datalink;
    struct event_pcap_packet    ev_packet;

    cap = (struct event_pcap *)arg;
    assert(cap != NULL);


    orig_packet           = packet;
    caplen                = pkthdr->caplen;
    length                = pkthdr->len;
    datalink              = pcap_datalink(cap->pcap);

    ev_packet.pkthdr      = pkthdr;
    ev_packet.full_packet = packet;
    ev_packet.l1_type     = datalink;

    switch (datalink) {
        case DLT_LINUX_SLL:
            if (caplen < SLL_HDR_LEN || length < SLL_HDR_LEN) {
                return;
            }

            sll_p                = (const struct sll_header *)packet;
            ether_type           = ntohs(sll_p->sll_protocol);

            length              -= SLL_HDR_LEN;
            caplen              -= SLL_HDR_LEN;
            packet              += SLL_HDR_LEN;

            ev_packet.l1_len     = SLL_HDR_LEN;
            ev_packet.l1.sll     = sll_p;
            ev_packet.l1_payload = packet;

            break;
        case DLT_EN10MB:
            if (caplen < ETHER_HDR_LEN || length < ETHER_HDR_LEN) {
                return;
            }

            eth_p                = (const struct ether_header *)packet;
            ether_type           = ntohs(eth_p->ether_type);

            length              -= ETHER_HDR_LEN;
            caplen              -= ETHER_HDR_LEN;
            packet              += ETHER_HDR_LEN;

            ev_packet.l1_len     = ETHER_HDR_LEN;
            ev_packet.l1.eth     = eth_p;
            ev_packet.l1_payload = packet;

            break;
        default:
            return;
    } /* switch */

    while (ether_type == ETHERTYPE_VLAN) {
        if (caplen < 4 || length < 4) {
            return;
        }

        ether_type           = ntohs(*(unsigned short *)(packet + 2));

        length              -= 4;
        caplen              -= 4;
        packet              += 4;

        ev_packet.l1_len    += 4;
        ev_packet.l1_payload = packet;
    }

    if (caplen < sizeof(struct ip) || length < sizeof(struct ip)) {
        return;
    }

    ev_packet.l2_type = ether_type;
    ip_p = (const struct ip *)packet;

    if (ip_p->ip_v != 4) {
        return;
    }

    ip_hl                 = ip_p->ip_hl * 4;

    length               -= ip_hl;
    caplen               -= ip_hl;
    packet               += ip_hl;

    ev_packet.l2.ip       = ip_p;
    ev_packet.l2_len      = ip_hl;
    ev_packet.l2_payload  = packet;
    ev_packet.payload     = packet;
    ev_packet.payload_len = length;
    ev_packet.l3_type     = ip_p->ip_p;

    switch (ip_p->ip_p) {
        case IPPROTO_TCP:
            tcp     = (struct tcphdr *)packet;
            toff    = tcp->th_off * 4;

            length -= toff;
            caplen -= toff;
            packet += toff;

            ev_packet.payload     = packet;
            ev_packet.payload_len = length;
            ev_packet.l3.tcp      = tcp;
            ev_packet.l3_payload  = packet;
            ev_packet.l3_len      = toff;

            break;
        case IPPROTO_UDP:
            udp     = (struct udphdr *)packet;

            length -= sizeof(struct udphdr);
            caplen -= sizeof(struct udphdr);
            packet += sizeof(struct udphdr);


            ev_packet.payload     = packet;
            ev_packet.payload_len = length;
            ev_packet.l3.udp      = udp;
            ev_packet.l3_payload  = packet;
            ev_packet.l3_len      = sizeof(struct udphdr);

            break;
    } /* switch */

    if (cap->callback != NULL) {
        (cap->callback)(&ev_packet, cap->userdata);
    }
}     /* ev_pcap_packet_handler_ */

static void
ev_pcap_decodecb_(int sock, short which, void * arg)
{
    struct event_pcap * cap = (struct event_pcap *)arg;

    (void)sock;
    (void)which;

    assert(cap != NULL);

    pcap_dispatch(cap->pcap, -1, (pcap_handler)ev_pcap_packet_handler_, (u_char *)arg);
}

struct event_pcap *
event_pcap_new(struct event_base * base, struct event_pcap_config * config)
{
    pcap_t            * pcap;
    struct event_pcap * cap;
    char                errbuf[PCAP_ERRBUF_SIZE];
    uint8_t             error = 1;

    assert(base != NULL);
    assert(config != NULL);

    if (!(cap = (struct event_pcap *)calloc(1, sizeof(*cap)))) {
        return NULL;
    }

    cap->config = config;
    cap->base   = base;
    cap->pcap   = pcap_open_live(
            config->iface,
            config->snaplen, 1, -1, errbuf);

    if (cap->pcap == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);

        free(cap);
        return NULL;
    }

    if (pcap_setnonblock(cap->pcap, 1, errbuf) == -1) {
        fprintf(stderr, "Error: %s\n", errbuf);

        free(cap);
        return NULL;
    }

    if (config->filter) {
        struct bpf_program filterp;

        pcap_compile(cap->pcap, &filterp, config->filter, 1, PCAP_NETMASK_UNKNOWN);
        pcap_setfilter(cap->pcap, &filterp);
    }

    cap->pcap_fd = pcap_get_selectable_fd(cap->pcap);
    cap->event   = event_new(base, cap->pcap_fd, EV_READ | EV_PERSIST,
            ev_pcap_decodecb_, cap);

    assert(cap->event != NULL);


    return cap;
} /* event_pcap_new */

int
event_pcap_setcb(struct event_pcap * cap,
                 void (*cb)(struct event_pcap_packet *, void *),
                 void * userdata)
{
    assert(cap != NULL);

    cap->callback = cb;
    cap->userdata = userdata;

    return 0;
}

int
event_pcap_start(struct event_pcap * cap)
{
    if (cap == NULL) {
        return -1;
    }

    return event_add(cap->event, NULL);
}
