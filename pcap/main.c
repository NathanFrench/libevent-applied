#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>


#include <pcap.h>
#include <event2/event.h>

#include "event_pcap.h"

static void
print_hex(const char * data, size_t len)
{
    int    i, line_buf_off;
    char * line_buf = NULL;
    int    spaces_left;
    char * spaces   = "                                          ";

    line_buf = (char *)alloca(len + 30);

    memset(line_buf, 0, len + 30);

    line_buf_off = 0;
    spaces_left  = 41;

    printf("      ");

    for (i = 0; i < len; i++) {
        if (i && !(i % 16)) {
            printf(" %s\n     ", line_buf);
            bzero(line_buf, len + 30);
            line_buf_off = -1;
            spaces_left  = 41;
        }

        if (line_buf_off < 0) {
            line_buf[++line_buf_off] = 'f';
        }

        if (line_buf_off >= 0) {
            if (isprint(data[i]) && !isspace(data[i])) {
                line_buf[line_buf_off] = data[i];
            } else {
                line_buf[line_buf_off] = '.';
            }
        }

        if (i && !(i % 2)) {
            spaces_left -= 1;
            printf(" ");
        }

        printf("%2.2X", (unsigned)(unsigned char)data[i]);
        line_buf_off++;

        spaces_left -= 2;
    }

    printf("%.*s%s\n\n", spaces_left,
           spaces, line_buf);
} /* print_hex */

static void
print_packet(struct event_pcap_packet * packet, void * arg)
{
    /* since we're only looking at ipv4+tcp, we assume this */
    printf("src=%s:%d ",
            inet_ntoa(*(struct in_addr *)&packet->l2.ip->ip_src.s_addr),
            ntohs(packet->l3.tcp->th_sport));
    printf("dst=%s:%d\n",
            inet_ntoa(*(struct in_addr *)&packet->l2.ip->ip_dst.s_addr),
            ntohs(packet->l3.tcp->th_dport));

    print_hex(packet->payload, packet->payload_len);
}

int
main(int argc, char ** argv)
{
    struct event_pcap_config config = {
        .iface     = "any",
        .filter    = "ip and tcp port 80",
        .bufferlen = 1024,
        .snaplen   = 1024
    };
    struct event_base      * base;
    struct event_pcap      * ev_pcap;

    base    = event_base_new();
    assert(base != NULL);

    ev_pcap = event_pcap_new(base, &config);
    assert(ev_pcap != NULL);

    event_pcap_setcb(ev_pcap, print_packet, (void *)ev_pcap);
    event_pcap_start(ev_pcap);
    event_base_loop(base, 0);

    return 0;
}
