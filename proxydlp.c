#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "windivert.h"

#include "dns.h"

#define MAXBUF          0xFFFF
#define PROXY_IP        "192.168.0.15"
#define PROXY_PORT      8080
#define HTTP_PORT       80
#define HTTPS_PORT      443
#define DNS_PORT        53

#define VERBOSITY       0   // 0=silent, 1=events, 2=connections, 3=full packet details

typedef struct {
    UINT32 orig_dst_ip;
    UINT16 orig_dst_port;
    UINT32 orig_src_ip;
    UINT16 orig_src_port;

    UINT32 proxy_dst_ip;
    UINT16 proxy_dst_port;
    UINT16 proxy_src_port; // new source port after rewriting if any
} conn_entry_t;

#define MAX_CONN 1024
conn_entry_t conn_table[MAX_CONN];
int conn_count = 0;

HANDLE handle;

#define VPRINT(level, fmt, ...) \
    do { \
        if (VERBOSITY >= level) { \
            fprintf(stderr, "[V%d] " fmt "\n", level, ##__VA_ARGS__); \
        } \
    } while (0)

static void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}


static void print_ip_port(UINT32 ip, UINT16 port) {
    unsigned char *bytes = (unsigned char *)&ip;
    fprintf(stderr, "%u.%u.%u.%u:%u",
        bytes[0], bytes[1], bytes[2], bytes[3], ntohs(port));
}

static UINT32 ip_str_to_u32(const char *ip_str) {
    UINT32 ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IP string: %s\n", ip_str);
        exit(EXIT_FAILURE);
    }
    return ip; // already in network byte order
}


// Find connection in table by original 4-tuple
int find_conn_outbound(UINT32 src_ip, UINT16 src_port, UINT32 dst_ip, UINT16 dst_port) {
    for (int i = 0; i < conn_count; i++) {
        if (conn_table[i].orig_src_ip == src_ip &&
            conn_table[i].orig_src_port == src_port &&
            conn_table[i].orig_dst_ip == dst_ip &&
            conn_table[i].orig_dst_port == dst_port) {
            return i;
        }
    }
    return -1;
}

// Find connection by proxy side 4-tuple
int find_conn_inbound(UINT32 src_ip, UINT16 src_port, UINT32 dst_ip, UINT16 dst_port) {
    for (int i = 0; i < conn_count; i++) {
        if (conn_table[i].proxy_dst_ip == src_ip &&
            conn_table[i].proxy_dst_port == src_port &&
            conn_table[i].orig_src_ip == dst_ip &&
            conn_table[i].proxy_src_port == dst_port) {
            return i;
        }
    }
    return -1;
}

UINT16 get_unused_src_port() {
    return (UINT16)(1024 + (rand() % (65535 - 1024)));
}

UINT32 handle_udp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header, UINT8 *packet, UINT packet_len, UINT8 payload[MAXBUF], UINT payload_len) {

    //Log DNS queries and responses.
    
    //fprintf(stderr, "Received UDP datagram... \n");
    
    /*
    if (addr->Outbound) {
        fprintf(stderr, "[Outbound] SrcPort: %u, DstPort: %u\n", ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort));
    } else {
        fprintf(stderr, "[Inbound] SrcPort: %u, DstPort: %u\n", ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort));
    }
    */

    if(addr->Outbound && ntohs(udp_header->DstPort) == DNS_PORT) {                 //DNS outbound queries

        fprintf(stderr, "Received DNS query --> \n");
        dns_handle_packet(ip_header, udp_header, payload, payload_len);
        

    } else if (!addr->Outbound && ntohs(udp_header->SrcPort) == DNS_PORT) {        //DNS inbound answers

        fprintf(stderr, "Received DNS response <-- \n");
        dns_handle_packet(ip_header, udp_header, payload, payload_len);
    }


    //Just, forward the datagram for the moment...
    //WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
    
    if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
        fprintf(stderr, "failed to send rewritten inbound packet\n");
        return -1;
    }

    return 0;

}


UINT32 handle_tcp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header, 
    const PWINDIVERT_TCPHDR tcp_header, UINT8 *packet, UINT packet_len) {

    if (addr->Outbound) {
        VPRINT(1, "Outbound packet intercepted");
        if (VERBOSITY >= 3) {
            fprintf(stderr, "    Src: "); print_ip_port(ip_header->SrcAddr, tcp_header->SrcPort);
            fprintf(stderr, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, tcp_header->DstPort);
            fprintf(stderr, "\n");
        }

        int idx = find_conn_outbound(ip_header->SrcAddr, tcp_header->SrcPort,
                                        ip_header->DstAddr, tcp_header->DstPort);
        conn_entry_t *entry;

        if (idx >= 0) {
            entry = &conn_table[idx];
            VPRINT(2, "Found existing connection entry");
        } else {
            if (conn_count >= MAX_CONN) {
                fprintf(stderr, "connection table full\n");
                return -1;
            }

            UINT16 new_src_port = get_unused_src_port();

            entry = &conn_table[conn_count++];
            entry->orig_src_ip = ip_header->SrcAddr;
            entry->orig_src_port = tcp_header->SrcPort;
            entry->orig_dst_ip = ip_header->DstAddr;
            entry->orig_dst_port = tcp_header->DstPort;

            UINT32 proxy_ip = ip_str_to_u32(PROXY_IP);

            entry->proxy_dst_ip = proxy_ip;
            entry->proxy_dst_port = htons(PROXY_PORT);
            entry->proxy_src_port = htons(new_src_port);

            VPRINT(2, "Tracking new connection:");
            if (VERBOSITY >= 2) {
                fprintf(stderr, "    Original: "); print_ip_port(entry->orig_src_ip, entry->orig_src_port);
                fprintf(stderr, " -> "); print_ip_port(entry->orig_dst_ip, entry->orig_dst_port);
                fprintf(stderr, "\n    Proxy: "); print_ip_port(entry->proxy_dst_ip, entry->proxy_dst_port);
                fprintf(stderr, " (src port remap to %u)\n", ntohs(entry->proxy_src_port));
            }
        }

        ip_header->DstAddr = entry->proxy_dst_ip;
        tcp_header->DstPort = entry->proxy_dst_port;
        tcp_header->SrcPort = entry->proxy_src_port;

        if (VERBOSITY >= 3) {
            fprintf(stderr, "Rewriting outbound packet to:\n");
            fprintf(stderr, "    Src: "); print_ip_port(ip_header->SrcAddr, tcp_header->SrcPort);
            fprintf(stderr, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, tcp_header->DstPort);
            fprintf(stderr, "\n");
        }

        WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);

        if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
            fprintf(stderr, "failed to send rewritten outbound packet\n");
        }

    } else {
        VPRINT(1, "Inbound packet intercepted");
        if (VERBOSITY >= 3) {
            fprintf(stderr, "    Src: "); print_ip_port(ip_header->SrcAddr, tcp_header->SrcPort);
            fprintf(stderr, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, tcp_header->DstPort);
            fprintf(stderr, "\n");
        }

        int idx = find_conn_inbound(ip_header->SrcAddr, tcp_header->SrcPort,
                                    ip_header->DstAddr, tcp_header->DstPort);
        if (idx < 0) {
            VPRINT(2, "No matching connection found, forwarding unchanged");
            if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
                fprintf(stderr, "failed to send inbound packet\n");
            }
            return -1;
        }

        conn_entry_t *entry = &conn_table[idx];

        ip_header->SrcAddr = entry->orig_dst_ip;
        tcp_header->SrcPort = entry->orig_dst_port;
        ip_header->DstAddr = entry->orig_src_ip;
        tcp_header->DstPort = entry->orig_src_port;

        if (VERBOSITY >= 3) {
            fprintf(stderr, "Rewriting inbound packet to:\n");
            fprintf(stderr, "    Src: "); print_ip_port(ip_header->SrcAddr, tcp_header->SrcPort);
            fprintf(stderr, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, tcp_header->DstPort);
            fprintf(stderr, "\n");
        }

        WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);

        if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
            fprintf(stderr, "failed to send rewritten inbound packet\n");
        }
    }

    return 0;

}

int main() {
    char filter[256];
    int r;

    srand((unsigned int)time(NULL));

    //We listen to outbound HTTP and HTTPS requests and also to incoming requests from the src proxy IP and port.

    r = snprintf(filter, sizeof(filter),
        "(outbound and tcp.DstPort == %d) or "
        "(outbound and tcp.DstPort == %d) or "
        "(inbound and tcp.SrcPort == %d and ip.SrcAddr == %s) or "
        "(outbound and udp.DstPort == %d) or "
        "(inbound and udp.SrcPort == %d)",
        HTTP_PORT, HTTPS_PORT, PROXY_PORT, PROXY_IP, DNS_PORT, DNS_PORT);

    if (r < 0 || r >= sizeof(filter)) {
        error("failed to create filter string");
    }

    VPRINT(1, "Opening WinDivert with filter: %s", filter);

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        error("failed to open WinDivert device");
    }

    UINT8 packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

    UINT8 *payload;
    UINT payload_len;

    while (1) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
            fprintf(stderr, "failed to read packet (%ld)\n", GetLastError());
            continue;
        }

        if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
                                        NULL, NULL, &tcp_header, &udp_header, (PVOID *)&payload, &payload_len, NULL, NULL)) {
            fprintf(stderr, "failed to parse packet\n");
            continue;
        }

        if(tcp_header) {

            /*UINT32 result =*/ handle_tcp_packet(&addr, ip_header, tcp_header, packet, packet_len);

        } else if (udp_header) {
            /*UINT32 result =*/ handle_udp_packet(&addr, ip_header, udp_header, packet, packet_len, payload, payload_len);
        }

    }

    WinDivertClose(handle);
    return 0;
}
