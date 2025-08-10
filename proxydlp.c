#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "windivert.h"

#define MAXBUF          0xFFFF
#define PROXY_IP        0xC0A8000F  // 192.168.0.15 in hex
#define PROXY_PORT      8080
#define HTTP_PORT       80
#define HTTPS_PORT      443

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

static void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

static UINT16 ntohs_u16(UINT16 netshort) {
    return (netshort >> 8) | (netshort << 8);
}

static UINT16 htons_u16(UINT16 hostshort) {
    return (hostshort >> 8) | (hostshort << 8);
}

// Find connection in table by original 4-tuple (src_ip, src_port, dst_ip, dst_port)
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

// Find connection by proxy side 4-tuple (src_ip, src_port, dst_ip, dst_port)
int find_conn_inbound(UINT32 src_ip, UINT16 src_port, UINT32 dst_ip, UINT16 dst_port) {
    for (int i = 0; i < conn_count; i++) {
        if (conn_table[i].proxy_dst_ip == src_ip &&       // From proxy server
            conn_table[i].proxy_dst_port == src_port &&
            conn_table[i].orig_src_ip == dst_ip &&
            conn_table[i].proxy_src_port == dst_port) {  // To client port
            return i;
        }
    }
    return -1;
}

UINT16 get_unused_src_port() {
    // For simplicity, pick random high ports (can be improved)
    return (UINT16)(1024 + (rand() % (65535 - 1024)));
}

int main() {
    char filter[256];
    int r;

    srand((unsigned int)time(NULL));

    // Filter for outbound to HTTP/HTTPS OR inbound from proxy port
    r = snprintf(filter, sizeof(filter),
        "(outbound and tcp.DstPort == %d) or "
        "(outbound and tcp.DstPort == %d) or "
        "(inbound and tcp.SrcPort == %d and ip.SrcAddr == %u)",
        HTTP_PORT, HTTPS_PORT, PROXY_PORT, htonl(PROXY_IP));


    if (r < 0 || r >= sizeof(filter)) {
        error("failed to create filter string");
    }

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        error("failed to open WinDivert device");
    }

    UINT8 packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;

    while (1) {

        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
            fprintf(stderr, "failed to read packet (%d)\n", GetLastError());
            continue;
        }

        if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
                                        NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL)) {
            fprintf(stderr, "failed to parse packet\n");
            continue;
        }

        if (addr.Outbound) {

            int idx = find_conn_outbound(ip_header->SrcAddr, tcp_header->SrcPort, ip_header->DstAddr, tcp_header->DstPort);

            conn_entry_t *entry;

            if (idx >= 0) {
                // Connection tracked: use existing entry
                entry = &conn_table[idx];
            } else {
                // Not tracked yet, create new entry
                if (conn_count >= MAX_CONN) {
                    fprintf(stderr, "connection table full\n");
                    continue;
                }

                UINT16 new_src_port = get_unused_src_port();

                entry = &conn_table[conn_count++];
                entry->orig_src_ip = ip_header->SrcAddr;
                entry->orig_src_port = tcp_header->SrcPort;
                entry->orig_dst_ip = ip_header->DstAddr;
                entry->orig_dst_port = tcp_header->DstPort;

                entry->proxy_dst_ip = PROXY_IP;
                entry->proxy_dst_port = htons(PROXY_PORT);
                entry->proxy_src_port = htons(new_src_port);
            }

            // Rewrite packet (common for both new and tracked connections)
            ip_header->DstAddr = entry->proxy_dst_ip;
            tcp_header->DstPort = entry->proxy_dst_port;
            tcp_header->SrcPort = entry->proxy_src_port;

            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);

            if (!WinDivertSend(handle, packet, packet_len, NULL, &addr)) {
                fprintf(stderr, "failed to send rewritten outbound packet\n");
            }

        } else {

            // Inbound packet, expected from proxy server to client
            // We want to rewrite source IP/port back to original destination IP/port

            int idx = find_conn_inbound(ip_header->SrcAddr, tcp_header->SrcPort, ip_header->DstAddr, tcp_header->DstPort);
            if (idx < 0) {
                // Not tracked, just forward
                if (!WinDivertSend(handle, packet, packet_len, NULL, &addr)) {
                    fprintf(stderr, "failed to send inbound packet\n");
                }
                continue;
            }

            conn_entry_t *entry = &conn_table[idx];

            // Rewrite source IP/port from proxy to original destination IP/port
            ip_header->SrcAddr = entry->orig_dst_ip;
            tcp_header->SrcPort = entry->orig_dst_port;

            // Rewrite dest IP/port from proxy to original source IP/port
            ip_header->DstAddr = entry->orig_src_ip;
            tcp_header->DstPort = entry->orig_src_port;

            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);

            if (!WinDivertSend(handle, packet, packet_len, NULL, &addr)) {
                fprintf(stderr, "failed to send rewritten inbound packet\n");
            }
        }
    }

    WinDivertClose(handle);
    return 0;
}
