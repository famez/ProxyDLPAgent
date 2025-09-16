#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "tracelog.h"
#include "proxydlp.h"
#include "windivert.h"
#include "config.h"

#include "dns.h"
#include "monitor.h"

#define MAXBUF          0xFFFF
#define MAX_CONN 1024
#define IDLE_TIMEOUT 300  // seconds (5 min)

extern volatile int g_Running;

typedef struct {
    UINT32 orig_dst_ip;
    UINT16 orig_dst_port;
    UINT32 orig_src_ip;
    UINT16 orig_src_port;

    UINT32 proxy_dst_ip;
    UINT16 proxy_dst_port;
    UINT16 proxy_src_port; // new source port after rewriting if any
    
    time_t last_seen; // internal tracking
} conn_entry_t;


typedef struct {
    conn_entry_t table[MAX_CONN];
    int count;
} conn_entries_t;

conn_entries_t conn_tcp_entries = { .count = 0 };
conn_entries_t conn_udp_entries = { .count = 0 };

HANDLE handle;


static void error(const char *msg) {
    VPRINT(1, "%s\n", msg);
    exit(EXIT_FAILURE);
}

static void print_ip_port(UINT32 ip, UINT16 port) {
    unsigned char *bytes = (unsigned char *)&ip;
    VPRINT(3, "%u.%u.%u.%u:%u",
        bytes[0], bytes[1], bytes[2], bytes[3], ntohs(port));
}

static UINT32 ip_str_to_u32(const char *ip_str) {
    UINT32 ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        VPRINT(1, "Invalid IP string: %s\n", ip_str);
        exit(EXIT_FAILURE);
    }
    return ip; // already in network byte order
}

UINT32 handle_conn_entry(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header, 
    UINT16 *src_port, UINT16 *dst_port, UINT8 *packet, UINT packet_len, conn_entries_t *entries, BOOL tcp_rst, BOOL tcp_fin);

// ---------------- Utility ----------------


static void conn_remove_at(conn_entries_t *entries, int idx)
{
    if (idx < entries->count - 1) {
        memmove(&entries->table[idx], &entries->table[idx + 1],
                (entries->count - idx - 1) * sizeof(conn_entry_t));
    }
    entries->count--;
}

void remove_connection(conn_entries_t *entries, conn_entry_t *entry)
{
    int idx = (int)(entry - entries->table);
    if (idx >= 0 && idx < entries->count) {
        conn_remove_at(entries, idx);
    }
}

void update_connection_seen(conn_entry_t *entry)
{
    if (entry) {
        entry->last_seen = time(NULL);
    }
}

void cleanup_connections(conn_entries_t *entries)
{
    time_t now = time(NULL);
    for (int i = 0; i < entries->count; ) {
        if (now - entries->table[i].last_seen > IDLE_TIMEOUT) {
            VPRINT(1, "[CONN] Removing idle connection src=%u:%u -> dst=%u:%u\n",
                   entries->table[i].orig_src_ip, entries->table[i].orig_src_port,
                   entries->table[i].orig_dst_ip, entries->table[i].orig_dst_port);
            conn_remove_at(entries, i);
        } else {
            i++;
        }
    }
}


UINT32 install_filter(){

    char filter[256];
    int r;

    srand((unsigned int)time(NULL));

    //We listen to outbound HTTP and HTTPS requests and also to incoming requests from the src proxy IP and port.

    r = snprintf(filter, sizeof(filter),
        "(outbound and udp.DstPort == %d) or "
        "(inbound and udp.SrcPort == %d)",
        DNS_PORT, DNS_PORT);

    if (r < 0 || r >= sizeof(filter)) {
        error("failed to create filter string");
    }

    VPRINT(1, "Opening WinDivert with filter: %s", filter);

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        error("failed to open WinDivert device");
    }

    return 0;

}


UINT32 intercept_packets_loop() {

    UINT8 packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

    UINT8 *payload;
    UINT payload_len;

    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);


    while (g_Running) {

        BOOL ok = WinDivertRecvEx(handle, packet, sizeof(packet), &packet_len, 0, &addr, NULL, &ov);

        if(!ok && GetLastError() == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(ov.hEvent, 1000); // 1 second timeout
            if (wait == WAIT_TIMEOUT) {
            CancelIo(handle);
            VPRINT(3, "Timed out\n");
            continue;
            } else {
                GetOverlappedResult(handle, &ov, (PDWORD)&packet_len, FALSE);
                VPRINT(3, "Got a packet!\n");
            }
        }

        if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL,
                                        NULL, NULL, &tcp_header, &udp_header, (PVOID *)&payload, &payload_len, NULL, NULL)) {
            VPRINT(1, "failed to parse packet\n");
            continue;
        }

        if(!ip_header) {
            VPRINT(1, "WARNING: No ip header!!!!!\n");
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

int find_conn_outbound(conn_entries_t *entries, UINT32 src_ip, UINT16 src_port, UINT32 dst_ip, UINT16 dst_port) {
    for (int i = 0; i < entries->count; i++) {
        if (entries->table[i].orig_src_ip == src_ip &&
            entries->table[i].orig_src_port == src_port &&
            entries->table[i].orig_dst_ip == dst_ip &&
            entries->table[i].orig_dst_port == dst_port) {
            return i;
        }
    }
    return -1;
}

int find_conn_inbound(conn_entries_t *entries, UINT32 src_ip, UINT16 src_port, UINT32 dst_ip, UINT16 dst_port) {
    for (int i = 0; i < entries->count; i++) {
        if (entries->table[i].proxy_dst_ip == src_ip &&
            entries->table[i].proxy_dst_port == src_port &&
            entries->table[i].orig_src_ip == dst_ip &&
            entries->table[i].proxy_src_port == dst_port) {
            return i;
        }
    }
    return -1;
}

UINT16 get_unused_src_port(conn_entries_t *entries) {
    UINT16 port;
    int tries = 0;
    const int max_tries = 1000;

    do {
        port = (UINT16)(1024 + (rand() % (65535 - 1024)));
        int conflict = 0;
        for (int i = 0; i < entries->count; i++) {
            if (entries->table[i].proxy_src_port == htons(port)) {
                conflict = 1;
                break;
            }
        }
        if (!conflict) {
            return port;
        }
        tries++;
    } while (tries < max_tries);

    VPRINT(1, "[WARN] Could not find unused source port after %d tries, returning random\n", max_tries);
    return port; // fallback
}



UINT32 handle_udp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header, UINT8 *packet, UINT packet_len, UINT8 *payload, UINT payload_len) {

    //Log DNS queries and responses.
   

    if(addr->Outbound && ntohs(udp_header->DstPort) == DNS_PORT) {                 //DNS outbound queries

        VPRINT(3, "Received DNS query --> \n");
        dns_handle_packet(ip_header, udp_header, payload, payload_len);
        

    } else if (!addr->Outbound && ntohs(udp_header->SrcPort) == DNS_PORT) {        //DNS inbound answers

        VPRINT(3, "Received DNS response <-- \n");
        dns_handle_packet(ip_header, udp_header, payload, payload_len);
    } else {
        VPRINT(3, "[UDP] Intercepted datagram...\n");

        handle_conn_entry(addr, ip_header, &udp_header->SrcPort, &udp_header->DstPort,
                  packet, packet_len, &conn_udp_entries, FALSE, FALSE);
   //Redirect quic protocol
        return 0;           //Return as the packet mangling and forward is done inside the handle_conn_entry function
    }


    //Just, forward the datagram if DNS.
    //WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
    
    if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
        VPRINT(1, "failed to send rewritten inbound packet\n");
        return -1;
    }

    return 0;

}

UINT32 handle_conn_entry(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header, 
    UINT16 *src_port, UINT16 *dst_port, UINT8 *packet, UINT packet_len, conn_entries_t *entries, BOOL tcp_rst, BOOL tcp_fin) 
{
    int idx = -1;

    if (addr->Outbound) {
        VPRINT(3, "Outbound packet intercepted");
        VPRINT(3, "    Src: "); print_ip_port(ip_header->SrcAddr, *src_port);
        VPRINT(3, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, *dst_port);
        VPRINT(3, "\n");

        idx = find_conn_outbound(entries, ip_header->SrcAddr, *src_port,
                                 ip_header->DstAddr, *dst_port);
        conn_entry_t *entry;

        if (idx >= 0) {
            entry = &entries->table[idx];
            VPRINT(2, "Found existing connection entry\n");
        } else {
            if (entries->count >= MAX_CONN) {
                VPRINT(1, "connection table full\n");
                return -1;
            }

            //Get IP address from hostname
            const char *proxy_ip = get_proxy_ip();

            UINT16 new_src_port = get_unused_src_port(entries);

            idx = entries->count;
            entry = &entries->table[entries->count++];
            entry->orig_src_ip = ip_header->SrcAddr;
            entry->orig_src_port = *src_port;
            entry->orig_dst_ip = ip_header->DstAddr;
            entry->orig_dst_port = *dst_port;

            entry->proxy_dst_ip = ip_str_to_u32(proxy_ip);
            entry->proxy_dst_port = htons(PROXY_PORT);
            entry->proxy_src_port = htons(new_src_port);
            entry->last_seen = time(NULL);

            VPRINT(2, "Tracking new connection:");
            VPRINT(2, "    Original: "); print_ip_port(entry->orig_src_ip, entry->orig_src_port);
            VPRINT(2, " -> "); print_ip_port(entry->orig_dst_ip, entry->orig_dst_port);
            VPRINT(2, "\n    Proxy: "); print_ip_port(entry->proxy_dst_ip, entry->proxy_dst_port);
            VPRINT(2, " (src port remap to %u)\n", ntohs(entry->proxy_src_port));
        }

        ip_header->DstAddr = entry->proxy_dst_ip;
        *dst_port = entry->proxy_dst_port;
        *src_port = entry->proxy_src_port;

        VPRINT(3, "Rewriting outbound packet to:\n");
        VPRINT(3, "    Src: "); print_ip_port(ip_header->SrcAddr, *src_port);
        VPRINT(3, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, *dst_port);
        VPRINT(3, "\n");

        WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);

        if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
            VPRINT(1, "failed to send rewritten outbound packet\n");
        }

    } else {
        VPRINT(3, "Inbound packet intercepted");
        VPRINT(3, "    Src: "); print_ip_port(ip_header->SrcAddr, *src_port);
        VPRINT(3, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, *dst_port);
        VPRINT(3, "\n");

        idx = find_conn_inbound(entries, ip_header->SrcAddr, *src_port,
                                ip_header->DstAddr, *dst_port);
        if (idx < 0) {
            VPRINT(2, "No matching connection found, forwarding unchanged\n");
            if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
                VPRINT(1, "failed to send inbound packet\n");
            }
            return -1;
        }

        conn_entry_t *entry = &entries->table[idx];
        ip_header->SrcAddr = entry->orig_dst_ip;
        *src_port = entry->orig_dst_port;
        ip_header->DstAddr = entry->orig_src_ip;
        *dst_port = entry->orig_src_port;

        VPRINT(3, "Rewriting inbound packet to:\n");
        VPRINT(3, "    Src: "); print_ip_port(ip_header->SrcAddr, *src_port);
        VPRINT(3, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, *dst_port);
        VPRINT(3, "\n");

        WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);

        if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
            VPRINT(1, "failed to send rewritten inbound packet\n");
        }
    }

    conn_entry_t *entry = &entries->table[idx];

    if (tcp_rst) {
        remove_connection(entries, entry);
        VPRINT(3, "[CONN] Removed (RST)\n");
        VPRINT(3, "    Src: "); print_ip_port(ip_header->SrcAddr, *src_port);
        VPRINT(3, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, *dst_port);
        VPRINT(3, "\n");

    } else if (tcp_fin) {
        remove_connection(entries, entry);
        VPRINT(3, "[CONN] Removed (FIN)\n");
        VPRINT(3, "    Src: "); print_ip_port(ip_header->SrcAddr, *src_port);
        VPRINT(3, "  ->  Dst: "); print_ip_port(ip_header->DstAddr, *dst_port);
        VPRINT(3, "\n");

    } else {
        update_connection_seen(entry);
    }

    cleanup_connections(entries);
    return 0;
}


UINT32 handle_tcp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header, 
    const PWINDIVERT_TCPHDR tcp_header, UINT8 *packet, UINT packet_len) 
{
    return handle_conn_entry(addr, ip_header,
        &tcp_header->SrcPort, &tcp_header->DstPort, packet, packet_len,
        &conn_tcp_entries, tcp_header->Rst, tcp_header->Fin);
}
