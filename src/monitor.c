// monitor.c
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"
#include "tracelog.h"
#include "monitor.h"

#define MAX_MONITORED_IPS 256
#define HTTP_PORT   80
#define HTTPS_PORT  443
#define DNS_PORT    53

extern HANDLE handle; // declared in your main .c file

// Global storage of monitored IPs
static UINT32 monitored_ips[MAX_MONITORED_IPS];
static int num_monitored_ips = 0;

// Utility: convert IP (network order) to string
static void ip_to_str(UINT32 ip, char *buf, size_t buflen) {
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    inet_ntop(AF_INET, &addr, buf, (DWORD)buflen);
}
// Build filter string with DNS + HTTP(S) for monitored IPs + proxy inbound
static void rebuild_filter(char *filter, size_t filter_len) {
    // Always listen to DNS traffic
    snprintf(filter, filter_len,
        "(outbound and udp.DstPort == %d) or "
        "(inbound and udp.SrcPort == %d)",
        DNS_PORT, DNS_PORT);

    // Add monitored IPs for outbound HTTP/HTTPS
    for (int i = 0; i < num_monitored_ips; i++) {
        char ipbuf[64];
        ip_to_str(monitored_ips[i], ipbuf, sizeof(ipbuf));

        char clause[256];
        snprintf(clause, sizeof(clause),
            " or (outbound and tcp.DstPort == %d and ip.DstAddr == %s)"
            " or (outbound and tcp.DstPort == %d and ip.DstAddr == %s)",
            HTTP_PORT, ipbuf,
            HTTPS_PORT, ipbuf);

        strncat(filter, clause, filter_len - strlen(filter) - 1);
    }

    // Finally, add inbound packets coming from the proxy itself
    char proxy_clause[256];
    snprintf(proxy_clause, sizeof(proxy_clause),
        " or (inbound and tcp.SrcPort == %d and ip.SrcAddr == %s)",
        PROXY_PORT, PROXY_IP);

    strncat(filter, proxy_clause, filter_len - strlen(filter) - 1);
}

// Public API: called from dns.c when new IPs resolved
void add_addrs_for_monitoring(const uint32_t *ips, int count) {
    if (count <= 0) return;

    // Add to monitored list (avoid duplicates, simple O(n) scan)
    for (int i = 0; i < count; i++) {
        UINT32 ip = ips[i];
        int already = 0;
        for (int j = 0; j < num_monitored_ips; j++) {
            if (monitored_ips[j] == ip) {
                already = 1;
                break;
            }
        }
        if (!already && num_monitored_ips < MAX_MONITORED_IPS) {
            monitored_ips[num_monitored_ips++] = ip;
            unsigned char *b = (unsigned char *)&ip;
            VPRINT(1, "[MONITOR] Added IP %u.%u.%u.%u for monitoring\n",
                   b[0], b[1], b[2], b[3]);
        }
    }

    // Rebuild filter
    char filter[2048];
    rebuild_filter(filter, sizeof(filter));

    VPRINT(1, "[MONITOR] Installing new filter: %s\n", filter);

    // Close old handle to unblock WinDivertRecv loop
    if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
    }

    // Open new handle
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[MONITOR] Failed to open WinDivert with new filter (%lu)\n",
                GetLastError());
        exit(EXIT_FAILURE);
    }
}
