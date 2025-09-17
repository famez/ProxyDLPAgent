// monitor.c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"
#include "tracelog.h"
#include "monitor.h"
#include "config.h"

#define MAX_MONITORED_IPS 256
#define HTTP_PORT   80
#define HTTPS_PORT  443
#define DNS_PORT    53

extern HANDLE handle; // declared in your main .c file

// Global storage of monitored IPs
static UINT32 monitored_ips[MAX_MONITORED_IPS];
static int num_monitored_ips = 0;

// Get the interface index and gateway used to reach dest_ip (network byte order)
BOOL get_route_for_dest(UINT32 dest_ip, DWORD *out_if_index, UINT32 *out_gateway)
{
    if (!out_if_index || !out_gateway)
        return FALSE;

    MIB_IPFORWARD_ROW2 row;
    memset(&row, 0, sizeof(row));

    SOCKADDR_INET dest;
    memset(&dest, 0, sizeof(dest));
    dest.Ipv4.sin_family = AF_INET;
    dest.Ipv4.sin_addr.S_un.S_addr = dest_ip;

    NETIO_STATUS status = GetBestRoute2(
        NULL,    // InterfaceLuid
        0,       // InterfaceIndex
        NULL,    // SourceAddress
        &dest,   // DestinationAddress
        0,       // AddressSortOptions
        &row,    // BestRoute
        NULL     // BestSourceAddress
    );

    if (status != NO_ERROR) {
        printf("GetBestRoute2 failed: %lu\n", status);
        return FALSE;
    }

    *out_if_index = row.InterfaceIndex;
    if (row.NextHop.si_family == AF_INET) {
        *out_gateway = row.NextHop.Ipv4.sin_addr.S_un.S_addr;
    } else {
        *out_gateway = 0; // direct route
    }

    return TRUE;
}

// Add a host route via specified interface and gateway
BOOL add_route(UINT32 dest_ip, UINT32 netmask, UINT32 gateway, DWORD if_index)
{
    MIB_IPFORWARDROW row;
    memset(&row, 0, sizeof(row));

    row.dwForwardDest = dest_ip;
    row.dwForwardMask = netmask;
    row.dwForwardNextHop = gateway;
    row.dwForwardIfIndex = if_index;
    row.dwForwardType = gateway ? 3 : 4; // 3 = indirect via gateway, 4 = direct
    row.dwForwardProto = MIB_IPPROTO_NETMGMT;
    row.dwForwardAge = 0;
    row.dwForwardMetric1 = 5;

    DWORD ret = CreateIpForwardEntry(&row);
    if (ret != NO_ERROR) {
        printf("CreateIpForwardEntry failed: %lu\n", ret);
        return FALSE;
    }

    return TRUE;
}


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

        char clause[2048];
        snprintf(clause, sizeof(clause),
            " or (outbound and tcp.DstPort == %d and ip.DstAddr == %s)"
            " or (outbound and tcp.DstPort == %d and ip.DstAddr == %s)"
            " or (outbound and udp.DstPort == %d and ip.DstAddr == %s)",        //For the quic protocol...
            HTTP_PORT, ipbuf,
            HTTPS_PORT, ipbuf,
            HTTPS_PORT, ipbuf);

        strncat(filter, clause, filter_len - strlen(filter) - 1);
    }

    //Get proxy IP
    const char *proxy_ip = get_proxy_ip();

    // Finally, add inbound packets coming from the proxy itself
    char proxy_clause[2048];
    snprintf(proxy_clause, sizeof(proxy_clause),
        " or (inbound and tcp.SrcPort == %d and ip.SrcAddr == %s)"
        " or (inbound and udp.SrcPort == %d and ip.SrcAddr == %s)",             //For quic protocol...
        PROXY_PORT, proxy_ip,
        PROXY_PORT, proxy_ip
    );

    strncat(filter, proxy_clause, filter_len - strlen(filter) - 1);
}

// Public API: called from dns.c when new IPs resolved
void add_addrs_for_monitoring(const uint32_t *ips, int count) {
    if (count <= 0) return;

    const char *proxy_ip = get_proxy_ip();

    struct in_addr proxy_addr;
    if (inet_pton(AF_INET, proxy_ip, &proxy_addr) != 1) {
        VPRINT(1, "[ERROR] Invalid proxy IP\n");
        return;
    }


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

        DWORD if_index;
        UINT32 gateway;

        //Add the same route for dest as for the proxy
        if(get_route_for_dest(proxy_addr.S_un.S_addr, &if_index, &gateway)) {
            if (add_route(ip, 0xFFFFFFFF, gateway, if_index)) {
                VPRINT(1, "[ROUTE] Route added successfully\n");
            } else {
                VPRINT(1, "[ERROR] Failed to add route\n");
            }
        }

    }

    // Rebuild filter
    char filter[8192];
    rebuild_filter(filter, sizeof(filter));

    VPRINT(1, "[MONITOR] Installing new filter: %s\n", filter);

    // Close old handle to unblock WinDivertRecv loop
    if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
    }

    // Open new handle
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        VPRINT(1, "[MONITOR] Failed to open WinDivert with new filter (%lu)\n",
                GetLastError());
        exit(EXIT_FAILURE);
    }
}
