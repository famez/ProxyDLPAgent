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


#define PROXY_PORT      8080
#define HTTPS_PORT      443
#define DNS_PORT        53

#define MAXBUF          0xFFFF
#define MAX_CONN 1024
#define IDLE_TIMEOUT 300  // seconds (5 min)

extern volatile int g_Running;

HANDLE handle;

static void error(const char *msg) {
    VPRINT(1, "%s\n", msg);
    exit(EXIT_FAILURE);
}

UINT32 install_filter(){

    char filter[256];
    int r;


    r = snprintf(filter, sizeof(filter),
        "(inbound and udp.SrcPort == %d)",
        DNS_PORT);

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

        if (udp_header) {
            /*UINT32 result =*/ handle_udp_packet(&addr, ip_header, udp_header, packet, packet_len, payload, payload_len);
        }

    }

    WinDivertClose(handle);
    return 0;
}


UINT32 handle_udp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header, UINT8 *packet, UINT packet_len, UINT8 *payload, UINT payload_len) {

   
   if(!addr->Outbound && ntohs(udp_header->SrcPort) == DNS_PORT) {        //DNS inbound answers

        VPRINT(3, "Received DNS response <-- \n");
        UINT8 outbuf[1500];
        UINT pkt_len = dns_handle_packet(ip_header, udp_header, payload, payload_len, outbuf, sizeof(outbuf));
        if (pkt_len > 0) {
            // send your spoofed response
            WinDivertHelperCalcChecksums(outbuf, pkt_len, NULL, 0);
            WinDivertSend(handle, outbuf, pkt_len, NULL, addr);
        } else {
            //Just, forward the packet.

            VPRINT(3, "Forwarding the packet, no modifications \n");
            WinDivertSend(handle, packet, packet_len, NULL, addr);
        }
        return 0;
    }

    // Just, forward if anything else.
        
    if (!WinDivertSend(handle, packet, packet_len, NULL, addr)) {
        VPRINT(1, "failed to send rewritten inbound packet\n");
        return -1;
    }

    return 0;

}