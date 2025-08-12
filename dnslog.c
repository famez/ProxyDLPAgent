// dnslog.c
#include <stdio.h>
#include <windows.h>
#include "windivert.h"

void dnslog_handle_packet(const PWINDIVERT_IPHDR ip_header, const PWINDIVERT_UDPHDR udp_header) {
    // Example DNS logging: just print source/dest IP:port
    unsigned char *src_bytes = (unsigned char *)&ip_header->SrcAddr;
    unsigned char *dst_bytes = (unsigned char *)&ip_header->DstAddr;

    fprintf(stderr, "[DNS] Packet from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
        src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], ntohs(udp_header->SrcPort),
        dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3], ntohs(udp_header->DstPort));
}
