#ifndef PROXYDLP_H
#define PROXYDLP_H

#include "windivert.h"

UINT32 install_filter();

UINT32 intercept_packets_loop();

UINT32 handle_udp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header, UINT8 *packet, UINT packet_len, UINT8 *payload, UINT payload_len);

UINT32 handle_tcp_packet(const PWINDIVERT_ADDRESS addr, const PWINDIVERT_IPHDR ip_header, 
    const PWINDIVERT_TCPHDR tcp_header, UINT8 *packet, UINT packet_len);

#endif
