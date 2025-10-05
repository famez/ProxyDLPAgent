// dnslog.h
#ifndef DNS_H
#define DNS_H

#include <windows.h>
#include "windivert.h"

UINT dns_handle_packet(const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header,
    const UINT8 *payload,
    const UINT payload_len,
    UINT8 *outbuf,
    UINT outbuf_len);

UINT build_dns_response_packet(
    const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header,
    const UINT8 *query_payload,
    UINT query_len,
    const char *queried_name,
    uint32_t spoof_ip,         // in network order
    UINT8 *outbuf,
    UINT outbuf_len);

BOOL add_domains_to_monitor(char **domain_list, int num_domains);

#endif
