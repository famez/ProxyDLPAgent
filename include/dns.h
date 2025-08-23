// dnslog.h
#ifndef DNS_H
#define DNS_H

#include <windows.h>
#include "windivert.h"

void dns_handle_packet(PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, const UINT8 *payload, const UINT payload_len);

BOOL add_domains_to_monitor(char **domain_list, int num_domains);

#endif
