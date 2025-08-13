// dnslog.h
#ifndef DNSLOG_H
#define DNSLOG_H

#include <windows.h>
#include "windivert.h"

void dns_handle_packet(PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, const UINT8 *payload, const UINT payload_len);

#endif
