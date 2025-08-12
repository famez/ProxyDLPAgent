// dnslog.h
#ifndef DNSLOG_H
#define DNSLOG_H

#include <windows.h>
#include "windivert.h"

void dnslog_handle_packet(PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header);

#endif
