#ifndef MONITOR_H
#define MONITOR_H

#include <stdint.h>

#define PROXY_PORT      8080
#define HTTP_PORT       80
#define HTTPS_PORT      443
#define DNS_PORT        53


void add_addrs_for_monitoring(const uint32_t *ips, int count);

#endif
