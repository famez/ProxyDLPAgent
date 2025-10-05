// dns.c
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <shlwapi.h>

#include "windivert.h"
#include "tracelog.h"
#include "telemetry.h"
#include "heartbeat.h"
#include "config.h"

#define MAX_DNS_NAME_LEN     255
#define MAX_DNS_RECURSION    10
#define MAX_HOSTNAME_LEN     255
#define MAX_IP_ADDRESSES     16   // max IPv4 addresses per entry
#define MAX_DNS_NAMES        16   // max hostnames/aliases per entry
#define MAX_DNS_ENTRIES      128




typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;



typedef struct dns_domains {
    char **domain_list;
    int num_domains;
} dns_domains_t;

dns_domains_t dns_monitored_domains_table;

// Returns TRUE if qname matches any monitored domain.
// Matching rules:
//  - exact match (case-insensitive) OR
//  - qname is a subdomain of monitored domain (e.g. "a.b.example.com" matches "example.com")
// qname may include a trailing '.' (we strip it).
static BOOL dns_qname_matches_monitored(const char *qname)
{
    if (!qname) return FALSE;

    char qnorm[MAX_DNS_NAME_LEN + 1];
    strncpy(qnorm, qname, MAX_DNS_NAME_LEN);
    qnorm[MAX_DNS_NAME_LEN] = '\0';

    // strip trailing dot if present
    size_t qlen = strlen(qnorm);
    if (qlen > 0 && qnorm[qlen - 1] == '.') {
        qnorm[qlen - 1] = '\0';
        qlen--;
    }

    for (int i = 0; i < dns_monitored_domains_table.num_domains; i++) {
        const char *mon = dns_monitored_domains_table.domain_list[i];
        if (!mon) continue;
        size_t mlen = strlen(mon);
        if (mlen == 0) continue;

        // exact match (case-insensitive)
        if (_stricmp(qnorm, mon) == 0) {
            return TRUE;
        }

        // qname ends with '.' + monitored (i.e. a subdomain)
        // ensure qlen > mlen and the char before the suffix is '.'
        if (qlen > mlen + 1) {
            const char *suffix = qnorm + (qlen - mlen);
            if (_stricmp(suffix, mon) == 0 && qnorm[qlen - mlen - 1] == '.') {
                return TRUE;
            }
        }
    }

    return FALSE;
}


static const uint8_t *read_name_safe(const uint8_t *ptr, const uint8_t *base,
                                     size_t payload_len, char *out,
                                     int depth) {
    if (depth > MAX_DNS_RECURSION) {
        strcpy(out, "<too deep>");
        return NULL;
    }

    size_t offset = ptr - base;
    if (offset >= payload_len) return NULL;

    int len;
    char *pos = out;
    size_t remaining = MAX_DNS_NAME_LEN;
    while (offset < payload_len && (len = *ptr++)) {
        offset++;
        if ((len & 0xC0) == 0xC0) { // compression pointer
            if (offset >= payload_len) return NULL;
            int pointer_offset = ((len & 0x3F) << 8) | *ptr++;
            if ((size_t)pointer_offset >= payload_len) return NULL;
            read_name_safe(base + pointer_offset, base, payload_len, pos, depth + 1);
            return ptr;
        }
        if (len > 63 || offset + len > payload_len || len >= remaining) return NULL;
        memcpy(pos, ptr, len);
        pos += len;
        remaining -= len + 1;
        *pos++ = '.';
        ptr += len;
        offset += len;
    }
    if (pos != out)
        *(pos - 1) = '\0';
    else
        *pos = '\0';
    return ptr;
}

// Build a DNS response packet (IP+UDP+DNS) into outbuf.
// Returns total packet length on success (>0), 0 on failure.
//
// This version does NOT swap IPs or ports.
UINT build_dns_response_packet(
    const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header,
    const UINT8 *query_payload,
    UINT query_len,
    const char *queried_name,
    uint32_t spoof_ip,         // in network order
    UINT8 *outbuf,
    UINT outbuf_len)
{
    if (!ip_header || !udp_header || !query_payload || !queried_name || !outbuf) return 0;

    // DNS payload
    uint8_t dns_payload[512];
    memset(dns_payload, 0, sizeof(dns_payload));
    struct dns_header *resp_hdr = (struct dns_header *)dns_payload;
    const struct dns_header *query_hdr = (const struct dns_header *)query_payload;

    // Copy ID and set flags
    resp_hdr->id = query_hdr->id;
    resp_hdr->flags = htons(0x8180); // standard response, recursion available, no error
    resp_hdr->qdcount = htons(1);
    resp_hdr->ancount = htons(1);
    resp_hdr->nscount = 0;
    resp_hdr->arcount = 0;

    uint8_t *dptr = dns_payload + sizeof(struct dns_header);

    // Write queried name
    const char *pos = queried_name;
    while (*pos) {
        const char *dot = strchr(pos, '.');
        size_t len = dot ? (size_t)(dot - pos) : strlen(pos);
        if (len > 63) return 0; // invalid label
        *dptr++ = (uint8_t)len;
        if ((UINT)(dptr - dns_payload) + len >= sizeof(dns_payload)) return 0;
        memcpy(dptr, pos, len);
        dptr += len;
        if (!dot) break;
        pos = dot + 1;
    }
    *dptr++ = 0; // end of name

    // Question section
    *(uint16_t *)dptr = htons(1); dptr += 2; // QTYPE = A
    *(uint16_t *)dptr = htons(1); dptr += 2; // QCLASS = IN

    // Answer section
    *(uint16_t *)dptr = htons(0xC00C); dptr += 2; // NAME = pointer to query name (offset 12)
    *(uint16_t *)dptr = htons(1); dptr += 2;      // TYPE = A
    *(uint16_t *)dptr = htons(1); dptr += 2;      // CLASS = IN
    *(uint32_t *)dptr = htonl(60); dptr += 4;     // TTL = 60
    *(uint16_t *)dptr = htons(4); dptr += 2;      // RDLENGTH = 4
    *(uint32_t *)dptr = spoof_ip; dptr += 4;      // RDATA = spoofed IP

    UINT dns_len = (UINT)(dptr - dns_payload);

    // Copy existing headers (no swapping)
    WINDIVERT_IPHDR ip_out = *ip_header;
    WINDIVERT_UDPHDR udp_out = *udp_header;

    // Set lengths only
    UINT ip_total_len = (UINT)(sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + dns_len);
    ip_out.Length = htons((uint16_t)ip_total_len);
    udp_out.Length = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + dns_len));
    udp_out.Checksum = 0; // to be recomputed later

    if (outbuf_len < ip_total_len) return 0;

    UINT offset = 0;
    memcpy(outbuf + offset, &ip_out, sizeof(ip_out)); offset += sizeof(ip_out);
    memcpy(outbuf + offset, &udp_out, sizeof(udp_out)); offset += sizeof(udp_out);
    memcpy(outbuf + offset, dns_payload, dns_len); offset += dns_len;

    return offset;
}


UINT dns_handle_packet(
    const PWINDIVERT_IPHDR ip_header,
    const PWINDIVERT_UDPHDR udp_header,
    const UINT8 *payload,
    const UINT payload_len,
    UINT8 *outbuf,
    UINT outbuf_len)
{
    if (!ip_header || !udp_header || !payload || !outbuf) return 0;

    const struct dns_header *hdr = (const struct dns_header *)payload;
    if (payload_len < sizeof(struct dns_header)) return 0;
    if (ntohs(hdr->qdcount) == 0) return 0;

    const uint8_t *ptr = payload + sizeof(struct dns_header);
    char qname[MAX_DNS_NAME_LEN + 1];
    const uint8_t *new_ptr = read_name_safe(ptr, payload, payload_len, qname, 0);
    if (!new_ptr) return 0;
    ptr = new_ptr;

    if ((size_t)(ptr - payload) + 4 > payload_len) return 0;
    uint16_t qtype = ntohs(*(uint16_t *)ptr); ptr += 2;
    uint16_t qclass = ntohs(*(uint16_t *)ptr); ptr += 2;

    VPRINT(2, "[DNS] Query: %s, Type=%u, Class=%u\n", qname, qtype, qclass);

    if (qtype == 1 && qclass == 1 && dns_qname_matches_monitored(qname)) {
        const char *proxy_ip_str = get_proxy_ip();
        uint32_t spoof_ip = inet_addr(proxy_ip_str); // convert string to network order uint32_t

        VPRINT(1, "[DNS] Building spoofed response for %s\n", qname);

        UINT pkt_len = build_dns_response_packet(ip_header, udp_header,
                                                 payload, payload_len,
                                                 qname, spoof_ip,
                                                 outbuf, outbuf_len);
        if (pkt_len == 0) {
            VPRINT(1, "[ERR] Failed to build DNS response packet\n");
            return 0;
        }

        return pkt_len;
    }

    return 0;
}


void free_domains_list() {
    for (int i = 0; i < dns_monitored_domains_table.num_domains; i++) {
        if (dns_monitored_domains_table.domain_list[i]) {
            free(dns_monitored_domains_table.domain_list[i]);  // free each string
        }
    }

    free(dns_monitored_domains_table.domain_list); // free the list itself
}

BOOL add_domains_to_monitor(char **domain_list, int num_domains) {
    VPRINT(2, "[INFO] add_domains_to_monitor call\n");

    dns_monitored_domains_table.domain_list = domain_list;
    dns_monitored_domains_table.num_domains = num_domains;

    return TRUE;
}