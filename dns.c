// dns.c
#include <stdio.h>
#include <windows.h>

#include "windivert.h"

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

static const uint8_t *read_name(const uint8_t *ptr, const uint8_t *base, char *out) {
    int len;
    char *pos = out;

    while ((len = *ptr++)) {
        if ((len & 0xC0) == 0xC0) { // compression pointer
            int offset = ((len & 0x3F) << 8) | *ptr++;
            read_name(base + offset, base, pos);
            return ptr;
        }
        memcpy(pos, ptr, len);
        pos += len;
        *pos++ = '.';
        ptr += len;
    }
    *(pos - 1) = '\0';
    return ptr;
}


static const uint8_t *read_record(const uint8_t *ptr, const uint8_t *base) {
    char name[256];
    ptr = read_name(ptr, base, name);

    uint16_t type = ntohs(*(uint16_t*)ptr); ptr += 2;
    uint16_t class = ntohs(*(uint16_t*)ptr); ptr += 2;
    uint32_t ttl = ntohl(*(uint32_t*)ptr); ptr += 4;
    uint16_t rdlength = ntohs(*(uint16_t*)ptr); ptr += 2;

    printf("Name: %s, Type: %u, Class: %u, TTL: %u, RDLENGTH: %u\n",
           name, type, class, ttl, rdlength);

    // Print RDATA for common types (A/AAAA/CNAME)
    if (type == 1 && rdlength == 4) { // A record
        printf("A: %u.%u.%u.%u\n", ptr[0], ptr[1], ptr[2], ptr[3]);
    } else if (type == 28 && rdlength == 16) { // AAAA record
        char addr[40];
        sprintf(addr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7],
                ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]);
        printf("AAAA: %s\n", addr);
    } else if (type == 5) { // CNAME
        char cname[256];
        read_name(ptr, base, cname);
        printf("CNAME: %s\n", cname);
    }

    return ptr + rdlength;
}


void dns_handle_packet(const PWINDIVERT_IPHDR ip_header, const PWINDIVERT_UDPHDR udp_header, const UINT8 *payload, const UINT payload_len) {

    // Example DNS logging: just print source/dest IP:port
    unsigned char *src_bytes = (unsigned char *)&ip_header->SrcAddr;
    unsigned char *dst_bytes = (unsigned char *)&ip_header->DstAddr;

    fprintf(stderr, "[DNS] Packet from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
        src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], ntohs(udp_header->SrcPort),
        dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3], ntohs(udp_header->DstPort));

    struct dns_header *hdr = (struct dns_header *)payload;

    fprintf(stderr, "ID: %u\n", ntohs(hdr->id));
    fprintf(stderr, "Questions: %u\n", ntohs(hdr->qdcount));
    fprintf(stderr, "Answers: %u\n", ntohs(hdr->ancount));

    const uint8_t *ptr = payload + sizeof(struct dns_header);

    for (int i = 0; i < ntohs(hdr->qdcount); i++) {
        char name[256];
        ptr = read_name(ptr, payload, name);
        uint16_t qtype = ntohs(*(uint16_t *)ptr); ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t *)ptr); ptr += 2;
        fprintf(stderr, "Query: %s, Type: %u, Class: %u\n", name, qtype, qclass);
    }

    // Answers
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        ptr = read_record(ptr, payload);
    }

    // Optionally: authority and additional records
    for (int i = 0; i < ntohs(hdr->nscount); i++) {
        ptr = read_record(ptr, payload);
    }
    for (int i = 0; i < ntohs(hdr->arcount); i++) {
        ptr = read_record(ptr, payload);
    }

}