// dns.c
#include <stdio.h>
#include <windows.h>

#include "windivert.h"

#define MAX_DNS_NAME_LEN     255
#define MAX_DNS_RECURSION    10
#define MAX_IP_ADDRESSES 16   // max IPv4 addresses per hostname
#define MAX_HOSTNAME_LEN 255

typedef struct dns_entry {
    char hostname[MAX_HOSTNAME_LEN + 1];
    uint32_t ipv4_addresses[MAX_IP_ADDRESSES];
    int num_addresses;
} dns_entry_t;

#define MAX_DNS_ENTRIES 128

typedef struct dns_table {
    dns_entry_t entries[MAX_DNS_ENTRIES];
    int num_entries;
} dns_table_t;


typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

static dns_table_t g_dns_table = { .num_entries = 0 };


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

static const uint8_t *read_record_safe(const uint8_t *ptr, const uint8_t *base,
                                       size_t payload_len, dns_table_t *table) {
    char name[MAX_DNS_NAME_LEN + 1];
    const uint8_t *new_ptr = read_name_safe(ptr, base, payload_len, name, 0);
    if (!new_ptr) return NULL;
    ptr = new_ptr;

    size_t remaining = payload_len - (ptr - base);
    if (remaining < 10) return NULL; // type(2) + class(2) + ttl(4) + rdlen(2)

    uint16_t type = ntohs(*(uint16_t*)ptr); ptr += 2;
    //uint16_t class = ntohs(*(uint16_t*)ptr); ptr += 2;
    //uint32_t ttl = ntohl(*(uint32_t*)ptr); ptr += 4;
    uint16_t rdlength = ntohs(*(uint16_t*)ptr); ptr += 2;

    if ((size_t)(ptr - base) + rdlength > payload_len) return NULL;

    if (type == 1 && rdlength == 4) { // A record
        fprintf(stderr, "A: %u.%u.%u.%u\n", ptr[0], ptr[1], ptr[2], ptr[3]);
        if (table->num_entries < MAX_DNS_ENTRIES) {
            dns_entry_t *entry = &table->entries[table->num_entries];
             // safely copy hostname
            size_t len = strnlen(name, MAX_HOSTNAME_LEN);
            memcpy(entry->hostname, name, len);
            entry->hostname[len] = '\0';
            entry->ipv4_addresses[0] = *(uint32_t*)ptr;  // store in network order
            entry->num_addresses = 1;
            table->num_entries++;
        }
    } 
    // handle CNAME or AAAA similarly if needed

    return ptr + rdlength;
}



void dns_handle_packet(const PWINDIVERT_IPHDR ip_header, const PWINDIVERT_UDPHDR udp_header,
                       const UINT8 *payload, const UINT payload_len) {

    unsigned char *src_bytes = (unsigned char *)&ip_header->SrcAddr;
    unsigned char *dst_bytes = (unsigned char *)&ip_header->DstAddr;

    fprintf(stderr, "[DNS] Packet from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
        src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], ntohs(udp_header->SrcPort),
        dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3], ntohs(udp_header->DstPort));

    if (payload_len < sizeof(struct dns_header)) return;
    const struct dns_header *hdr = (const struct dns_header *)payload;

    fprintf(stderr, "ID: %u\n", ntohs(hdr->id));
    fprintf(stderr, "Questions: %u\n", ntohs(hdr->qdcount));
    fprintf(stderr, "Answers: %u\n", ntohs(hdr->ancount));

    const uint8_t *ptr = payload + sizeof(struct dns_header);

    // Questions
    for (int i = 0; i < ntohs(hdr->qdcount); i++) {
        char name[MAX_DNS_NAME_LEN + 1];
        const uint8_t *new_ptr = read_name_safe(ptr, payload, payload_len, name, 0);
        if (!new_ptr) return;
        ptr = new_ptr;

        if ((size_t)(ptr - payload) + 4 > payload_len) return;
        uint16_t qtype = ntohs(*(uint16_t *)ptr); ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t *)ptr); ptr += 2;
        fprintf(stderr, "Query: %s, Type: %u, Class: %u\n", name, qtype, qclass);
    }

    // Answers
    for (int i = 0; i < ntohs(hdr->ancount); i++) {
        const uint8_t *new_ptr = read_record_safe(ptr, payload, payload_len, &g_dns_table);
        if (!new_ptr) return;
        ptr = new_ptr;
    }

    /*
    // Authority
    for (int i = 0; i < ntohs(hdr->nscount); i++) {
        const uint8_t *new_ptr = read_record_safe(ptr, payload, payload_len);
        if (!new_ptr) return;
        ptr = new_ptr;
    }

    // Additional
    for (int i = 0; i < ntohs(hdr->arcount); i++) {
        const uint8_t *new_ptr = read_record_safe(ptr, payload, payload_len);
        if (!new_ptr) return;
        ptr = new_ptr;
    }
    */

}
