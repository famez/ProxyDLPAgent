// dns.c
#include <stdio.h>
#include <windows.h>
#include <string.h>

#include "windivert.h"
#include "tracelog.h"

#define MAX_DNS_NAME_LEN     255
#define MAX_DNS_RECURSION    10
#define MAX_HOSTNAME_LEN     255
#define MAX_IP_ADDRESSES     16   // max IPv4 addresses per entry
#define MAX_DNS_NAMES        16   // max hostnames/aliases per entry
#define MAX_DNS_ENTRIES      128

typedef struct dns_entry {
    char hostnames[MAX_DNS_NAMES][MAX_HOSTNAME_LEN + 1];
    int num_hostnames;

    uint32_t ipv4_addresses[MAX_IP_ADDRESSES];
    int num_addresses;
} dns_entry_t;

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

dns_entry_t* dns_table_find_by_hostname(dns_table_t *table, const char *hostname);
dns_entry_t* dns_table_find_by_ip(dns_table_t *table, uint32_t ip);
dns_entry_t* dns_table_add_entry(dns_table_t *table, const char *hostname);
void dns_entry_add_hostname(dns_entry_t *entry, const char *hostname);
void dns_entry_add_ip(dns_entry_t *entry, uint32_t ip);
void dns_table_add_cname(dns_table_t *table, const char *alias, const char *canonical);


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

    if (payload_len - (ptr - base) < 10) return NULL;

    uint16_t type = ntohs(*(uint16_t*)ptr); ptr += 2;
    ptr += 2; // class
    ptr += 4; // ttl
    uint16_t rdlength = ntohs(*(uint16_t*)ptr); ptr += 2;

    if ((size_t)(ptr - base) + rdlength > payload_len) return NULL;

    if (type == 1 && rdlength == 4) { // A record
        dns_entry_t *entry = dns_table_add_entry(table, name);
        dns_entry_add_ip(entry, *(uint32_t*)ptr);
    } else if (type == 5) { // CNAME
        char cname[MAX_DNS_NAME_LEN + 1];
        const uint8_t *end = read_name_safe(ptr, base, payload_len, cname, 0);
        if (!end) return NULL;
        dns_table_add_cname(table, name, cname);
    }
    // TODO: AAAA support

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
}


// ----------------------------------------------------------------------
// Lookup and modification functions
// ----------------------------------------------------------------------

// Find entry by hostname
dns_entry_t* dns_table_find_by_hostname(dns_table_t *table, const char *hostname) {
    for (int i = 0; i < table->num_entries; i++) {
        for (int j = 0; j < table->entries[i].num_hostnames; j++) {
            if (strcmp(table->entries[i].hostnames[j], hostname) == 0) {
                return &table->entries[i];
            }
        }
    }
    return NULL;
}

// Find entry by IP
dns_entry_t* dns_table_find_by_ip(dns_table_t *table, uint32_t ip) {
    for (int i = 0; i < table->num_entries; i++) {
        for (int j = 0; j < table->entries[i].num_addresses; j++) {
            if (table->entries[i].ipv4_addresses[j] == ip) {
                return &table->entries[i];
            }
        }
    }
    return NULL;
}

// Add a new entry (if doesn't exist yet)
dns_entry_t* dns_table_add_entry(dns_table_t *table, const char *hostname) {
    dns_entry_t *entry = dns_table_find_by_hostname(table, hostname);
    if (entry) return entry;

    if (table->num_entries >= MAX_DNS_ENTRIES) {
        VPRINT(1, "[WARN] DNS table full, cannot add entry for %s\n", hostname);
        return NULL;
    }

    entry = &table->entries[table->num_entries++];
    memset(entry, 0, sizeof(*entry));
    strncpy(entry->hostnames[0], hostname, MAX_HOSTNAME_LEN);
    entry->num_hostnames = 1;
    entry->num_addresses = 0;
    return entry;
}

// Add an alias hostname to an existing entry
void dns_entry_add_hostname(dns_entry_t *entry, const char *hostname) {
    if (!entry) return;

    for (int i = 0; i < entry->num_hostnames; i++) {
        if (strcmp(entry->hostnames[i], hostname) == 0) {
            return; // already stored
        }
    }

    if (entry->num_hostnames < MAX_DNS_NAMES) {
        strncpy(entry->hostnames[entry->num_hostnames++], hostname, MAX_HOSTNAME_LEN);
    } else {
        VPRINT(1, "[WARN] Too many hostnames for entry, ignoring %s\n", hostname);
    }
}

// Add an IPv4 address to an entry
void dns_entry_add_ip(dns_entry_t *entry, uint32_t ip) {
    if (!entry) return;

    for (int i = 0; i < entry->num_addresses; i++) {
        if (entry->ipv4_addresses[i] == ip) {
            return; // avoid duplicates
        }
    }

    if (entry->num_addresses < MAX_IP_ADDRESSES) {
        entry->ipv4_addresses[entry->num_addresses++] = ip;

        unsigned char *ip_bytes = (unsigned char *)&ip;
        VPRINT(2, "[INFO] Added IP %u.%u.%u.%u to entry\n",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    } else {
        VPRINT(1, "[WARN] Too many IPs for entry, ignoring\n");
    }
}

// Store a CNAME mapping (alias → canonical)
void dns_table_add_cname(dns_table_t *table, const char *alias, const char *canonical) {
    dns_entry_t *alias_entry = dns_table_add_entry(table, alias);
    if (!alias_entry) return;

    dns_entry_add_hostname(alias_entry, canonical);

    VPRINT(2, "[INFO] CNAME: %s -> %s (stored in same entry)\n", alias, canonical);
}
