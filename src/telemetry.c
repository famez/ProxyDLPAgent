#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "telemetry.h"

typedef struct {
    HostEntry* hosts;
    size_t count;
    size_t capacity;
    pthread_mutex_t mutex;
} TelemetrySystem;

static TelemetrySystem telemetry_system;

void init_telemetry() {
    telemetry_system.hosts = NULL;
    telemetry_system.count = 0;
    telemetry_system.capacity = 0;
    pthread_mutex_init(&telemetry_system.mutex, NULL);
}

void update_telemetry_data_multiple(const char* hostname, const uint32_t* ips, size_t num_ips) {
    if (!hostname || !ips || num_ips == 0) return;

    pthread_mutex_lock(&telemetry_system.mutex);

    // Search for hostname
    HostEntry* entry = NULL;
    for (size_t i = 0; i < telemetry_system.count; ++i) {
        if (strcmp(telemetry_system.hosts[i].hostname, hostname) == 0) {
            entry = &telemetry_system.hosts[i];
            break;
        }
    }

    // If hostname does not exist, create a new entry
    if (!entry) {
        if (telemetry_system.count == telemetry_system.capacity) {
            size_t new_capacity = telemetry_system.capacity == 0 ? 4 : telemetry_system.capacity * 2;
            HostEntry* new_hosts = realloc(telemetry_system.hosts, new_capacity * sizeof(HostEntry));
            if (!new_hosts) {
                perror("Failed to allocate memory for hosts");
                pthread_mutex_unlock(&telemetry_system.mutex);
                return;
            }
            telemetry_system.hosts = new_hosts;
            telemetry_system.capacity = new_capacity;
        }
        entry = &telemetry_system.hosts[telemetry_system.count];
        entry->hostname = strdup(hostname);
        entry->ips = NULL;
        entry->ip_count = 0;
        entry->ip_capacity = 0;
        telemetry_system.count++;
    }

    // Add each IP if it doesn't already exist
    for (size_t i = 0; i < num_ips; ++i) {
        uint32_t ip = ips[i];
        int exists = 0;
        for (size_t j = 0; j < entry->ip_count; ++j) {
            if (entry->ips[j].ip == ip) {
                exists = 1;
                break;
            }
        }
        if (exists) continue;

        // Expand IP array if needed
        if (entry->ip_count == entry->ip_capacity) {
            size_t new_capacity = entry->ip_capacity == 0 ? 4 : entry->ip_capacity * 2;
            IPEntry* new_ips = realloc(entry->ips, new_capacity * sizeof(IPEntry));
            if (!new_ips) {
                perror("Failed to allocate memory for IP list");
                break;
            }
            entry->ips = new_ips;
            entry->ip_capacity = new_capacity;
        }

        entry->ips[entry->ip_count].ip = ip;
        entry->ip_count++;
    }

    pthread_mutex_unlock(&telemetry_system.mutex);
}

HostEntry* get_telemetry_data(size_t* out_count) {
    pthread_mutex_lock(&telemetry_system.mutex);

    HostEntry* copy = malloc(telemetry_system.count * sizeof(HostEntry));
    if (!copy) {
        perror("Failed to allocate memory for telemetry copy");
        *out_count = 0;
        pthread_mutex_unlock(&telemetry_system.mutex);
        return NULL;
    }

    for (size_t i = 0; i < telemetry_system.count; ++i) {
        copy[i].hostname = strdup(telemetry_system.hosts[i].hostname);
        copy[i].ip_count = telemetry_system.hosts[i].ip_count;
        copy[i].ip_capacity = telemetry_system.hosts[i].ip_count;
        copy[i].ips = malloc(copy[i].ip_count * sizeof(IPEntry));
        for (size_t j = 0; j < copy[i].ip_count; ++j) {
            copy[i].ips[j].ip = telemetry_system.hosts[i].ips[j].ip;
        }
    }

    *out_count = telemetry_system.count;
    pthread_mutex_unlock(&telemetry_system.mutex);
    return copy;
}

void free_telemetry_data(HostEntry* data, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        free(data[i].hostname);
        free(data[i].ips);
    }
    free(data);
}

void cleanup_telemetry() {
    pthread_mutex_lock(&telemetry_system.mutex);
    for (size_t i = 0; i < telemetry_system.count; ++i) {
        free(telemetry_system.hosts[i].hostname);
        free(telemetry_system.hosts[i].ips);
    }
    free(telemetry_system.hosts);
    telemetry_system.hosts = NULL;
    telemetry_system.count = 0;
    telemetry_system.capacity = 0;
    pthread_mutex_unlock(&telemetry_system.mutex);

    pthread_mutex_destroy(&telemetry_system.mutex);
}
