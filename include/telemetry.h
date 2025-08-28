#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t ip;
} IPEntry;

typedef struct {
    char* hostname;
    IPEntry* ips;
    size_t ip_count;
    size_t ip_capacity;
} HostEntry;

// Initialize telemetry system
void init_telemetry();

// Add an array of IP addresses to a hostname (thread-safe)
void update_telemetry_data_multiple(const char* hostname, const uint32_t* ips, size_t num_ips);

// Get a copy of all telemetry data (thread-safe)
HostEntry* get_telemetry_data(size_t* out_count);

// Free telemetry data copy returned by get_telemetry_data
void free_telemetry_data(HostEntry* data, size_t count);

// Clean up telemetry system
void cleanup_telemetry();

#endif // TELEMETRY_H
