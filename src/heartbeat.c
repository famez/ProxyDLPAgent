#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "heartbeat.h"
#include "https_client.h"

pthread_t heartbeat_thread;
pthread_mutex_t heartbeat_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t heartbeat_cond = PTHREAD_COND_INITIALIZER;
static volatile int running = 1;
static volatile int heartbeat_requested = 0;

void* heartbeat_worker(void* arg) {
    struct timespec ts;
    
    while (running) {
        // Calculate timeout for 2 minutes
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 120;

        pthread_mutex_lock(&heartbeat_mutex);

        // Wait until either heartbeat_requested is set or timeout occurs
        while (!heartbeat_requested && running) {
            if (pthread_cond_timedwait(&heartbeat_cond, &heartbeat_mutex, &ts) == ETIMEDOUT) {
                break; // timed out, send heartbeat
            }
        }

        // Reset request flag
        heartbeat_requested = 0;

        pthread_mutex_unlock(&heartbeat_mutex);

        if (running) {
            send_heartbeat();
        }
    }

    return NULL;
}

void init_heartbeat_worker() {
    running = 1;

    if (pthread_create(&heartbeat_thread, NULL, heartbeat_worker, NULL) != 0) {
        perror("Failed to create heartbeat thread");
        exit(EXIT_FAILURE);
    }
}

// Signal the heartbeat thread to send immediately
void request_heartbeat() {
    pthread_mutex_lock(&heartbeat_mutex);
    heartbeat_requested = 1;
    pthread_cond_signal(&heartbeat_cond);
    pthread_mutex_unlock(&heartbeat_mutex);
}

void finish_heartbeat_worker() {
    pthread_mutex_lock(&heartbeat_mutex);
    running = 0;
    pthread_cond_signal(&heartbeat_cond); // wake thread if waiting
    pthread_mutex_unlock(&heartbeat_mutex);

    pthread_join(heartbeat_thread, NULL);
}
