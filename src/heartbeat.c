#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     // for sleep()
#include <pthread.h>
#include <signal.h>     // for handling stop signals

#include "heartbeat.h"
#include "https_client.h"

pthread_t heartbeat_thread;
static volatile int running = 1;

void* heartbeat_worker(void* arg) {
    while (running) {
        send_heartbeat();
        sleep(120); // sleep for 120 seconds (2 minutes)
    }
    return NULL;
}

void init_heartbeat_worker() {

    running = 1;
    
    // Start heartbeat thread
    if (pthread_create(&heartbeat_thread, NULL, heartbeat_worker, NULL) != 0) {
        perror("Failed to create heartbeat thread");
        exit(EXIT_FAILURE);
    }

}

void finish_heartbeat_worker() {

    running = 0;

    pthread_join(heartbeat_thread, NULL);

}