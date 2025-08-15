
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>


#include "proxydlp.h"
#include "https_client.h"


int main() {

    printf("[INFO] Hello...\n");

    connect_to_server();

    install_filter();

    intercept_packets_loop();

    return 0;
}
