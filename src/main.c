
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

    init_curl();

    register_agent();

    send_heartbeat();

    install_filter();

    intercept_packets_loop();

    close_curl();

    return 0;
}
