
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>


#include "proxydlp.h"
#include "https_client.h"
#include "config.h"


int main() {

    init_https();
    
    if (!load_values_from_registry()) {
        
        //If no values in registry, then let's proceed to register the agent.
        register_agent();

    }
    
    send_heartbeat();

    install_filter();

    intercept_packets_loop();

    end_https();

    return 0;
}
