
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
#include "heartbeat.h"


int main() {

    init_https();
    
    if (!load_values_from_registry()) {
        
        //If no values in registry, then let's proceed to register the agent.
        register_agent();

    }
    
    get_urls_to_monitor();

    //Start heartbeat worker to report status to the server
    init_heartbeat_worker();

    install_filter();

    intercept_packets_loop();

    end_https();

    finish_heartbeat_worker();

    return 0;
}
