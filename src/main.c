
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>


#include "proxydlp.h"



int main() {

    install_filter();

    intercept_packets_loop();

    return 0;
}
