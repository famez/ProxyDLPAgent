#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>


#include "proxydlp.h"
#include "https_client.h"
#include "config.h"
#include "heartbeat.h"
#include "telemetry.h"
#include "tracelog.h"

pthread_t workerThread;
volatile int g_Running = 1;


// --- Globals for Service Control ---
SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HANDLE stopEvent;

// Forward declarations
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);
void RunProxyDLP();
void DeregisterAgent();

void* ProxyDLPThread(void* arg) {
    RunProxyDLP();
    return NULL;
}


// --- Entry point ---
int main(int argc, char* argv[]) {

    // Check for command-line arguments first
    if (argc > 1) {
        if (_stricmp(argv[1], "/deregister") == 0) {
            DeregisterAgent();  // <-- your function to remove/unregister service
            return 0;
        }

    }


    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { "ProxyDLPAgent", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    // Try to run as service
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        // If not started by SCM, run interactively (for debugging)
        RunProxyDLP();
    }

    return 0;
}

// --- Service main ---
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler("ProxyDLPAgent", ServiceCtrlHandler);
    if (!hStatus) return;

    // Notify SCM that we are running
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    // Create stop event
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (pthread_create(&workerThread, NULL, ProxyDLPThread, NULL) != 0) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = 1;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;
    }

    // Wait until stop requested
    WaitForSingleObject(stopEvent, INFINITE);

    // Tell loop to stop
    g_Running = 0;

    // Wait for worker to exit
    pthread_join(workerThread, NULL);

    // Cleanup before stopping
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
}

// --- Handle service control requests ---
void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch(ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(hStatus, &ServiceStatus);

            // Signal to stop
            SetEvent(stopEvent);
            break;
        default:
            break;
    }
}

// Function to resolve hostname to IP address (IPv4)
int resolve_hostname(const char *hostname, char *ip_str, size_t ip_str_len) {
    WSADATA wsaData;
    struct addrinfo hints, *res = NULL;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        return -1; // Failed to initialize Winsock
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        WSACleanup();
        return -2; // DNS lookup failed
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    if (inet_ntop(AF_INET, &(addr->sin_addr), ip_str, ip_str_len) == NULL) {
        freeaddrinfo(res);
        WSACleanup();
        return -3; // Failed to convert IP to string
    }

    freeaddrinfo(res);
    WSACleanup();
    return 0; // Success
}

void RunProxyDLP() {

    char proxy_ip[INET_ADDRSTRLEN];

    //Remove old logs
    remove(LOG_FILE_PATH);

    VPRINT(1, "ProxyDLP started\n");

    init_telemetry();
    init_https();

    if (!load_values_from_registry()) {
        // If no values in registry, register the agent
        register_agent();
    }

    const char *hostname = get_proxy_hostname();

    //Get IP address of the proxy from the hostname or domain name
    if (resolve_hostname(hostname, proxy_ip, sizeof(proxy_ip)) == 0) {
        VPRINT(1, "IP Address: %s\n", proxy_ip);
    } else {
        VPRINT(1, "Failed to resolve hostname.\n");
    }

    set_proxy_ip(proxy_ip);

    get_urls_to_monitor();

    // Start heartbeat worker to report status to the server
    init_heartbeat_worker();

    install_filter();

    intercept_packets_loop();   // <- This is your main loop

    end_https();
    finish_heartbeat_worker();
}


void DeregisterAgent() {
    
    init_https();

    if (load_values_from_registry()) {
        deregister_agent();
    }   

    end_https();
}
