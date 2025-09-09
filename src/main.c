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
#include "telemetry.h"

// --- Globals for Service Control ---
SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;
HANDLE stopEvent;

// Forward declarations
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);
void RunProxyDLP();

// --- Entry point ---
int main(int argc, char* argv[]) {
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

    // Run your agent logic
    RunProxyDLP();

    // Wait until stop requested
    WaitForSingleObject(stopEvent, INFINITE);

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

// --- Your existing program logic wrapped here ---
void RunProxyDLP() {
    init_telemetry();
    init_https();

    if (!load_values_from_registry()) {
        // If no values in registry, register the agent
        register_agent();
    }

    get_urls_to_monitor();

    // Start heartbeat worker to report status to the server
    init_heartbeat_worker();

    install_filter();

    intercept_packets_loop();   // <- This is your main loop

    end_https();
    finish_heartbeat_worker();
}
