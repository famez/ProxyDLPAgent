#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <lmcons.h>
#include <iphlpapi.h>
#include <curl/curl.h>
#include <lm.h>

#include "https_client.h"

// Callback function to handle incoming data
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    fwrite(ptr, size, nmemb, stdout); // Print directly to stdout
    return total_size;
}


// Get computer name
void get_computer_name(char *buffer, DWORD size) {
    GetComputerNameA(buffer, &size);
}

// Get OS version (using GetVersionEx - old but simple)
void get_os_version(char *buffer, size_t size) {
    OSVERSIONINFOA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (GetVersionExA(&osvi)) {
        snprintf(buffer, size, "Windows %lu.%lu (Build %lu)",
                 (unsigned long)osvi.dwMajorVersion,
                 (unsigned long)osvi.dwMinorVersion,
                 (unsigned long)osvi.dwBuildNumber);
    } else {
        snprintf(buffer, size, "Unknown OS");
    }
}

// Get current user
void get_logged_in_users(char *buffer, size_t size) {
    LPWKSTA_USER_INFO_1 pBuf = NULL;
    LPWKSTA_USER_INFO_1 pTmpBuf;
    DWORD dwLevel = 1;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD i;

    buffer[0] = '\0';

    NET_API_STATUS nStatus = NetWkstaUserEnum(NULL,
                                              dwLevel,
                                              (LPBYTE*)&pBuf,
                                              dwPrefMaxLen,
                                              &dwEntriesRead,
                                              &dwTotalEntries,
                                              NULL);
    if ((nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) && pBuf != NULL) {
        pTmpBuf = pBuf;
        for (i = 0; i < dwEntriesRead; i++) {
            if (pTmpBuf != NULL && pTmpBuf->wkui1_username != NULL) {
                if (strlen(buffer) + wcslen(pTmpBuf->wkui1_username) + 2 < size) {
                    char username[UNLEN+1];
                    wcstombs(username, pTmpBuf->wkui1_username, sizeof(username));
                    strcat_s(buffer, size, username);
                    strcat_s(buffer, size, ", ");
                }
            }
            pTmpBuf++;
        }
        NetApiBufferFree(pBuf);

        size_t len = strlen(buffer);
        if (len > 2) buffer[len - 2] = '\0'; // trim trailing comma+space
    } else {
        snprintf(buffer, size, "No active users");
    }
}


// Get IP addresses
void get_ip_addresses(char *buffer, size_t size) {
    DWORD dwSize = 0;
    GetAdaptersInfo(NULL, &dwSize);  // Get required buffer size
    IP_ADAPTER_INFO *pAdapterInfo = (IP_ADAPTER_INFO*) malloc(dwSize);
    
    if (GetAdaptersInfo(pAdapterInfo, &dwSize) == NO_ERROR) {
        IP_ADAPTER_INFO *pAdapter = pAdapterInfo;
        buffer[0] = '\0';
        while (pAdapter) {
            strcat_s(buffer, size, pAdapter->IpAddressList.IpAddress.String);
            if (pAdapter->Next) strcat_s(buffer, size, ", ");
            pAdapter = pAdapter->Next;
        }
    } else {
        snprintf(buffer, size, "Unknown IP");
    }
    free(pAdapterInfo);
}

int connect_to_server() {
    CURL *curl;
    CURLcode res;

    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    char os_version[128];
    char logged_users[UNLEN + 1];
    char ip_addresses[512];
    const char *agent_version = "1.0.0";

    // Gather system info
    get_computer_name(computer_name, sizeof(computer_name));
    get_os_version(os_version, sizeof(os_version));
    get_logged_in_users(logged_users, sizeof(logged_users));
    get_ip_addresses(ip_addresses, sizeof(ip_addresses));

    // Build JSON string manually
    char json_data[1024];
    snprintf(json_data, sizeof(json_data),
             "{"
             "\"computer_name\":\"%s\","
             "\"os_version\":\"%s\","
             "\"user\":\"%s\","
             "\"ip_addresses\":\"%s\","
             "\"agent_version\":\"%s\""
             "}",
             computer_name, os_version, logged_users, ip_addresses, agent_version);

    printf("[DEBUG] JSON Payload: %s\n", json_data);

    printf("[INFO] Initializing libcurl...\n");
    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("[INFO] Creating CURL easy handle...\n");
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://10.228.217.251/api/agent/heartbeat");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

        // Set content-type to JSON
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Optional debugging
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        // Skip SSL verification (for testing only)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        printf("[INFO] Performing HTTPS POST request...\n");
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("[INFO] POST request completed successfully.\n");
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "[ERROR] Failed to create CURL handle.\n");
    }

    curl_global_cleanup();

    return 0;

}
