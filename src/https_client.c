#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <lmcons.h>
#include <iphlpapi.h>
#include <curl/curl.h>
#include <lm.h>
#include <cJSON.h>


#include "https_client.h"
#include "tracelog.h"


struct response_string {
    char *ptr;
    size_t len;
};

void init_response_string(struct response_string *s) {
    s->len = 0;
    s->ptr = malloc(1);  // start with empty string
    s->ptr[0] = '\0';
}


size_t write_callback_register_agent(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t new_len = size * nmemb;
    struct response_string *s = (struct response_string *)userdata;

    s->ptr = realloc(s->ptr, s->len + new_len + 1);
    memcpy(s->ptr + s->len, ptr, new_len);
    s->len += new_len;
    s->ptr[s->len] = '\0';

    return new_len;
}


// Callback function to handle incoming data
size_t write_callback_generic_log(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    fwrite(ptr, size, nmemb, stdout); // Print directly to stdout
    return total_size;
}


void init_curl() {
    VPRINT(1, "[INFO] Initializing libcurl...\n");
    curl_global_init(CURL_GLOBAL_DEFAULT);
}


void close_curl() {
    curl_global_cleanup();
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

int send_heartbeat() {
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

    VPRINT(1, "[DEBUG] JSON Payload: %s\n", json_data);

    VPRINT(1, "[INFO] Creating CURL easy handle...\n");
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, BASE_URL HEARTBEAT_ENDPOINT);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_generic_log);

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

        VPRINT(1, "[INFO] Performing HTTPS POST request...\n");
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            VPRINT(1, "[INFO] POST request completed successfully.\n");
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

    } else {
        VPRINT(1, "[ERROR] Failed to create CURL handle.\n");
    }

    return 0;

}


void save_string_to_registry(const char *value_name, const char *value_data) {
    HKEY hKey;
    LONG result;

    result = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\ProxyDlp",
        0, NULL, 0,
        KEY_WRITE, NULL,
        &hKey, NULL
    );

    if (result == ERROR_SUCCESS) {
        result = RegSetValueExA(
            hKey,
            value_name,         // registry value name (e.g. "guid" or "token")
            0,
            REG_SZ,
            (const BYTE*)value_data,
            (DWORD)(strlen(value_data) + 1)
        );

        if (result != ERROR_SUCCESS) {
            VPRINT(2, "[ERROR] Failed to set registry value %s (error %ld)\n",
                    value_name, result);
        } else {
            VPRINT(2, "[INFO] Saved %s to registry successfully.\n", value_name);
        }

        RegCloseKey(hKey);
    } else {
        VPRINT(2, "[ERROR] Failed to open/create registry key (error %ld)\n", result);
    }
}


int register_agent() {
    CURL *curl;
    CURLcode res;
    struct response_string s;

    init_response_string(&s);

    VPRINT(1, "[INFO] Creating CURL easy handle...\n");
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, BASE_URL REGISTER_ENDPOINT);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_register_agent);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

        // Debug
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        VPRINT(1, "[INFO] Performing HTTPS GET request...\n");
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {

            VPRINT(2, "[INFO] GET request completed successfully.\n");
            VPRINT(2, "[DEBUG] Response: %s\n", s.ptr);

            // Parse JSON response using cJSON
            cJSON *json = cJSON_Parse(s.ptr);
            if (!json) {
                VPRINT(2, "[ERROR] Failed to parse JSON response\n");
            } else {
                // Extract GUID
                cJSON *guid_item = cJSON_GetObjectItemCaseSensitive(json, "guid");
                // Extract token
                cJSON *token_item = cJSON_GetObjectItemCaseSensitive(json, "token");

                if (cJSON_IsString(guid_item) && guid_item->valuestring &&
                    cJSON_IsString(token_item) && token_item->valuestring) {
                    
                    VPRINT(2, "[INFO] Extracted agent_id: %s\n", guid_item->valuestring);
                    //VPRINT(2, "[INFO] Extracted token: %s\n", token_item->valuestring);

                    // Save both to registry / file
                    save_string_to_registry("guid", guid_item->valuestring);
                    save_string_to_registry("token", token_item->valuestring);

                } else {
                    VPRINT(2, "[ERROR] Missing 'guid' or 'token' in response\n");
                }

                cJSON_Delete(json);

            }

        }

        curl_easy_cleanup(curl);
    } else {
        VPRINT(1, "[ERROR] Failed to create CURL handle.\n");
    }

    free(s.ptr);

    return 0;
}


int get_domain_names_to_watch() {
    return 0;
}
