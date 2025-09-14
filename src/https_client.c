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
#include "config.h"
#include "dns.h"
#include "telemetry.h"

typedef struct {
    char *data;
    size_t size;
} MemoryStruct;


struct response_string {
    char *ptr;
    size_t len;
};

void init_response_string(struct response_string *s) {
    s->len = 0;
    s->ptr = malloc(1);  // start with empty string
    s->ptr[0] = '\0';
}

size_t write_callback_store(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userdata;

    char *tmp = realloc(mem->data, mem->size + total_size + 1);
    if (!tmp) {
        VPRINT(1, "[ERROR] Not enough memory for response\n");
        return 0; // curl will abort
    }

    mem->data = tmp;
    memcpy(&(mem->data[mem->size]), ptr, total_size);
    mem->size += total_size;
    mem->data[mem->size] = '\0'; // null-terminate
    return total_size;
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


void init_https() {
    VPRINT(1, "[INFO] Initializing libcurl...\n");
    curl_global_init(CURL_GLOBAL_DEFAULT);
}


void end_https() {
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
    long http_code = 0;
    int ret = -1; // default: error

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

    //Get telemetry data
    size_t out_count;
    HostEntry* telemetry_entries = get_telemetry_data(&out_count);

    // Get guid and token from registry
    const char * guid = get_guid();
    const char * token = get_token();

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    // Build JSON with cJSON
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        VPRINT(3, "[ERROR] Failed to create JSON object\n");
        return -4;
    }

    cJSON_AddStringToObject(root, "computer_name", computer_name);
    cJSON_AddStringToObject(root, "os_version", os_version);
    cJSON_AddStringToObject(root, "user", logged_users);
    cJSON_AddStringToObject(root, "ip_addresses", ip_addresses);
    cJSON_AddStringToObject(root, "agent_version", agent_version);
    cJSON_AddStringToObject(root, "guid", guid);

    // Add telemetry data as a JSON object
    cJSON *telemetry_json = cJSON_CreateObject();
    if (telemetry_json) {
        for (size_t i = 0; i < out_count; ++i) {
            cJSON *ip_array = cJSON_CreateArray();
            for (size_t j = 0; j < telemetry_entries[i].ip_count; ++j) {
                struct in_addr addr;
                addr.s_addr = telemetry_entries[i].ips[j].ip;  // convert to network byte order
                const char *ip_str = inet_ntoa(addr);
                cJSON_AddItemToArray(ip_array, cJSON_CreateString(ip_str));
            }
            cJSON_AddItemToObject(telemetry_json, telemetry_entries[i].hostname, ip_array);
        }
        cJSON_AddItemToObject(root, "telemetry", telemetry_json);
    }

    free_telemetry_data(telemetry_entries, out_count);

    char *json_data = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_data) {
        VPRINT(1, "[ERROR] Failed to print JSON payload\n");
        return -5;
    }

    VPRINT(1, "[DEBUG] JSON Payload: %s\n", json_data);

    VPRINT(1, "[INFO] Creating CURL easy handle...\n");
    curl = curl_easy_init();
    if (!curl) {
        VPRINT(1, "[ERROR] Failed to create CURL handle.\n");
        free(json_data);
        return -6;
    }

    const char *hostname = get_proxy_hostname();
    char base_url[256];
    snprintf(base_url, sizeof(base_url), "https://%s/api/agent/" HEARTBEAT_ENDPOINT, hostname);

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_generic_log);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Debug/SSL
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, PROXYDLP_CA_FILE);

    VPRINT(1, "[INFO] Performing HTTPS POST request...\n");
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        VPRINT(1, "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        ret = -7;
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            VPRINT(1, "[ERROR] Server returned HTTP %ld\n", http_code);
            ret = -8;
        } else {
            VPRINT(1, "[INFO] POST request completed successfully.\n");
            ret = 0; // success ✅
        }
    }

    free(json_data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return ret;
}


int register_agent() {
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    struct response_string s;
    int ret = -1; // default: error

    init_response_string(&s);

    VPRINT(1, "[INFO] Creating CURL easy handle...\n");
    curl = curl_easy_init();
    if (!curl) {
        VPRINT(1, "[ERROR] Failed to create CURL handle.\n");
        free(s.ptr);
        return -2; // CURL init failed
    }

    const char *hostname = get_proxy_hostname();
    char base_url[256];
    snprintf(base_url, sizeof(base_url), "https://%s/api/agent/" REGISTER_ENDPOINT, hostname);

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_register_agent);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);

    // Debug / SSL relax
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, PROXYDLP_CA_FILE);

    VPRINT(1, "[INFO] Performing HTTPS GET request...\n");
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        VPRINT(1, "[ERROR] curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        ret = -3; // network error
    } else {
        // Check HTTP response code
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            VPRINT(1, "[ERROR] Server returned HTTP %ld\n", http_code);
            ret = -4; // bad HTTP response
        } else {
            VPRINT(2, "[INFO] GET request completed successfully.\n");

            // Parse JSON
            cJSON *json = cJSON_Parse(s.ptr);
            if (!json) {
                VPRINT(2, "[ERROR] Failed to parse JSON response\n");
                ret = -5; // JSON parse error
            } else {
                cJSON *guid_item = cJSON_GetObjectItemCaseSensitive(json, "guid");
                cJSON *token_item = cJSON_GetObjectItemCaseSensitive(json, "token");

                if (cJSON_IsString(guid_item) && guid_item->valuestring &&
                    cJSON_IsString(token_item) && token_item->valuestring) {
                    
                    VPRINT(2, "[INFO] Extracted agent_id: %s\n", guid_item->valuestring);

                    set_guid(guid_item->valuestring);
                    set_token(token_item->valuestring);

                    if (!save_values_to_registry()) {
                        VPRINT(1, "[ERROR] Failed to save guid or token to registry (insufficient permissions?)\n");
                        ret = -6;
                    } else {
                        ret = 0; // SUCCESS ✅
                    }

                } else {
                    VPRINT(2, "[ERROR] Missing 'guid' or 'token' in response\n");
                    ret = -8;
                }

                cJSON_Delete(json);
            }
        }
    }

    curl_easy_cleanup(curl);
    free(s.ptr);

    return ret;
}

int deregister_agent() {
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    int ret = -1;

    const char *guid = get_guid();
    const char *token = get_token();
    if (!guid || !token) {
        VPRINT(1, "[ERROR] Missing guid or token\n");
        return -2;
    }

    // Prepare authorization header
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    // Build deregister URL
    char url[1024];
    const char *hostname = get_proxy_hostname();
    char base_url[256];
    snprintf(base_url, sizeof(base_url), "https://%s/api/agent/" DEREGISTER_ENDPOINT, hostname);
    snprintf(url, sizeof(url), "%s?guid=%s", base_url, guid);

    VPRINT(1, "[DEBUG] Deregister URL: %s\n", url);

    curl = curl_easy_init();
    if (!curl) return -3;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, PROXYDLP_CA_FILE);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        VPRINT(1, "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        ret = -4;
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        VPRINT(1, "[ERROR] Deregister failed, HTTP %ld\n", http_code);
        ret = -5;
        goto cleanup;
    }

    VPRINT(1, "[INFO] Deregister successful\n");
    ret = 0; // success

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ret;
}


int get_urls_to_monitor() {
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    int ret = -1;

    const char *guid = get_guid();
    const char *token = get_token();
    if (!guid || !token) {
        VPRINT(1, "[ERROR] Missing guid or token\n");
        return -2;
    }

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    char url[1024];

    const char *hostname = get_proxy_hostname();
    char base_url[256];
    snprintf(base_url, sizeof(base_url), "https://%s/api/agent/" MON_URLS_ENDPOINT, hostname);
    snprintf(url, sizeof(url), "%s?guid=%s", base_url, guid);
    VPRINT(1, "[DEBUG] Request URL: %s\n", url);

    MemoryStruct response = {0}; // buffer for response

    curl = curl_easy_init();
    if (!curl) return -3;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_store);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, PROXYDLP_CA_FILE);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        VPRINT(1, "[ERROR] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        ret = -4;
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        VPRINT(1, "[ERROR] Server returned HTTP %ld\n", http_code);
        ret = -5;
        goto cleanup;
    }

    // Parse JSON
    cJSON *root = cJSON_Parse(response.data);
    if (!root) {
        VPRINT(1, "[ERROR] Failed to parse JSON\n");
        ret = -6;
        goto cleanup;
    }

    cJSON *domains = cJSON_GetObjectItem(root, "domains");
    if (!cJSON_IsArray(domains)) {
        VPRINT(1, "[ERROR] 'domains' is not an array\n");
        cJSON_Delete(root);
        ret = -7;
        goto cleanup;
    }

    // Build a C array of strings
    int num_domains = cJSON_GetArraySize(domains);
    char **domain_list = malloc(num_domains * sizeof(char*));
    if (!domain_list) {
        VPRINT(1, "[ERROR] malloc failed\n");
        ret = -9;
        cJSON_Delete(root);
        return ret;
    }

    for (int i = 0; i < num_domains; i++) {
        cJSON *domain_item = cJSON_GetArrayItem(domains, i);
        if (cJSON_IsString(domain_item)) {
            // Copy the string so we own it
            domain_list[i] = strdup(domain_item->valuestring);
            if (!domain_list[i]) {
                VPRINT(1, "[ERROR] strdup failed\n");
                // free already allocated strings
                for (int j = 0; j < i; j++) {
                    free(domain_list[j]);
                }
                free(domain_list);
                cJSON_Delete(root);
                return -10;
            }
        } else {
            domain_list[i] = NULL; // handle non-string gracefully
        }
    }

    if (add_domains_to_monitor(domain_list, num_domains)) {
        ret = 0; // success
    } else {
        VPRINT(1, "[ERROR] add_domains_to_monitor failed\n");
        ret = -8;
    }

    // domain_list and strings are freed inside add_domains_to_monitor
    cJSON_Delete(root);

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);
    return ret;
}
