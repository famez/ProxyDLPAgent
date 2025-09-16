#include <stdio.h>
#include <ws2tcpip.h>

#include "config.h"
#include "tracelog.h"


static char guid[256] = {0};
static char token[256] = {0}; 
static char proxy_hostname[256] = {0}; 
static char proxy_ip[INET_ADDRSTRLEN] = {0}; 

BOOL read_string_from_registry(const char *value_name, char *buffer, DWORD buffer_size) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\ProxyDlp", 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        VPRINT(1, "[ERROR] Failed to open registry key (error %ld)\n", result);
        return FALSE;
    }

    DWORD type = REG_SZ;
    result = RegGetValueA(hKey, NULL, value_name, RRF_RT_REG_SZ, &type, buffer, &buffer_size);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        VPRINT(1, "[ERROR] Failed to read registry value %s (error %ld)\n", value_name, result);
        return FALSE;
    }

    return TRUE;
}

BOOL save_string_to_registry(const char *value_name, const char *value_data) {
    HKEY hKey;
    LONG result = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\ProxyDlp",
        0, NULL, 0,
        KEY_WRITE, NULL,
        &hKey, NULL
    );

    if (result != ERROR_SUCCESS) {
        VPRINT(1, "[ERROR] RegCreateKeyExA failed (%ld)\n", result);
        return FALSE;
    }

    result = RegSetValueExA(
        hKey, value_name, 0, REG_SZ,
        (const BYTE*)value_data,
        (DWORD)(strlen(value_data) + 1)
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        VPRINT(1, "[ERROR] RegSetValueExA failed (%ld)\n", result);
        return FALSE;
    }

    return TRUE;
}

BOOL save_values_to_registry() {
    
    return save_string_to_registry("guid", guid) && save_string_to_registry("token", token);

}

BOOL load_values_from_registry() {

    return (read_string_from_registry("ProxyHostname", proxy_hostname, sizeof(guid))
        && read_string_from_registry("guid", guid, sizeof(guid)) 
        && read_string_from_registry("token", token, sizeof(token)));

}

void set_guid(const char *new_guid) {
    if (new_guid) {
        strncpy(guid, new_guid, sizeof(guid) - 1);
        guid[sizeof(guid) - 1] = '\0'; // ensure null termination
    }
}

void set_token(const char *new_token) {
    if (new_token) {
        strncpy(token, new_token, sizeof(token) - 1);
        token[sizeof(token) - 1] = '\0'; // ensure null termination
    }
}

const char* get_guid() { return guid; }
const char* get_token() { return token; }


const char* get_proxy_hostname() {
    return proxy_hostname;
}

void set_proxy_ip(const char *ip) {
    if (ip) {
        strncpy(proxy_ip, ip, sizeof(proxy_ip) - 1);
        proxy_ip[sizeof(proxy_ip) - 1] = '\0'; // ensure null termination
    }
}

const char* get_proxy_ip() {
    return proxy_ip;
}