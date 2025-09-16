#ifndef CONFIG_H
#define CONFIG_H

#include <windows.h>
#include <string.h>

BOOL read_string_from_registry(const char *value_name, char *buffer, DWORD buffer_size);
BOOL save_string_to_registry(const char *value_name, const char *value_data);

BOOL load_values_from_registry();
BOOL save_values_to_registry();

const char* get_guid();
const char* get_token();
const char* get_proxy_hostname();

void set_guid(const char *new_guid);
void set_token(const char *new_token);

void set_proxy_ip(const char *ip);
const char* get_proxy_ip();



#endif