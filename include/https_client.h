#ifndef HTTPSCLIENT_H
#define HTTPSCLIENT_H

#define BASE_URL    "https://192.168.0.15/api/agent/"

#define REGISTER_ENDPOINT   "register"
#define HEARTBEAT_ENDPOINT  "heartbeat"
#define MON_URLS_ENDPOINT  "monitored_domains"


int register_agent();

int send_heartbeat();

int get_urls_to_monitor();

int get_domain_names_to_watch();

void init_https();

void end_https();

#endif