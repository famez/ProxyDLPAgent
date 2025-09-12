#ifndef HTTPSCLIENT_H
#define HTTPSCLIENT_H

#define REGISTER_ENDPOINT       "register"
#define DEREGISTER_ENDPOINT     "deregister"
#define HEARTBEAT_ENDPOINT      "heartbeat"
#define MON_URLS_ENDPOINT       "monitored_domains"

#define PROXYDLP_CA_FILE        "C:\\Program Files\\ProxyDLPAgent\\mitmCA.pem"


int register_agent();
int deregister_agent();

int send_heartbeat();

int get_urls_to_monitor();

int get_domain_names_to_watch();

void init_https();

void end_https();

#endif