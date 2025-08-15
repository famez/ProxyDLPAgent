#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "https_client.h"

// Callback function to handle incoming data
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    fwrite(ptr, size, nmemb, stdout); // Print directly to stdout
    return total_size;
}

int connect_to_server() {
    CURL *curl;
    CURLcode res;

    printf("[INFO] Initializing libcurl...\n");
    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("[INFO] Creating CURL easy handle...\n");
    curl = curl_easy_init();
    if (curl) {
        printf("[INFO] Setting URL to connect: https://10.228.217.251/api/agent/hearbeat\n");
        curl_easy_setopt(curl, CURLOPT_URL, "https://10.228.217.251/api/agent/hearbeat");

        printf("[INFO] Setting write callback...\n");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // Enable verbose output for debugging
        printf("[INFO] Enabling verbose output...\n");
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        // Optional: if HTTPS certificate verification is disabled
        printf("[INFO] Skipping SSL certificate verification (INSECURE!)\n");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        printf("[INFO] Performing HTTPS request...\n");
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "[ERROR] curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        } else {
            printf("[INFO] Request completed successfully.\n");
        }

        printf("[INFO] Cleaning up CURL easy handle...\n");
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "[ERROR] Failed to create CURL handle.\n");
    }

    printf("[INFO] Cleaning up libcurl global resources...\n");
    curl_global_cleanup();

    return 0;
}
