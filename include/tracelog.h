#ifndef TRACELOG_H
#define TRACELOG_H

#include <stdio.h>

#define VERBOSITY 1   // 0=silent, 1=events, 2=connections, 3=full packet details

#ifdef _WIN32
#define LOG_FILE_PATH "C:\\trace.log"
#else
#define LOG_FILE_PATH "/trace.log"
#endif

#define VPRINT(level, fmt, ...) \
    do { \
        if (VERBOSITY >= level) { \
            FILE *fp = fopen(LOG_FILE_PATH, "a"); \
            if (fp) { \
                fprintf(fp, "[V%d] " fmt "\n", level, ##__VA_ARGS__); \
                fclose(fp); \
            } \
        } \
    } while (0)

#endif
