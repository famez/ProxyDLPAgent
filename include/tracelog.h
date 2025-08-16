#ifndef TRACELOG_H
#define TRACELOG_H

#define VERBOSITY       1   // 0=silent, 1=events, 2=connections, 3=full packet details

#define VPRINT(level, fmt, ...) \
    do { \
        if (VERBOSITY >= level) { \
            fprintf(stderr, "[V%d] " fmt "\n", level, ##__VA_ARGS__); \
        } \
    } while (0)

#endif