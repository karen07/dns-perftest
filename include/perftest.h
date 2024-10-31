#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdbool.h>

#define PACKET_MAX_SIZE 1600
#define URL_MAX_SIZE 300
#define EXIT_WAIT_SEC 10

#define FIRST_BIT_UINT16 0x8000
#define FIRST_TWO_BITS_UINT8 0xC0

typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t quest;
    uint16_t ans;
    uint16_t auth;
    uint16_t add;
} __attribute__((packed)) dns_header_t;

typedef struct end_name {
    uint16_t type;
    uint16_t class;
} __attribute__((packed)) end_name_t;

typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;
