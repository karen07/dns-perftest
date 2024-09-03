#include "perftest.h"

FILE *fp;

uint32_t dns_ip;
uint16_t dns_port;

uint32_t listen_ip;
uint16_t listen_port;

uint32_t rps;

int32_t is_domains_file_path;
char domains_file_path[PATH_MAX];

int32_t sended;
int32_t readed;

double coeff = 1;

struct sockaddr_in repeater_addr, dns_addr;
int repeater_socket;

void print_help()
{
    printf("Commands:\n"
           "-file /example.txt            Domains file path\n"
           "-DNS_IP 0.0.0.0               DNS IP\n"
           "-DNS_port 00                  DNS port\n"
           "-listen_IP 0.0.0.0            Listen IP\n"
           "-listen_port 0000             Listen port\n"
           "-RPS 00000                    Request per second\n");
    exit(EXIT_FAILURE);
}

void *send_dns(__attribute__((unused)) void *arg)
{
    char packet[PACKET_MAX_SIZE], line_buf[PACKET_MAX_SIZE];
    int line_count = 0;

    while (fscanf(fp, "%s", line_buf) != EOF) {
        line_count++;

        dns_header_t *header = (dns_header_t *)packet;
        uint16_t id = line_count;
        header->id = htons(id);
        header->flags = htons(0x0100);
        header->quest = htons(1);
        header->ans = htons(0);
        header->auth = htons(0);
        header->add = htons(0);

        int k = 0;
        char *dot_pos_new = line_buf;
        char *dot_pos_old = line_buf;
        while ((dot_pos_new = strchr(dot_pos_old + 1, '.')) != NULL) {
            dot_pos_new++;
            packet[12 + k] = dot_pos_new - dot_pos_old - 1;
            memcpy(&packet[12 + k + 1], dot_pos_old, packet[12 + k]);
            k += packet[12 + k] + 1;
            dot_pos_old = dot_pos_new;
        }

        packet[12 + k] = strlen(line_buf) - k;
        memcpy(&packet[12 + k + 1], &line_buf[k], packet[12 + k]);
        k += packet[12 + k] + 1;
        packet[12 + k] = 0;

        end_name_t *end_name = (end_name_t *)&packet[12 + k + 1];
        end_name->type = htons(1);
        end_name->class = htons(1);

        if (sendto(repeater_socket, packet, 12 + k + 5, 0, (struct sockaddr *)&dns_addr,
                   sizeof(dns_addr)) < 0) {
            printf("Error:Can't send %s\n", strerror(errno));
        }

        sended = line_count;

        usleep(1000000 / rps / coeff);
    }

    return NULL;
}

void *read_dns(__attribute__((unused)) void *arg)
{
    int32_t receive_msg_len = 0;
    char receive_msg[PACKET_MAX_SIZE];

    struct sockaddr_in receive_DNS_addr;
    uint32_t receive_DNS_addr_length = sizeof(receive_DNS_addr);

    while (1) {
        receive_msg_len = recvfrom(repeater_socket, receive_msg, PACKET_MAX_SIZE, 0,
                                   (struct sockaddr *)&receive_DNS_addr, &receive_DNS_addr_length);

        if (receive_msg_len > 0) {
            readed++;
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    printf("\nDNS perftest started\n");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                printf("Get urls from file %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_IP")) {
            if (i != argc - 1) {
                printf("DNS IP %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    dns_ip = inet_addr(argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_port")) {
            if (i != argc - 1) {
                printf("DNS port %s\n", argv[i + 1]);
                sscanf(argv[i + 1], "%hu", &dns_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_IP")) {
            if (i != argc - 1) {
                printf("Listen IP %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    listen_ip = inet_addr(argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_port")) {
            if (i != argc - 1) {
                printf("Listen port %s\n", argv[i + 1]);
                sscanf(argv[i + 1], "%hu", &listen_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-RPS")) {
            if (i != argc - 1) {
                printf("RPS %s\n", argv[i + 1]);
                sscanf(argv[i + 1], "%u", &rps);
                i++;
            }
            continue;
        }
        printf("Unknown command %s\n", argv[i]);
        print_help();
    }

    if (!is_domains_file_path) {
        printf("Programm need domains file path\n");
        print_help();
    }

    if (dns_ip == 0) {
        printf("Programm need DNS IP\n");
        print_help();
    }

    if (dns_port == 0) {
        printf("Programm need DNS port\n");
        print_help();
    }

    if (listen_ip == 0) {
        printf("Programm need listen IP\n");
        print_help();
    }

    if (listen_port == 0) {
        printf("Programm need listen port\n");
        print_help();
    }

    if (rps == 0) {
        printf("Programm need rps\n");
        print_help();
    }

    printf("\n");

    fp = fopen(domains_file_path, "r");
    if (!fp) {
        printf("Error opening file %s\n", domains_file_path);
        return 0;
    }

    repeater_addr.sin_family = AF_INET;
    repeater_addr.sin_port = htons(listen_port);
    repeater_addr.sin_addr.s_addr = listen_ip;

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(dns_port);
    dns_addr.sin_addr.s_addr = dns_ip;

    repeater_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_socket < 0) {
        printf("Error:Error while creating socket %s\n", strerror(errno));
        return 0;
    }

    if (bind(repeater_socket, (struct sockaddr *)&repeater_addr, sizeof(repeater_addr)) < 0) {
        printf("Error:Couldn't bind to the port %s\n", strerror(errno));
        return 0;
    }

    pthread_t send_thread;
    if (pthread_create(&send_thread, NULL, send_dns, NULL)) {
        printf("Can't create send_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(send_thread)) {
        printf("Can't detach send_thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_t read_thread;
    if (pthread_create(&read_thread, NULL, read_dns, NULL)) {
        printf("Can't create read_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(read_thread)) {
        printf("Can't detach read_thread\n");
        exit(EXIT_FAILURE);
    }

    int32_t sended_old = 0;
    int32_t readed_old = 0;

    printf("Min:Sec Send_RPS Read_RPS Sended Readed Diff \n");
    while (1) {
        sleep(1);

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("%d:%d %d %d %d %d %d\n", tm_struct->tm_min, tm_struct->tm_sec, sended - sended_old,
               readed - readed_old, sended, readed, sended - readed);

        coeff *= (1.0 * rps) / (sended - sended_old);

        sended_old = sended;
        readed_old = readed;
    }

    return 0;
}
