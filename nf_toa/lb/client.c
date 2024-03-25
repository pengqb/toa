#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>  /* netdb is necessary for struct hostent */
#include <arpa/inet.h>
#include <sys/errno.h>
#include "../include/toa.h"

#define PORT 4321   /* server port */
#define MAXDATASIZE 100

int main(int argc, char *argv[]) {
    int sockfd, num, s;    /* files descriptors */
    char buf[MAXDATASIZE];    /* buf will store received text */
    //unsigned char ip4[sizeof(struct in_addr)];
    struct hostent *he;    /* structure that will get information about remote host */
    struct sockaddr_in server;

    if (argc != 2) {
        printf("Usage: %s <IP Address>\n", argv[0]);
        exit(1);
    }
    toa_ip4_data_s opt = {
            .opcode = 0xfe,
            .opsize = 8,
            .port = 0xffff
    };

    s = inet_pton(AF_INET, argv[1], &opt.ip);
    if (s <= 0) {
        if (s == 0)
            fprintf(stderr, "Not in presentation format");
        else
            perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("socket() error\n");
        exit(1);
    }


    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    //server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_addr.s_addr = opt.ip;
    if (connect(sockfd, (struct sockaddr *) &server, sizeof(server)) == -1) {
        printf("connect() error\n");
        exit(1);
    }
    if(setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, (void *) &opt, sizeof(toa_ip4_data_s)) == -1){
        printf("setsockopt error: %s", strerror(errno));
        exit(1);
    }
    char str[] = "horst\n";
    if ((num = send(sockfd, str, sizeof(str), 0)) == -1) {
        printf("send() error\n");
        exit(1);
    }
    if ((num = recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
        printf("recv() error\n");
        exit(1);
    }
    buf[num - 1] = '\0';
    printf("server message: %s\n", buf);
    close(sockfd);
    return 0;
}
