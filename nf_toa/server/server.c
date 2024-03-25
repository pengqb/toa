#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../include/toa.h"

#define PORT 4321

#define BACKLOG 1
#define MAXRECVLEN 1024

int main(int argc, char *argv[]) {
    char buf[MAXRECVLEN];
    int listenfd, connectfd;   /* socket descriptors */
    struct sockaddr_in server; /* server's address information */
    struct sockaddr_in client; /* client's address information */
    socklen_t addrlen;
    int res;
    toa_ip4_data_s opt1 = {
            .opcode = 0,
            .opsize = 0,
            .port = 0,
            .ip = 0
    };
    int opt_len = sizeof(toa_ip4_data_s);
    /* Create TCP socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        /* handle exception */
        perror("socket() error. Failed to initiate a socket");
        exit(1);
    }

    /* set socket option */
    int opt = SO_REUSEADDR;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listenfd, (struct sockaddr *) &server, sizeof(server)) == -1) {
        /* handle exception */
        perror("Bind() error.");
        exit(1);
    }

    if (listen(listenfd, BACKLOG) == -1) {
        perror("listen() error. \n");
        exit(1);
    }

    addrlen = sizeof(client);
    while (1) {
        if ((connectfd = accept(listenfd, (struct sockaddr *) &client, &addrlen)) == -1) {
            perror("accept() error. \n");
            exit(1);
        }

        struct timeval tv;
        gettimeofday(&tv, NULL);
        printf("You got a connection from client's ip %s, port %d at time %ld.%ld\n", inet_ntoa(client.sin_addr),
               htons(client.sin_port), tv.tv_sec, tv.tv_usec);

        int iret = -1;
        while (1) {
            //IPPROTO_TCP不允许自定义option，除非nf_register_sockopt。如下面是错误的
            //res = getsockopt(connectfd, IPPROTO_TCP, 254, (void *) &opt1, 6);
            //getsockopt 参数 socklen_t *restrict option_len 必须传指针 setsockopt是传值
            //IPPROTO_IP可以写自定义option，但不可以读自定义option，除非nf_register_sockopt.
            //所以本程序要结合netfilter toa一起使用
            res = getsockopt(connectfd, IPPROTO_IP, 254, (void *) &opt1, &opt_len);
            if( res != 0)
                printf("res:%d,eno:%d,emsg:%s\n",res, errno, strerror(errno));
            printf("res:%d,opt1.port:%d,opt1.ip:%u.%u.%u.%u\n",res, opt1.port, NIPQUAD(opt1.ip));
            /* print client's ip and port */
            iret = recv(connectfd, buf, MAXRECVLEN, 0);
            if (iret > 0) {
                printf("%s\n", buf);
            } else {
                close(connectfd);
                break;
            }

            send(connectfd, buf, iret, 0); /* send to the client welcome message */
        }
    }
    close(listenfd); /* close listenfd */
    return 0;
}
