//
// Created by 彭强兵 on 2023/12/19.
//

#ifndef NF_TOA_TOA_H
#define NF_TOA_TOA_H

/* MUST be 4n !!!! */
#define TCPOLEN_TOA 8        /* |opcode|size|ip+port| = 1 + 1 + 6 */
#define TCPOLEN_IP6_TOA 20        /* |opcode|size|ip_of_v6+port| = 1 + 1 + 18 */
#define TCPOPT_TOA  254
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

/* MUST be 4 bytes alignment */
typedef struct toa_ip4_data {
    uint8_t opcode;
    uint8_t opsize;
    uint16_t port;
    uint32_t ip;
} __attribute__((packed)) toa_ip4_data_s;

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
struct  toa_ip6_data {
    uint8_t opcode;
    uint8_t opsize;
    uint16_t port;
    struct in6_addr in6_addr;
};
#endif

#endif //NF_TOA_TOA_H
