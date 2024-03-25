//
// Created by 彭强兵 on 2023/12/18.
//
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/moduleparam.h>
#include "../include/toa.h"

#define SOCKET_OPS_BASE          254
#define SOCKET_OPS_SET       (SOCKET_OPS_BASE)
#define SOCKET_OPS_GET      (SOCKET_OPS_BASE)
#define SOCKET_OPS_MAX       (SOCKET_OPS_BASE + 1)

MODULE_LICENSE("GPL v2");

MODULE_AUTHOR("michael.peng");

MODULE_DESCRIPTION("sockopt module, get tcp option address, get ip option address");

MODULE_VERSION("1.0");

// the tcp option that will be appended on tcp header
static unsigned char option_tm[TCPOLEN_TOA] = {SOCKET_OPS_BASE, TCPOLEN_TOA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};

// bit count of bit map
#define BIT_CNT 0XFFFF
DECLARE_BITMAP(inPorts, BIT_CNT) = {[0 ... BITS_TO_LONGS(BIT_CNT) - 1] = 0};

// config port 0: start port 1: end port
static int port[2];
static int portArgs;

module_param_array(port, int, &portArgs, 0644);

MODULE_PARM_DESC(port, "port config port=startPort,endPort. exrample: port=3306,3307");

// config in port 0: port1 1: port2
static int inPort[100];
static int inArgs;

module_param_array(inPort, int, &inArgs, 0644);

MODULE_PARM_DESC(inPort, "port config in inPort=port1,port2. exrample: port=3306,3307");

//user defined function for reading tcp option
static unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *iph;
    struct tcphdr *tcph;
    int length;
    unsigned char *ptr;
    struct toa_ip4_data tdata;
    int port;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    //printk(KERN_INFO"net hook source IP=%x to IP=%x \n", iph->saddr, iph->daddr);

    //the condition for modify packet
    //地址小于22不知道有什么实际意义,可能是skb->len
    if ((skb) < 22) {
        return NF_ACCEPT;
    }
    //ipv4 and tcp packet
    if (skb->data[0] != 0x45 || iph->protocol != 0x06) {
        return NF_ACCEPT;
    }
    // not target port
    port = ntohs(tcph->dest);
    if (test_bit(port, inPorts) == 0) {
        return NF_ACCEPT;
    }

    if (NULL != skb) {
        length = (tcph->doff * 4) - sizeof(struct tcphdr);

        ptr = (unsigned char *) (tcph + 1);
        if (!ptr) {
            printk(KERN_INFO"ptr is null");
            return NF_ACCEPT;
        }
        //printk(KERN_INFO"port=%d, size of tcphdr=%d,length=%d,ptr=%s", port, sizeof(struct tcphdr), length, ptr);
        while (length > 0) {
            int opcode = *ptr++;
            int opsize;
            switch (opcode) {
                case TCPOPT_EOL:
                    return NF_ACCEPT;
                case TCPOPT_NOP:    /* Ref: RFC 793 section 3.1 */
                    length--;
                    continue;
                default:
                    opsize = *ptr++;
                    if (opsize < 2) {/* "silly options" */
                        printk(KERN_INFO"silly options");
                        return NF_ACCEPT;
                    }
                    if (opsize > length) {/* don't parse partial options */
                        printk(KERN_INFO"dont parse partial options,opcode=%x,opsize=%x,length=%d", opcode, opsize,
                               length);
                        return NF_ACCEPT;
                    }
                    if (TCPOPT_TOA == opcode && TCPOLEN_TOA == opsize) {//NAT44
                        memcpy(&tdata, ptr - 2, sizeof(tdata));
                        printk(KERN_INFO"find toa data: ip = %u.%u.%u.%u, port = %u\n",
                               NIPQUAD(tdata.ip), ntohs(tdata.port));
                            memcpy(option_tm, ptr - 2, sizeof(tdata));
                            return NF_ACCEPT;
                    }
                    if (TCPOPT_TOA == opcode && TCPOLEN_IP6_TOA == opsize) {//NAT64
                        struct toa_ip6_data *ptr_toa_ip6;
                        struct toa_ip6_entry *ptr_toa_entry =
                                kzalloc(sizeof(struct toa_ip6_entry), GFP_ATOMIC);
                        if (!ptr_toa_entry) {
                            return NULL;
                        }
                        ptr_toa_ip6 = &ptr_toa_entry->toa_data;
                        memcpy(ptr_toa_ip6, ptr - 2, sizeof(struct toa_ip6_data));
                    }
                    ptr += opsize - 2;
                    length -= opsize;
            }
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_in[] __read_mostly = {
        {
                .hook = hook_in,
                .pf = PF_INET,
                .hooknum = NF_INET_LOCAL_IN,
                //.hooknum = NF_INET_PRE_ROUTING,
                .priority = NF_IP_PRI_FIRST,
        },
        {
                .hook = hook_inv6,
                .pf = PF_INET6,
                .hooknum = NF_INET_LOCAL_IN,
                //.hooknum = NF_INET_PRE_ROUTING,
                .priority = NF_IP_PRI_FIRST,
        }
};

unsigned long sk_data_ready_addr = 0;

static int sample_toa(struct sock *sk, int cmd, void __user *user, int *len) {
    struct inet_sock *inet;
    int ret = 0;

    if (cmd != SOCKET_OPS_GET || !sk) {
        printk(KERN_INFO"%s: bad cmd\n", __func__);
        return -EINVAL;
    }

    if (*len < TCPOLEN_TOA || NULL == user) {
        printk(KERN_INFO"%s: bad param len\n", __func__);
        return -EINVAL;
    }

    inet = inet_sk(sk);
    /* refered to inet_getname */
    if (!inet->inet_dport || ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT))) {
        printk(KERN_INFO"%s: bad state\n", __func__);
        return -ENOTCONN;
    }

    return copy_to_user(user, option_tm, TCPOLEN_TOA);
}

static struct nf_sockopt_ops toa_sockopts = {
        .pf = PF_INET, //PF_INET PF_INET6
        .owner    = THIS_MODULE,
        /* Nothing to do in set */
        /* get */
        .get_optmin = SOCKET_OPS_GET,
        .get_optmax = SOCKET_OPS_MAX,
        .get        = sample_toa
};

static int initParams(void) {
    int i;
    int max = 0, min = 0;
    if (portArgs > 0) {
        if (portArgs == 1) {
            min = port[0];
            max = port[0];
        } else if (portArgs == 2) {
            min = port[0];
            max = port[1];
        }
        if (min > max) {
            printk(KERN_ERR"Custom tcp filter init failed, port config error; min=%d, max=%d\n", min, max);
            return -1;
        }

        for (i = min; i <= max; i++) {
            set_bit(i, inPorts);
            printk(KERN_INFO"[CustomTcp]start filter in and out Port: %d", i);
        }
    }

    if (inArgs > 0) {
        for (i = 0; i < inArgs; i++) {
            printk(KERN_INFO"[CustomTcp]start filter in Port: %d", inPort[i]);
            set_bit(inPort[i], inPorts);
        }
    }

    return 0;
}

/* module init */
static int __init nf_toa_init(void) {
    struct net *net;
    if (initParams() < 0) {
        printk(KERN_ERR"Custom tcp filter init failed, port config error");
        return -1;
    }
    for_each_net(net) {
        if (nf_register_net_hooks(net, nfho_in, ARRAY_SIZE(nfho_in))) {
            printk(KERN_ERR"nf_register_net_hooks() failed\n");
            return -1;
        }
    }
    printk(KERN_INFO "sockopt: nf_toa_init\n");
    return nf_register_sockopt(&toa_sockopts);
}

/* module cleanup*/
static void __exit nf_toa_exit(void) {
    struct net *net;
    for_each_net(net) {
        nf_unregister_net_hooks(net, nfho_in, ARRAY_SIZE(nfho_in));
    }
    printk(KERN_INFO "sockopt: nf_toa_exit\n");
    nf_unregister_sockopt(&toa_sockopts);
}

module_init(nf_toa_init);
module_exit(nf_toa_exit);