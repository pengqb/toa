//
// Created by 彭强兵 on 2023/12/19.
// Custom Tcp Options add
//
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include "../include/toa.h"

MODULE_AUTHOR("michael.peng");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("add tcp option for output packets");

// the tcp option that will be appended on tcp header
static unsigned char option_tm[TCPOLEN_TOA] = {TCPOPT_TOA, TCPOLEN_TOA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static char my_buf[64];

// bit count of bit map
#define BIT_CNT 0XFFFF
DECLARE_BITMAP(outPorts, BIT_CNT) = {[0 ... BITS_TO_LONGS(BIT_CNT) - 1] = 0};

// config port
// 0: start port
// 1: end port
static int port[2];
static int portArgs;
module_param_array(port, int, &portArgs, 0644);
MODULE_PARM_DESC(port, "port config port=startPort,endPort. exrample: port=3306,3307");

// config out port
// 0: port1
// 1: port2
static int outPort[100];
static int outArgs;
module_param_array(outPort, int, &outArgs, 0644);
MODULE_PARM_DESC(outPort, "port config out outPort=port1,port2. exrample: port=3306,3307");

//user defined function for adding tcp option
static unsigned int hook_out(
        void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct net_device *dev;
    int hdr_len;
    int port;
    int datalen;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    dev = skb->dev;

    /* log the original src IP */
    // printk(KERN_INFO"debug post-routing dest IP=%x\n", iph->daddr);
    // printk(KERN_INFO"debug post-routing skb-> iphdr=\n" );

    skb_network_header(skb);

    //the condition for modify packet
    if (skb_headroom(skb) < 22) {
        return NF_ACCEPT;
    }
    //not ipv4 and tcp packet
    if (skb->data[0] != 0x45 || iph->protocol != 0x06) {
        return NF_ACCEPT;
    }
    port = ntohs(tcph->dest);
    // not target port
    if (test_bit(port, outPorts) == 0) {
        return NF_ACCEPT;
    }

    //original header length, ip header + tcp header
    hdr_len = (iph->ihl + tcph->doff) * 4;
    //copy original header to tmp buf; copy 64B to tmp buf; 64B is bigger than hdr_len;
    memcpy(my_buf, skb->data, 64);
    //append new tcp option on original header to generate a new header;
    memcpy(my_buf + hdr_len, option_tm, TCPOLEN_TOA);

    // remove original header
    skb_pull(skb, hdr_len);
    //add new header
    skb_push(skb, hdr_len + TCPOLEN_TOA);
    //copy new header into skb;
    memcpy(skb->data, my_buf, hdr_len + TCPOLEN_TOA);

    //update header offset in skb
    skb->transport_header = skb->transport_header - TCPOLEN_TOA;
    skb->network_header = skb->network_header - TCPOLEN_TOA;

    //update ip header and checksum
    iph = ip_hdr(skb);  //update iph point to new ip header
    iph->tot_len = htons(skb->len);
    iph->check = 0;     //re-calculate ip checksum
    iph->check = ip_fast_csum(iph, iph->ihl);
    //update tcp header and checksum
    tcph = (struct tcphdr *) skb_transport_header(skb);
    //update tcph point to new tcp header
    tcph->doff = tcph->doff + (TCPOLEN_TOA / 4);

    tcph->check = 0;

    //tcp segment length
    datalen = (skb->len - iph->ihl * 4);

    ////re-calculate tcp checksum
    //tcp checksum = tcp segment checksum and tcp pseudo-header checksum
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                    datalen, iph->protocol,
                                    csum_partial((char *) tcph, datalen, 0));
    //the reason is not clear, but without it, it seems the hardware will re-calcuate the checksum
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    /* modify the packet's src IP */
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho_in[] __read_mostly = {
        {
                .hook = hook_out,
                .pf = PF_INET,
                .hooknum = NF_INET_POST_ROUTING,
                .priority = NF_IP_PRI_FIRST,
        }
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
            set_bit(i, outPorts);
            printk(KERN_INFO"[CustomTcp]start filter in and out Port: %d", i);
        }
    }

    if (outArgs > 0) {
        for (i = 0; i < outArgs; i++) {
            printk(KERN_INFO"[CustomTcp]start filter out Port: %d", outPort[i]);
            set_bit(outPort[i], outPorts);
        }
    }
    return 0;
}

static int __init sknf_init(void) {
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
    printk(KERN_INFO"Custom tcp add init successed!");
    return 0;
}

static void __exit sknf_exit(void) {
    struct net *net;
    for_each_net(net) {
        nf_unregister_net_hooks(net, nfho_in, ARRAY_SIZE(nfho_in));
    }
    return;
}

module_init(sknf_init);
module_exit(sknf_exit);