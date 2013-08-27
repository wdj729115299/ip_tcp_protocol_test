/**
 * @file translog.c
 * @brief 
 * @author Airead Fan <fgh1987168@gmail.com>
 * @date 2012/09/27 14:40:20
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ctype.h>
#include <linux/netdevice.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_REJECT.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>

/*
 * Macros to help debugging
 */

#undef PDEBUG             /* undef it, just in case */
#ifdef SRVTABLES_DEBUG
#  ifdef __KERNEL__
/* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_INFO "translog: " fmt, ## args)
#  else
/* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#define VERSION 	"1.0.1"

#define ADDR_BUFF_SIZE (sizeof("xxx.xxx.xxx.xxx:xxxxx"))
#define DATA_SIZE 1024

static char *devname = "all";
static struct iphdr *iph;        /* ip header struct */
static struct tcphdr *tcph;      /* tcp header struct */
static char message[DATA_SIZE];

/**
 * strnstr - Find the first substring in a length-limited string
 * @s1: The string to be searched
 * @s2: The string to search for
 * @len: the maximum number of characters to search
 */
char *my_strnstr(const char *s1, const char *s2, size_t len)
{
	size_t l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	while (len >= l2) {
		len--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

/* function to be called by hook */
static unsigned int 
hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,\
          const struct net_device *out, int (*okfn)(struct sk_buff *))
{
#if 1
	int i = 0;
    char *payload, *p, *q, *key, *pre_p;
    u16 tcplen, datalen, len, limit;
    int spn; 

    if (in == NULL) {
        return NF_ACCEPT;
    } else if (in->name == NULL) {
        return NF_ACCEPT;
    }
    
    if (memcmp(devname, "all", 3) != 0) {
        if (memcmp(devname, in->name, 4) != 0) {
            return NF_ACCEPT;
        }
    }

    iph = ip_hdr(skb); /* grab network header */

    if (!skb) {
        return NF_ACCEPT;
    }
    
    if (iph->protocol != 6) {       /* not tcp, pass */
        return NF_ACCEPT;
    }

    /* get header size */
    tcph = (void *)skb->data + iph->ihl * 4;

    if (skb->len - iph->ihl * 4 - tcph->doff * 4 <= 0) {
        return NF_ACCEPT;
    }


//    pr_info("=================================\n");
//    pr_info("before linearize: skb->len: %u, truesize: %d, data_len: %u, ip_summed: %u, csum_start: %u, csum_offset: %u\n", 
//            skb->len, skb->truesize, skb->data_len, skb->ip_summed, skb->csum_start, skb->csum_offset);
//    pr_info("skb_linearize()\n");
    if (skb_linearize(skb) != 0) { /* linerize failed */
        printk(KERN_WARNING "linerize failed\n");
        return NF_ACCEPT;
    }

//    pr_info("linearize: skb->len: %u, truesize: %d, data_len: %u, ip_summed: %u, csum_start: %u, csum_offset: %u\n", 
//            skb->len, skb->truesize, skb->data_len, skb->ip_summed, skb->csum_start, skb->csum_offset);

    iph = ip_hdr(skb); /* grab network header */
    tcph = (void *)skb->data + iph->ihl * 4;
    payload = (char *)tcph + tcph->doff * 4;

    tcplen = ntohs(iph->tot_len)-iph->ihl * 4;
    datalen = tcplen - tcph->doff * 4;

    if (datalen < 4) {
        return NF_ACCEPT;
    }

    memset(message, 0, sizeof(message));
//    pr_info("%c, %c, %c, %c\n", payload[0], payload[1], payload[2], payload[3]);
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') || 
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')) {
//        pr_info("enter GET: %s\n", in->name);
        q = message;
	for (i = 0; i < 10; i++){
		printk("!!!%c", payload[i]);
	}
	printk("\n");
        
        if (payload[0] == 'G') {
            memcpy(q, payload, 3);
            q += 3;
        } else {
            memcpy(q, payload, 4);
            q += 4;
        }

        key = "Host:";
        pre_p = payload;
        len = datalen;
        if ((p = my_strnstr((const char *)pre_p, key, len)) != NULL) {
            p = p + strlen(key);
            limit = p - payload;
//            pr_info("catch %s, datalen %u, p-payload %u\n", key, datalen, limit);
            while (*p != '\r' && *p != '\n' && q - message < DATA_SIZE) {
                if (limit >= datalen) {
//                    pr_info("limit: %u, break, datalen: %u\n", limit, datalen);
                    break;
                } 
//                pr_info("limit: %u, *p: %c\n", limit, *p);
                *q++ = *p++;
                limit++;
            }
            p = my_strnstr((const char *)payload, "/", len);
            while (p != NULL && *p != ' ' && *p != '?' && *p != '\r' && *p != '\n' && q - message < DATA_SIZE) {
                if (limit >= datalen) {
//                    pr_info("limit: %u, break, datalen: %u\n", limit, datalen);
                    break;
                } 
//                pr_info("limit: %u, *p: %c\n", limit, *p);
                *q++ = *p++;
                limit++;
            }
        }

        spn = snprintf(q, DATA_SIZE - (q - message), " %pI4 %pI4", &iph->saddr, &iph->daddr);
        pr_info("%s\n", message);
    }
#else
    char *payload, *p, *q, *key, *pre_p;
    u16 tcplen, datalen, len, limit;
    int spn; 

    if (in == NULL) {
        return NF_ACCEPT;
    } else if (in->name == NULL) {
        return NF_ACCEPT;
    }
    
    if (memcmp(devname, "all", 3) != 0) {
        if (memcmp(devname, in->name, 4) != 0) {
            return NF_ACCEPT;
        }
    }

    iph = ip_hdr(skb); /* grab network header */

    if (!skb) {
        return NF_ACCEPT;
    }
    
    if (iph->protocol != 6) {       /* not tcp, pass */
        return NF_ACCEPT;
    }

    /* get header size */
    tcph = (void *)skb->data + iph->ihl * 4;

    if (skb->len - iph->ihl * 4 - tcph->doff * 4 <= 0) {
        return NF_ACCEPT;
    }


//    pr_info("=================================\n");
//    pr_info("before linearize: skb->len: %u, truesize: %d, data_len: %u, ip_summed: %u, csum_start: %u, csum_offset: %u\n", 
//            skb->len, skb->truesize, skb->data_len, skb->ip_summed, skb->csum_start, skb->csum_offset);
//    pr_info("skb_linearize()\n");
    if (skb_linearize(skb) != 0) { /* linerize failed */
        printk(KERN_WARNING "linerize failed\n");
        return NF_ACCEPT;
    }

//    pr_info("linearize: skb->len: %u, truesize: %d, data_len: %u, ip_summed: %u, csum_start: %u, csum_offset: %u\n", 
//            skb->len, skb->truesize, skb->data_len, skb->ip_summed, skb->csum_start, skb->csum_offset);

    iph = ip_hdr(skb); /* grab network header */
    tcph = (void *)skb->data + iph->ihl * 4;
    payload = (char *)tcph + tcph->doff * 4;

    tcplen = ntohs(iph->tot_len)-iph->ihl * 4;
    datalen = tcplen - tcph->doff * 4;

    if (datalen < 4) {
        return NF_ACCEPT;
    }

    memset(message, 0, sizeof(message));
//    pr_info("%c, %c, %c, %c\n", payload[0], payload[1], payload[2], payload[3]);
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') || 
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')) {
//        pr_info("enter GET: %s\n", in->name);
        q = message;
        
        if (payload[0] == 'G') {
            memcpy(q, payload, 3);
            q += 3;
        } else {
            memcpy(q, payload, 4);
            q += 4;
        }

        key = "Host:";
        pre_p = payload;
        len = datalen;
        if ((p = my_strnstr((const char *)pre_p, key, len)) != NULL) {
            p = p + strlen(key);
            limit = p - payload;
//            pr_info("catch %s, datalen %u, p-payload %u\n", key, datalen, limit);
            while (*p != '\r' && *p != '\n' && q - message < DATA_SIZE) {
                if (limit >= datalen) {
//                    pr_info("limit: %u, break, datalen: %u\n", limit, datalen);
                    break;
                } 
//                pr_info("limit: %u, *p: %c\n", limit, *p);
                *q++ = *p++;
                limit++;
            }
            p = my_strnstr((const char *)payload, "/", len);
            while (p != NULL && *p != ' ' && *p != '?' && *p != '\r' && *p != '\n' && q - message < DATA_SIZE) {
                if (limit >= datalen) {
//                    pr_info("limit: %u, break, datalen: %u\n", limit, datalen);
                    break;
                } 
//                pr_info("limit: %u, *p: %c\n", limit, *p);
                *q++ = *p++;
                limit++;
            }
        }

        spn = snprintf(q, DATA_SIZE - (q - message), " %pI4 %pI4", &iph->saddr, &iph->daddr);
        pr_info("%s\n", message);
    }
#endif

    return NF_ACCEPT;
}
static struct nf_hook_ops nfho = {
    .hook = hook_func,
    .hooknum = 	NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_MANGLE,
};

static int __init my_init_module(void)
{
    int ret;

    ret = nf_register_hook(&nfho);         /* register hook */
    if (ret < 0) {
        goto failed;
    }

    printk("insmod translog module, dev: %s\n", devname);


    return 0;                   /* return 0 for success */
   
failed:
    return ret;
}

/* Call when module unloaded using 'rmmod' */
static void __exit my_cleanup_module(void)
{
    nf_unregister_hook(&nfho);  /* cleanup - unregister hook */

    printk("rmmod translog module\n");
}

module_init(my_init_module);
module_exit(my_cleanup_module);

module_param(devname, charp, S_IRUGO);

MODULE_AUTHOR("Airead Fan <fgh1987168@gmail.com>");
MODULE_DESCRIPTION("translog");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
