#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#define VERSION 	"1.0"
#define SEND_NUM	200	


unsigned int kook_func(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct iphdr 	*ip_addr = NULL;
	struct tcphdr	*tcp_addr = NULL;
	char 		*payload = NULL;
	int 		datalen = 0;
	struct sk_buff	*clone_skb;
	int count = 0;
	int ret = 0;
	unsigned char mac_temp[ETH_ALEN] = {0};
	struct ethhdr *mach = NULL;

	ip_addr =  ip_hdr(skb);
	if (ip_addr->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	tcp_addr = tcp_hdr(skb);
	pr_info("version:%d, ihl:%d, tos:%d, tot_len:%d,id:%d,\
frag_off:%d, ttl:%d, protocol:%d, check:%d, saddr:%d, daddr:%d",\
	ip_addr->version,
	ip_addr->ihl,
	ip_addr->tos,
	ip_addr->tot_len,
	ip_addr->id, 
	ip_addr->frag_off,
	ip_addr->ttl,
	ip_addr->protocol,
	ip_addr->check,
	ip_addr->saddr,
	ip_addr->daddr);
#if 0
#if 0
	printk(KERN_INFO"ip_addr->id:%d\n", ntohs(ip_addr->id));
	printk(KERN_INFO"skb->dev->name:%s\n", skb->dev->name);
	printk("tcp_addr->seq:%d\n", ntohs(tcp_addr->seq));
	printk("tcp_addr->ack_seq:%d\n", ntohs(tcp_addr->ack_seq));
#endif

	/*
	struct net_device	*dev;
	printk(KERN_INFO"");
	*/

#if BITS_PER_LONG != 64 && !defined(CONFIG_KTIME_SCALAR)
	printk(KERN_INFO"sec:%d\n",		\
			skb->tstamp.tv.sec);
	printk(KERN_INFO"nsec:%d\n",		\
			skb->tstamp.tv.nsec);
#endif
	payload = (char *)tcp_addr + tcp_hdrlen(skb);
	datalen = ntohs(ip_addr->tot_len) - ip_addr->ihl * 4 - tcp_hdrlen(skb);

#if 0
	if (strncmp(payload, "GET", 3) == 0 || strncmp(payload, "POST", 4) == 0)
#endif
	{
		printk(KERN_INFO"POST_ROUTING\n");
		printk(KERN_INFO"dstaddr:%pI4\n", &ip_addr->daddr);
		printk(KERN_INFO"srcaddr:%pI4\n", &ip_addr->saddr);
		printk(KERN_INFO"datalen:%d\n",	datalen);
		printk(KERN_INFO"----\n");
#if 0
		printk(KERN_INFO"%s\n", payload);
#endif
	}
	while (count < SEND_NUM)
	{
		clone_skb = skb_clone(skb, GFP_ATOMIC);
		printk(KERN_INFO"skb_clone_addr:%p\n", clone_skb);
		mach = eth_hdr(clone_skb);
		printk(KERN_INFO"mach->h_dest:%pM\n", mach->h_dest);
		printk(KERN_INFO"mach->h_source:%pM\n", mach->h_source);
		printk(KERN_INFO"mach->h_proto:%x\n", ntohs(mach->h_proto));
#if 0
		memcpy(mac_temp, (unsigned char *)mach->h_dest, ETH_ALEN);
		memcpy(mach->h_dest, (unsigned char *)mach->h_source, ETH_ALEN);
		memcpy(mach->h_source, mac_temp, ETH_ALEN);
#endif
		skb_push(clone_skb , ETH_HLEN);
		ret = dev_queue_xmit(clone_skb);
		printk(KERN_INFO"ret:%d\n", ret);
		count++;
	}
#endif
	

	return NF_ACCEPT;
}
static struct nf_hook_ops nfho = {
	.hook		= kook_func,
	.pf		= PF_INET,
	.priority	= NF_IP_PRI_MANGLE,
	.hooknum	= NF_INET_PRE_ROUTING,
	/*
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP_PRI_SELINUX_LAST,
	*/
};
/* static void _exit my_init_module(void)  */
static inline int ret_mudule(int ret)
{
	printk(KERN_INFO"%d\n",ret);
	return ret;
}
static int __init my_init_module(void)
{
	int hook_ret = 0;
	hook_ret = nf_register_hook(&nfho);
	/* cleanup - unregister hook */
	if (hook_ret)
		printk("translog module false\n");
	else
		printk("translog module true\n");
	return 0;
}
static void __exit my_exit_module(void)
{
	nf_unregister_hook(&nfho);
	printk(KERN_INFO"translog: un\n");
	return;
}
module_init(my_init_module);
module_exit(my_exit_module);

MODULE_AUTHOR("zhang liu ying<zhangliuying@sohu.com>");
MODULE_DESCRIPTION("skb_test");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
