#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#define VERSION "1.0"

#if 0
void myntoa(u32 net, char *ip_addr)
{
	sprintf(ip_addr , "%u.%u.%u.%u", net & 0xff,	\
		net >> 8 & 0xff, net >> 16 & 0xff,	\
		net >> 24 & 0xff);
	return;
}
#endif
unsigned int kook_func(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct iphdr 	*ip_addr = NULL;
	struct tcphdr	*tcp_addr = NULL;
	char 		*payload = NULL;
	int 		i = 0;
	int 		datalen = 0;
	

	ip_addr =  ip_hdr(skb);
	if (ip_addr->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	tcp_addr = tcp_hdr(skb);
#if 0

	printk(KERN_INFO"ip_addr->ttl:%d\n", ip_addr->ttl);
	printk(KERN_INFO"ip_addr->protocol:%d\n", ip_addr->protocol);
	printk(KERN_INFO"ip_addr->check:%d\n", ip_addr->check);
	printk("tcp_addr->source:%d\n",	\
			ntohs(tcp_addr->source));
	printk("tcp_addr->dest:%d\n",	\
			ntohs(tcp_addr->dest));
	printk("tcp_addr->fin:%d\n", tcp_addr->fin);
	printk("tcp_addr->syn:%d\n", tcp_addr->syn);
	printk("tcp_addr->rst:%d\n", tcp_addr->rst);
	printk("tcp_addr->psh:%d\n", tcp_addr->psh);
	printk("tcp_addr->ack:%d\n", tcp_addr->ack);
	printk("tcp_addr->urg:%d\n", tcp_addr->urg);
	printk("tcp_addr->seq:%d\n", ntohs(tcp_addr->seq));
	printk("tcp_addr->ack_seq:%d\n", ntohs(tcp_addr->ack_seq));
	printk("tcp_addr->window:%d\n", ntohs(tcp_addr->window));
	printk("tcp_addr->check:%d\n", tcp_addr->check);
	printk("tcp_addr->urg_ptr:%d\n", ntohs(tcp_addr->urg_ptr));
	printk(KERN_INFO"skb->len:%d\n",  skb->len);
	printk(KERN_INFO"skb->data_len:%d\n", skb->data_len);
	printk(KERN_INFO"ip_addr->id:%d\n", ntohs(ip_addr->id));
	printk(KERN_INFO"tv64:%lld\n", skb->tstamp.tv64);
	printk(KERN_INFO"ip_addr->version:%d\n",\
			ip_addr->version);
	printk(KERN_INFO"ip_addr->tos:%x\n",	\
			(ip_addr->tos));
	printk(KERN_INFO"ip_addr->frag_off:%x\n",\
		ntohs(ip_addr->frag_off));
#else
#endif

	/*
	printk(KERN_INFO"");
	*/

#if BITS_PER_LONG != 64 && !defined(CONFIG_KTIME_SCALAR)
	printk(KERN_INFO"sec:%d\n",		\
			skb->tstamp.tv.sec);
	printk(KERN_INFO"nsec:%d\n",		\
			skb->tstamp.tv.nsec);
#endif
#if 0

	memset(ip_addr_c, 0x00, sizeof(ip_addr_c));
	myntoa(ip_addr->saddr, ip_addr_c);
	printk(KERN_INFO"srcaddr:%s\n", ip_addr_c);

	if(in && in->name)
		printk(KERN_INFO"dev.in:%s\n", in->name);
	if(out && out->name)
		printk(KERN_INFO"dev.out:%s\n", out->name);
	if (skb->dev && skb->dev->name)
		printk(KERN_INFO"skb->dev->name:%s\n",\
			skb->dev->name);
#endif
	/*
	FRAG_CB(skb);
	TCP_SKB_CB(skb);
	*/
#if 0
	printk(KERN_INFO"ip_addr->tot_len:%d\n",\
			ntohs(ip_addr->tot_len));
	printk(KERN_INFO"ip_addr->ihl * 4:%d\n",\
			ip_addr->ihl * 4);
	printk(KERN_INFO"tcp_hdrlen:%d\n",	\
			tcp_hdrlen(skb));
	printk(KERN_INFO"tcp_addr->doff*4:%d\n",\
			tcp_addr->doff * 4);
#endif
	payload = (char *)tcp_addr + tcp_hdrlen(skb);
	datalen = ntohs(ip_addr->tot_len) - ip_addr->ihl * 4 - tcp_hdrlen(skb);
#if 1
	if (strncmp(payload, "GET", 3) == 0 || strncmp(payload, "POST", 4) == 0)
	{
		printk(KERN_INFO"POST_ROUTING\n");
		printk(KERN_INFO"dstaddr:%pI4\n", &ip_addr->daddr);
		printk(KERN_INFO"srcaddr:%pI4\n", &ip_addr->saddr);
		printk(KERN_INFO"datalen:%d\n",	datalen);
		printk(KERN_INFO"%s\n", payload);
		printk(KERN_INFO"----\n");
	}
	
#else
	for (i = 0; i < datalen; i++)
		printk(KERN_INFO"%c", payload[i]);
	printk(KERN_INFO"\n");
#endif

	return NF_ACCEPT;
}
static struct nf_hook_ops nfho = {
	.hook		= kook_func,
	.pf		= PF_INET,
	.hooknum	= NF_INET_POST_ROUTING,
	/*
	.hooknum	= NF_INET_PRE_ROUTING,
	*/
	.priority	= NF_IP_PRI_MANGLE,
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
