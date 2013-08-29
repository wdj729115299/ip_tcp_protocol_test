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
	struct ethhdr *mach = NULL;
	struct iphdr 	*ip_addr = NULL;
	struct tcphdr	*tcp_addr = NULL;



	ip_addr =  ip_hdr(skb);
	if (ip_addr->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	mach = eth_hdr(skb);
	if (mach == NULL)
		return NF_ACCEPT;

	printk(KERN_INFO"h_dest:%pM, h_source:%pM, h_proto:%x\n", \
	mach->h_dest, mach->h_source, ntohs(mach->h_proto));

	tcp_addr = tcp_hdr(skb);
#if 0
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/
	pr_info("IP_OFFSET:%04x\n", IP_OFFSET);
	pr_info("ip_addr->frag_off IP_DF:%d\n",ip_addr->frag_off & IP_DF);
	pr_info("ip_addr->frag_off IP_MF:%d\n",ip_addr->frag_off & IP_MF);
#endif
	
	pr_info("version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,\
ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",\
	ip_addr->version,
	ip_addr->ihl,
	ip_addr->tos,
	ntohs(ip_addr->tot_len),
	ntohs(ip_addr->id), 
	ntohs(ip_addr->frag_off) & ~(0x7 << 13),
	ip_addr->ttl,
	ip_addr->protocol,
	ip_addr->check,
	&ip_addr->saddr,
	&ip_addr->daddr);

	pr_info("source:%d, dest:%d, seq:%d, ack_seq:%d, res1:%d,\
doff:%d, fin:%d, syn:%d, rst:%d, psh:%d, ack:%d, urg:%d, ece:%d,\
cwr:%d, window:%d, check:%d, urg_ptr:%d\n",\
	ntohs(tcp_addr->source),
	ntohs(tcp_addr->dest),
	ntohs(tcp_addr->seq),
	ntohs(tcp_addr->ack_seq),
	tcp_addr->res1,
	tcp_addr->doff,
	tcp_addr->fin,
	tcp_addr->syn,
	tcp_addr->rst,
	tcp_addr->psh,
	tcp_addr->ack,
	tcp_addr->urg,
	tcp_addr->ece,
	tcp_addr->cwr,
	ntohs(tcp_addr->window),
	tcp_addr->check,
	ntohs(tcp_addr->urg_ptr));

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
