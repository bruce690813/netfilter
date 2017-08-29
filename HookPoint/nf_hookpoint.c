/* 3.16.0-77-generic */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");

inline void dumpIpHdr(const char *fn, const struct sk_buff *skb)
{
    const struct iphdr *ip = ip_hdr(skb);

    printk("%s: srcip:%pI4, dstip:%pI4\n", fn, &ip->saddr, &ip->daddr);
}

static unsigned int
prerouting(const struct nf_hook_ops *ops, struct sk_buff *skb,
           const struct net_device *in, const struct net_device *out,
           int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
localin(const struct nf_hook_ops *ops, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
localout(const struct nf_hook_ops *ops, struct sk_buff *skb,
         const struct net_device *in, const struct net_device *out,
         int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
postrouting(const struct nf_hook_ops *ops, struct sk_buff *skb,
            const struct net_device *in, const struct net_device *out,
            int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static unsigned int
forwarding(const struct nf_hook_ops *ops, struct sk_buff *skb,
           const struct net_device *in, const struct net_device *out,
           int (*okfn)(struct sk_buff*))
{
    dumpIpHdr(__FUNCTION__, skb);
    return NF_ACCEPT;
}

static struct nf_hook_ops brook_ops[] __read_mostly = {
    {
        .hook = prerouting,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    },
    {
        .hook = localin,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    },
    {
        .hook = forwarding,
        .pf = PF_INET,
        .hooknum = NF_INET_FORWARD,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    },
    {
        .hook = localout,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    },
    {
        .hook = postrouting,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_RAW,
        .owner = THIS_MODULE,
    },
};

static int __init init_modules(void)
{
    printk("nf_register_hook\n");

    if (nf_register_hooks(brook_ops, ARRAY_SIZE(brook_ops)) < 0) {
        printk("nf_register_hook failed\n");
    }
    return 0;
}

static void __exit exit_modules(void)
{
    nf_unregister_hooks(brook_ops, ARRAY_SIZE(brook_ops));
}

module_init(init_modules);
module_exit(exit_modules);
