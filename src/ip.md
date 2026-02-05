# IP Protocol Implementation

## Overview

The **IP (Internet Protocol) layer** in Linux sits between the link layer (NIC drivers, see [nics.md](nics.md)) and the transport layer (TCP/UDP, see [udp_tcp.md](udp_tcp.md)). This chapter explains how Linux implements IPv4 packet processing, focusing on the kernel's data structures, algorithms, and code flow rather than the IP protocol itself.

### Role in the Network Stack

```
Application
     ↓
Socket/Syscalls (send/recv)
     ↓
Transport Layer (TCP/UDP) ──────────┐
     ↓                              │
IP Layer ← You are here             │
     ↓                              │
Link Layer (net_device)             │
     ↓                              │
NIC Driver                          │
     ↓                              │
Hardware                            │
                                    │
Routing decides: ───────────────────┘
  - Local delivery (up to transport)
  - Forward (out another interface)
  - Drop/ICMP error
```

The IP layer's primary responsibilities:

1. **Receive path**: Validate incoming packets, route lookup, deliver locally or forward
2. **Transmit path**: Build IP headers, route lookup, fragment if needed, pass to link layer
3. **Routing**: Maintain FIB (Forwarding Information Base), perform longest prefix match
4. **Fragmentation/Reassembly**: Handle packets larger than MTU
5. **ICMP**: Generate and process control messages
6. **Netfilter integration**: Hook points for iptables/nftables

This chapter focuses on **IPv4** implementation. IPv6 follows similar patterns but with different structures and code paths (`net/ipv6/` directory).

## Key Data Structures

### `struct sk_buff` IP-Specific Fields

The socket buffer holds packet data and metadata. IP layer uses specific fields:

```c
/* From include/linux/skbuff.h */
struct sk_buff {
    /* Network protocol type (set by eth_type_trans) */
    __be16 protocol;           /* ETH_P_IP (0x0800) for IPv4 */
    
    /* Header offsets (from skb->head) */
    __u16 transport_header;    /* Offset to TCP/UDP/ICMP header */
    __u16 network_header;      /* Offset to IP header */
    __u16 mac_header;          /* Offset to Ethernet header */
    __u16 inner_network_header; /* For tunneling */
    
    /* Checksum information */
    __u8 ip_summed;            /* CHECKSUM_NONE, CHECKSUM_UNNECESSARY, etc. */
    __wsum csum;               /* Partial checksum */
    __u16 csum_start;          /* Offset to start checksumming */
    __u16 csum_offset;         /* Offset to place checksum */
    
    /* Routing information */
    unsigned long _skb_refdst; /* Destination entry (struct dst_entry *) */
    
    /* Device information */
    struct net_device *dev;    /* Device packet arrived on or leaving from */
    int skb_iif;               /* Interface index for received packets */
    
    /* ... many other fields ... */
};

/* Accessor macros */
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *)skb_network_header(skb);
}

static inline struct rtable *skb_rtable(const struct sk_buff *skb)
{
    return (struct rtable *)skb_dst(skb);
}
```

After a packet is received from the NIC driver:
- `skb->protocol` = `ETH_P_IP` (set by `eth_type_trans()`)
- `skb->network_header` points to the IP header
- `skb->data` points to the IP header (Ethernet header removed)

### `struct rtable` - Route Entry

Every routed packet has an associated routing entry:

```c
/* From include/net/route.h */
struct rtable {
    struct dst_entry dst;      /* Generic destination cache entry */
    
    int rt_genid;              /* Generation ID for cache invalidation */
    unsigned short rt_flags;   /* Routing flags */
    __u16 rt_type;             /* Route type: RTN_UNICAST, RTN_LOCAL, etc. */
    __u8 rt_is_input:1;        /* Is this for input? */
    __u8 rt_uses_gateway:1;    /* Uses gateway? */
    
    int rt_iif;                /* Input interface index */
    
    u8 rt_gw_family;           /* Gateway address family */
    union {
        __be32 rt_gw4;         /* IPv4 gateway */
        struct in6_addr rt_gw6; /* IPv6 gateway (for IPv4-mapped) */
    };
    
    /* Device for output */
    struct net_device *dst.dev;
    
    /* Cached from FIB lookup */
    u32 rt_mtu_locked:1;
    u32 rt_pmtu:31;            /* Path MTU */
};

/* The dst_entry provides function pointers for packet processing */
struct dst_entry {
    struct net_device *dev;
    struct dst_ops *ops;
    unsigned long expires;     /* Expiration time */
    
    /* Function pointers */
    int (*input)(struct sk_buff *); /* Input handler: ip_local_deliver, ip_forward, etc. */
    int (*output)(struct net *net, struct sock *sk, struct sk_buff *skb); /* Output handler */
    
    /* Reference counting */
    atomic_t __refcnt;
    int __use;
    
    /* ... */
};
```

The routing decision sets `skb_dst(skb)->input` to:
- `ip_local_deliver()` if destination is local
- `ip_forward()` if packet should be forwarded
- `ip_error()` if route lookup failed

### `struct fib_table` - Forwarding Information Base

The FIB holds routing table entries:

```c
/* From include/net/ip_fib.h */
struct fib_table {
    struct hlist_node tb_hlist;
    u32 tb_id;                 /* Table ID (RT_TABLE_MAIN = 254) */
    int tb_num_default;
    struct rcu_head rcu;
    unsigned long *tb_data;    /* Pointer to actual data structure (trie) */
    
    /* Operations */
    int (*tb_lookup)(struct fib_table *tb, const struct flowi4 *flp,
                    struct fib_result *res, int fib_flags);
    int (*tb_insert)(struct fib_table *, struct fib_config *, struct netlink_ext_ack *);
    int (*tb_delete)(struct fib_table *, struct fib_config *, struct netlink_ext_ack *);
    /* ... more operations ... */
};
```

Most systems use two routing tables:
- **RT_TABLE_LOCAL** (255): Local addresses
- **RT_TABLE_MAIN** (254): General routing table

### `struct key_vector` - FIB Trie Node

The FIB uses an LC-trie (Level Compressed trie) for fast longest-prefix-match lookups:

```c
/* From net/ipv4/fib_trie.c */
struct key_vector {
    t_key key;                 /* Routing prefix (network address) */
    unsigned char pos;         /* Position of first different bit */
    unsigned char bits;        /* Number of bits in this node */
    unsigned char slen;        /* Significant length of prefix */
    
    union {
        /* Internal node: pointers to child nodes */
        struct key_vector __rcu *tnode[0];
        
        /* Leaf node: routing entries */
        struct fib_alias __rcu *leaf[0];
    };
};

/* A leaf contains one or more fib_alias entries */
struct fib_alias {
    struct hlist_node fa_list;
    struct fib_info *fa_info;  /* Route information */
    u8 fa_tos;                 /* Type of Service */
    u8 fa_type;                /* Route type (RTN_UNICAST, etc.) */
    u8 fa_state;
    u8 fa_slen;                /* Prefix length */
    struct rcu_head rcu;
};

/* Actual route information */
struct fib_info {
    struct hlist_node fib_hash;
    struct hlist_node fib_lhash;
    int fib_treeref;
    refcount_t fib_clntref;
    unsigned int fib_flags;
    int fib_priority;          /* Route priority/metric */
    __be32 fib_prefsrc;        /* Preferred source address */
    u32 fib_tb_id;
    u32 fib_nhs;               /* Number of next hops */
    struct fib_nh fib_nh[0];   /* Next hop information */
};
```

### `struct net_protocol` - Protocol Handler Registration

Transport protocols register handlers for packet delivery:

```c
/* From include/net/protocol.h */
struct net_protocol {
    int (*handler)(struct sk_buff *skb);              /* Receive handler */
    int (*err_handler)(struct sk_buff *skb, u32 info); /* Error handler (ICMP) */
    unsigned int no_policy:1;  /* Don't check IPsec policy */
    unsigned int netns_ok:1;   /* Network namespace aware */
};

/* Global array indexed by protocol number */
extern const struct net_protocol __rcu *inet_protos[MAX_INET_PROTOS];

/* Example: TCP registration in net/ipv4/af_inet.c */
static const struct net_protocol tcp_protocol = {
    .handler = tcp_v4_rcv,
    .err_handler = tcp_v4_err,
    .no_policy = 1,
    .netns_ok = 1,
};

/* During initialization: */
inet_add_protocol(&tcp_protocol, IPPROTO_TCP);  /* TCP = 6 */
inet_add_protocol(&udp_protocol, IPPROTO_UDP);  /* UDP = 17 */
inet_add_protocol(&icmp_protocol, IPPROTO_ICMP); /* ICMP = 1 */
```

### `struct iphdr` - IP Header (Brief)

For reference, the kernel's IP header structure:

```c
/* From include/uapi/linux/ip.h */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 ihl:4,        /* Header length */
         version:4;    /* Version (4) */
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         ihl:4;
#endif
    __u8 tos;          /* Type of Service */
    __be16 tot_len;    /* Total length */
    __be16 id;         /* Identification */
    __be16 frag_off;   /* Flags (3 bits) + Fragment offset (13 bits) */
    __u8 ttl;          /* Time to live */
    __u8 protocol;     /* Protocol (TCP=6, UDP=17, ICMP=1) */
    __sum16 check;     /* Header checksum */
    __be32 saddr;      /* Source address */
    __be32 daddr;      /* Destination address */
    /* Options follow if ihl > 5 */
};

/* Flags in frag_off field */
#define IP_CE   0x8000  /* Congestion Experienced */
#define IP_DF   0x4000  /* Don't Fragment */
#define IP_MF   0x2000  /* More Fragments */
#define IP_OFFSET 0x1FFF /* Fragment offset mask */
```

Note the bitfield ordering depends on endianness (AMD64 is little-endian).

## Receive Path (RX) Implementation

### Protocol Handler Registration

During IP subsystem initialization, the IP layer registers itself to receive `ETH_P_IP` packets from the link layer:

```c
/* From net/ipv4/af_inet.c */
static struct packet_type ip_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_IP),  /* 0x0800 */
    .func = ip_rcv,                  /* Receive handler */
    .list_func = ip_list_rcv,        /* Batch receive (GRO) */
};

static int __init inet_init(void)
{
    /* ... other initialization ... */
    
    /* Register IP packet handler */
    dev_add_pack(&ip_packet_type);
    
    /* Register protocol handlers */
    if (inet_add_protocol(&icmp_protocol, IPPROTO_ICMP) < 0)
        pr_crit("%s: Cannot add ICMP protocol\n", __func__);
    if (inet_add_protocol(&udp_protocol, IPPROTO_UDP) < 0)
        pr_crit("%s: Cannot add UDP protocol\n", __func__);
    if (inet_add_protocol(&tcp_protocol, IPPROTO_TCP) < 0)
        pr_crit("%s: Cannot add TCP protocol\n", __func__);
    
    /* ... */
    return 0;
}

fs_initcall(inet_init);  /* Called during kernel initialization */
```

The `dev_add_pack()` function adds the handler to a global hash table (`ptype_base[]`) indexed by protocol type. When `netif_receive_skb()` processes a packet with `ETH_P_IP`, it calls `ip_rcv()`.

### Entry Point: `ip_rcv()` Implementation

The IP receive path starts in `ip_rcv()`:

```c
/* From net/ipv4/ip_input.c */
int ip_rcv(struct sk_buff *skb, struct net_device *dev,
          struct packet_type *pt, struct net_device *orig_dev)
{
    struct net *net = dev_net(dev);
    const struct iphdr *iph;
    u32 len;
    
    /* Fast path checks before pulling header */
    
    /* Drop packets for other hosts (unless promiscuous) */
    if (skb->pkt_type == PACKET_OTHERHOST)
        goto drop;
    
    /* Update statistics */
    __IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);
    
    /* Ensure IP header is in linear part of skb */
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        goto inhdr_error;
    
    iph = ip_hdr(skb);
    
    /* Sanity checks on IP header */
    
    /* RFC 791: version must be 4 */
    if (iph->version != 4)
        goto inhdr_error;
    
    /* Header length must be at least 20 bytes (5 * 4) */
    if (iph->ihl < 5)
        goto inhdr_error;
    
    /* Ensure full header is present (including options) */
    if (!pskb_may_pull(skb, iph->ihl * 4))
        goto inhdr_error;
    
    iph = ip_hdr(skb);  /* May have changed after pskb_may_pull */
    
    /* Verify IP header checksum (if not offloaded) */
    if (ip_fast_csum((u8 *)iph, iph->ihl))
        goto csum_error;
    
    /* Check total length */
    len = ntohs(iph->tot_len);
    if (skb->len < len) {
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (iph->ihl * 4))
        goto inhdr_error;
    
    /* Trim any extra bytes (padding from link layer) */
    if (pskb_trim_rcsum(skb, len))
        goto drop;
    
    /* Process IP options if present */
    if (iph->ihl > 5 && ip_rcv_options(skb, dev))
        goto drop;
    
    /* Store input interface for socket SO_BINDTODEVICE */
    skb->skb_iif = skb->dev->ifindex;
    
    /* Pass to netfilter PRE_ROUTING hook */
    return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
                  net, NULL, skb, dev, NULL,
                  ip_rcv_finish);
    
csum_error:
    __IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
    __IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
    kfree_skb(skb);
    return NET_RX_DROP;
}
```

Key implementation details:

1. **`pskb_may_pull()`**: Ensures the IP header is in the linear part of the skb. Non-linear skbs (with page fragments) need data pulled into the linear buffer before accessing headers.

2. **`ip_fast_csum()`**: Fast checksum calculation. On AMD64, uses optimized assembly. If hardware already validated the checksum (`skb->ip_summed == CHECKSUM_UNNECESSARY`), this check is skipped.

3. **Statistics**: `__IP_UPD_PO_STATS` and `__IP_INC_STATS` update per-CPU counters (visible in `/proc/net/snmp`).

4. **Options handling**: `ip_rcv_options()` parses and validates IP options if present.

### Checksum Validation Implementation

The `ip_fast_csum()` function is performance-critical:

```c
/* From arch/x86/include/asm/checksum_64.h */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
    unsigned int sum;
    
    asm("  movl (%1), %0\n"
        "  subl $4, %2\n"
        "  jbe 2f\n"
        "  addl 4(%1), %0\n"
        "  adcl 8(%1), %0\n"
        "  adcl 12(%1), %0\n"
        "1: adcl 16(%1), %0\n"
        "  lea 4(%1), %1\n"
        "  decl %2\n"
        "  jne 1b\n"
        "  adcl $0, %0\n"
        "  movl %0, %2\n"
        "  shrl $16, %0\n"
        "  addw %w2, %w0\n"
        "  adcl $0, %0\n"
        "  notl %0\n"
        "2:"
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl)
        : "memory");
    return (__force __sum16)sum;
}
```

This uses AMD64 assembly for maximum speed:
- Adds 32-bit words with carry (`adcl`)
- Folds 32-bit result into 16-bit checksum
- Typically ~10-20 CPU cycles for a 20-byte header

Hardware checksum offload bypasses this entirely, saving precious cycles.

### Netfilter Integration: `NF_HOOK`

The `NF_HOOK` macro invokes netfilter hooks (iptables/nftables rules):

```c
/* From include/linux/netfilter.h */
static inline int NF_HOOK(uint8_t pf, unsigned int hook,
                         struct net *net, struct sock *sk, struct sk_buff *skb,
                         struct net_device *in, struct net_device *out,
                         int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
    int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
    if (ret == 1)
        ret = okfn(net, sk, skb);  /* No hooks, continue */
    return ret;
}
```

Hook verdicts:
- `NF_ACCEPT` (1): Continue processing (call `okfn`)
- `NF_DROP` (0): Drop packet
- `NF_STOLEN` (2): Packet consumed by hook (don't free)
- `NF_QUEUE` (3): Queue to userspace
- `NF_REPEAT` (4): Call hook again

If no netfilter rules are active, this is a fast path (inline check, then direct call to `okfn`). With active rules, overhead is ~100-300 cycles per hook per packet.

### Route Lookup: `ip_rcv_finish()`

After netfilter PRE_ROUTING, the packet enters `ip_rcv_finish()`:

```c
/* From net/ipv4/ip_input.c */
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb->dev;
    int ret;
    
    /* Drop martian source addresses */
    if (ipv4_is_multicast(ip_hdr(skb)->saddr) ||
        ipv4_is_lbcast(ip_hdr(skb)->saddr))
        goto drop;
    
    /* Early demux: try to find socket directly */
    if (!skb_valid_dst(skb)) {
        int protocol = ip_hdr(skb)->protocol;
        const struct net_protocol *ipprot;
        
        ipprot = rcu_dereference(inet_protos[protocol]);
        if (ipprot && ipprot->early_demux) {
            ipprot->early_demux(skb);
            /* early_demux may set skb_dst */
        }
    }
    
    /* Perform route lookup if not already set */
    if (!skb_valid_dst(skb)) {
        int err = ip_route_input_noref(skb, ip_hdr(skb)->daddr,
                                       ip_hdr(skb)->saddr,
                                       ip_hdr(skb)->tos, dev);
        if (unlikely(err))
            goto drop;
    }
    
    /* Call the input handler based on route type */
    return dst_input(skb);
    
drop:
    kfree_skb(skb);
    return NET_RX_DROP;
}

/* dst_input() simply calls the function pointer from routing */
static inline int dst_input(struct sk_buff *skb)
{
    return skb_dst(skb)->input(skb);
}
```

### Early Demux Optimization

**Early demux** is a major performance optimization introduced in Linux 3.6. Instead of doing a full FIB lookup, it tries to find the socket directly:

```c
/* From net/ipv4/tcp_ipv4.c */
int tcp_v4_early_demux(struct sk_buff *skb)
{
    const struct iphdr *iph;
    const struct tcphdr *th;
    struct sock *sk;
    
    /* Need at least IP + TCP headers */
    if (skb_headlen(skb) < sizeof(struct iphdr) + sizeof(struct tcphdr))
        return 0;
    
    iph = ip_hdr(skb);
    th = (const struct tcphdr *)(iph + 1);
    
    /* Look up socket in hash table */
    sk = __inet_lookup_established(dev_net(skb->dev), &tcp_hashinfo,
                                   iph->saddr, th->source,
                                   iph->daddr, ntohs(th->dest),
                                   skb->skb_iif, inet_sdif(skb));
    if (sk) {
        skb->sk = sk;
        skb->destructor = sock_edemux;
        
        /* Use cached route from socket */
        if (sk->sk_state != TCP_TIME_WAIT) {
            struct dst_entry *dst = READ_ONCE(sk->sk_rx_dst);
            
            if (dst)
                dst = dst_check(dst, 0);
            if (dst) {
                /* Cache hit! Skip FIB lookup */
                skb_dst_set_noref(skb, dst);
                return 0;
            }
        }
    }
    return 0;
}
```

Early demux benefits:
- **Bypasses FIB lookup** for established connections
- Uses cached route from socket
- Huge win for TCP: ~30-40% improvement in receive throughput
- Typical fast path: ~50-100 cycles vs 200-400 for FIB lookup

### Route Lookup: `ip_route_input_noref()`

If early demux doesn't find a cached route, perform full lookup:

```c
/* From net/ipv4/route.c */
int ip_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                        u8 tos, struct net_device *dev)
{
    struct fib_result res;
    int err;
    
    tos &= IPTOS_RT_MASK;
    rcu_read_lock();
    
    /* Check for local addresses first (fast path) */
    err = ip_route_input_slow(skb, daddr, saddr, tos, dev, &res);
    
    rcu_read_unlock();
    return err;
}

static int ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                              u8 tos, struct net_device *dev,
                              struct fib_result *res)
{
    struct in_device *in_dev = __in_dev_get_rcu(dev);
    struct net *net = dev_net(dev);
    struct rtable *rth;
    struct flowi4 fl4;
    int err;
    
    /* Build flow key for lookup */
    flowi4_init_output(&fl4, dev->ifindex, 0, tos,
                      RT_SCOPE_UNIVERSE, 0, 0,
                      daddr, saddr, 0, 0, sock_net_uid(net, NULL));
    
    /* Check for local address (destination is us) */
    if (ipv4_is_local_multicast(daddr)) {
        /* Multicast to local group */
        goto local_input;
    }
    
    if (ipv4_is_zeronet(saddr))
        goto martian_source;
    
    /* Perform FIB lookup */
    err = fib_lookup(net, &fl4, res, 0);
    if (err != 0) {
        if (!IN_DEV_FORWARD(in_dev))
            goto e_inval;
        goto no_route;
    }
    
    /* Process result based on route type */
    if (res->type == RTN_LOCAL)
        goto local_input;
    
    if (res->type == RTN_BROADCAST)
        goto brd_input;
    
    if (res->type != RTN_UNICAST)
        goto martian_destination;
    
    /* Forward path */
    err = ip_mkroute_input(skb, res, in_dev, daddr, saddr, tos, fl4);
    return err;
    
local_input:
    /* Create route for local delivery */
    rth = rt_dst_alloc(net->loopback_dev, flags | RTCF_LOCAL, res->type,
                      IN_DEV_ORCONF(in_dev, NOPOLICY), false);
    if (!rth)
        goto e_nobufs;
    
    rth->dst.input = ip_local_deliver;
    skb_dst_set(skb, &rth->dst);
    return 0;
    
no_route:
    /* No route found */
    RT_CACHE_STAT_INC(in_no_route);
    res->type = RTN_UNREACHABLE;
    /* Will send ICMP unreachable */
    goto local_input;
    
    /* ... error handling ... */
}
```

Key routing decisions:

1. **Local delivery** (`RTN_LOCAL`): Destination is this host
   - Sets `dst->input = ip_local_deliver`
   - Packet goes up to transport layer

2. **Forwarding** (`RTN_UNICAST`): Destination is another host
   - Sets `dst->input = ip_forward`
   - Requires `/proc/sys/net/ipv4/ip_forward = 1`

3. **Broadcast** (`RTN_BROADCAST`): Broadcast address
   - Deliver locally and possibly forward

4. **No route** (`RTN_UNREACHABLE`): No matching route
   - Generate ICMP Destination Unreachable

The routing decision is stored in `skb_dst(skb)`, and `dst_input(skb)` calls the appropriate handler.

## Routing Infrastructure Implementation

The Linux routing subsystem uses a sophisticated data structure called an **LC-trie** (Level Compressed trie) for fast longest-prefix-match lookups.

### FIB Trie Overview

The FIB (Forwarding Information Base) trie provides O(log n) lookup time with good cache locality:

```
Example routing table:
192.168.0.0/16  → eth0
192.168.1.0/24  → eth1
192.168.1.128/25 → eth2
10.0.0.0/8      → eth3

Trie structure (simplified):
                    Root
                     │
          ┌──────────┴──────────┐
          │                     │
      bit 0=0               bit 0=1
     (192.168.x.x)        (10.x.x.x)
          │                     │
    ┌─────┴─────┐            Leaf [10.0.0.0/8]
    │           │
 bit 8=0     bit 8=1
   │           │
Leaf       ┌───┴───┐
[/16]      │       │
       bit 9=0  bit 9=1
          │       │
       Leaf    Leaf
       [/24]   [/25]
```

### FIB Lookup Implementation

The core lookup function traverses the trie:

```c
/* From net/ipv4/fib_trie.c */
int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,
                    struct fib_result *res, int fib_flags)
{
    struct trie *t = (struct trie *)tb->tb_data;
    struct key_vector *n, *pn;
    t_key key = ntohl(flp->daddr);  /* Network to host byte order */
    unsigned long index;
    t_key cindex;
    
    rcu_read_lock();
    
    /* Start at root */
    n = rcu_dereference(t->kv);
    if (!n)
        goto failed;
    
    /* Traverse trie */
    while (IS_TNODE(n)) {
        /* Internal node: determine which child to follow */
        index = get_index(key, n);
        
        /* Check for valid child */
        if (index >= (1ul << n->bits))
            break;
        
        /* Move to child node */
        n = rcu_dereference(n->tnode[index]);
        if (!n)
            break;
    }
    
    /* Reached a leaf node (or NULL) */
    /* Check all prefixes in this leaf for longest match */
    if (IS_LEAF(n)) {
        struct fib_alias *fa;
        
        hlist_for_each_entry_rcu(fa, &n->leaf, fa_list) {
            struct fib_info *fi = fa->fa_info;
            int nhsel, err;
            
            /* Check if prefix matches */
            if (fa->fa_slen < KEYLENGTH &&
                !fib_prefix_match(key, fa))
                continue;
            
            /* Check TOS (Type of Service) */
            if (fa->fa_tos && fa->fa_tos != flp->flowi4_tos)
                continue;
            
            /* Found a match! */
            if (fi->fib_flags & RTNH_F_DEAD)
                continue;
            
            /* Select next hop */
            for (nhsel = 0; nhsel < fi->fib_nhs; nhsel++) {
                const struct fib_nh *nh = &fi->fib_nh[nhsel];
                
                if (nh->fib_nh_flags & RTNH_F_DEAD)
                    continue;
                
                /* Found valid next hop */
                res->prefix = htonl(n->key);
                res->prefixlen = KEYLENGTH - fa->fa_slen;
                res->nh_sel = nhsel;
                res->type = fa->fa_type;
                res->scope = fa->fa_info->fib_scope;
                res->fi = fi;
                res->table = tb;
                res->fa_head = &n->leaf;
                
                rcu_read_unlock();
                return 0;
            }
        }
    }
    
failed:
    rcu_read_unlock();
    return -ENETUNREACH;
}
```

### Trie Node Structure Details

The trie uses two node types:

```c
/* From net/ipv4/fib_trie.c */

/* Check if node is internal (tnode) or leaf */
#define IS_TNODE(n) ((n)->bits)
#define IS_LEAF(n)  (!(n)->bits)

struct key_vector {
    t_key key;         /* Routing prefix (32 bits for IPv4) */
    
    /* Position of first bit that differs among children */
    unsigned char pos;
    
    /* Number of bits in this node's key */
    unsigned char bits;
    
    /* Significant length (prefix length) */
    unsigned char slen;
    
    union {
        /* Internal node: array of child pointers */
        /* Size: 2^bits entries */
        struct key_vector __rcu *tnode[0];
        
        /* Leaf node: list of routing entries */
        struct hlist_head leaf[0];
    };
};
```

Example node traversal:

```c
/* To find which child to follow for a given IP address */
static inline unsigned long get_index(t_key key, struct key_vector *kv)
{
    unsigned long index = key ^ kv->key;  /* XOR to find difference */
    
    /* Shift to get the relevant bits */
    if (kv->pos + kv->bits <= 32)
        return (index >> kv->pos) & ((1 << kv->bits) - 1);
    
    return 0;
}
```

For IP 192.168.1.130 (0xC0A80182) searching in a trie:
- Root node: Check bit 0 → 1 (MSB), take right child
- Next node: Check bits 8-15, extract index
- Continue until reaching leaf

### Level Compression

The "LC" in LC-trie means Level Compressed. Empty intermediate levels are skipped:

```
Without compression:        With compression:
       Root                      Root
        │                         │
    ┌───┴───┐                ┌────┴────┐
    0       1                0         1
    │       │                │         │
  ┌─┴─┐   ┌─┴─┐           Leaf    ┌───┴───┐
  0   1   0   1                    00  01  10  11
  │   │   │   │                    │   │   │   │
 ...            ...               ...         Leaves

Left side: Single child → Skip these levels
Right side: Multiple children → Compress into one node with bits=2
```

This reduces tree depth and improves cache locality.

### Route Installation

When adding a route via `ip route add`:

```c
/* From net/ipv4/fib_trie.c */
int fib_table_insert(struct fib_table *tb, struct fib_config *cfg,
                    struct netlink_ext_ack *extack)
{
    struct trie *t = (struct trie *)tb->tb_data;
    struct fib_alias *fa, *new_fa;
    struct key_vector *l, *tp;
    u32 key;
    int err;
    
    key = ntohl(cfg->fc_dst);
    
    /* Find insertion point */
    l = fib_find_node(t, &tp, key);
    
    /* Check for duplicate */
    if (l) {
        fa = fib_find_alias(&l->leaf, cfg->fc_dst_len, cfg->fc_tos,
                           cfg->fc_priority, cfg->fc_type);
        if (fa) {
            /* Route exists, check if we should replace */
            if (cfg->fc_nlflags & NLM_F_EXCL)
                return -EEXIST;
            
            if (cfg->fc_nlflags & NLM_F_REPLACE) {
                /* Replace existing route */
                return fib_replace_alias(t, tp, l, fa, new_fa, cfg, extack);
            }
        }
    }
    
    /* Allocate new fib_alias */
    new_fa = kmem_cache_alloc(fn_alias_kmem, GFP_KERNEL);
    if (!new_fa)
        return -ENOMEM;
    
    /* Fill in route information */
    new_fa->fa_info = fi;
    new_fa->fa_tos = cfg->fc_tos;
    new_fa->fa_type = cfg->fc_type;
    new_fa->fa_slen = cfg->fc_dst_len;
    
    /* Insert into trie */
    err = fib_insert_alias(t, tp, l, new_fa, NULL, key);
    if (err)
        goto out_free_new_fa;
    
    /* Notify routing daemons */
    rtmsg_fib(RTM_NEWROUTE, htonl(key), new_fa, cfg->fc_dst_len,
             tb->tb_id, &cfg->fc_nlinfo, 0);
    
    return 0;
    
out_free_new_fa:
    kmem_cache_free(fn_alias_kmem, new_fa);
    return err;
}
```

Trie insertion may require splitting nodes or creating new internal nodes to maintain the trie structure.

### Routing Tables

Linux supports multiple routing tables (policy routing):

```c
/* From include/uapi/linux/rtnetlink.h */
#define RT_TABLE_UNSPEC    0
#define RT_TABLE_COMPAT    252
#define RT_TABLE_DEFAULT   253
#define RT_TABLE_MAIN      254
#define RT_TABLE_LOCAL     255

/* Each network namespace has routing tables */
struct netns_ipv4 {
    struct fib_table __rcu *fib_main;   /* Main table (254) */
    struct fib_table __rcu *fib_local;  /* Local addresses (255) */
    struct fib_table __rcu *fib_default; /* Default table (253) */
    /* ... */
};
```

Typical lookup order:
1. Check local table (255) - for local addresses
2. Check main table (254) - for general routing
3. Check custom tables (via policy routing rules)

### Route Cache and DST

The older Linux kernels had a route cache, but it was removed in 3.6 due to cache poisoning attacks. Modern kernels cache routes per-socket:

```c
/* From include/net/sock.h */
struct sock {
    /* ... */
    struct dst_entry __rcu *sk_rx_dst;  /* RX cached route */
    struct dst_entry __rcu *sk_dst_cache; /* TX cached route */
    /* ... */
};
```

Socket route caching combined with early demux provides most of the benefits of a global route cache without the security issues.

### Destination Entry (DST)

The `dst_entry` structure is the generic interface for routing:

```c
/* From include/net/dst.h */
struct dst_entry {
    struct rcu_head rcu_head;
    struct dst_entry *child;
    struct net_device *dev;
    struct dst_ops *ops;
    
    unsigned long expires;
    struct dst_entry *path;
    struct dst_entry *from;
    
    /* Reference counting */
    atomic_t __refcnt;
    int __use;
    unsigned long lastuse;
    
    /* MTU information */
    int flags;
#define DST_HOST         0x0001
#define DST_NOXFRM       0x0002
#define DST_NOPOLICY     0x0004
#define DST_NOCOUNT      0x0008
    
    unsigned short header_len;  /* Space for link headers */
    unsigned short trailer_len;
    unsigned short pref_src_len;
    
    /* Function pointers for packet processing */
    int (*input)(struct sk_buff *);
    int (*output)(struct net *net, struct sock *sk, struct sk_buff *skb);
    
    /* ... more fields ... */
};
```

For IPv4, `struct rtable` embeds `dst_entry` as its first member, allowing safe casting.

### Multipath Routing

Linux supports multiple next hops for load balancing:

```c
/* From include/net/ip_fib.h */
struct fib_info {
    /* ... */
    int fib_nhs;                   /* Number of next hops */
    int fib_power;                 /* Total weight */
    struct fib_nh fib_nh[0];       /* Next hop array */
};

struct fib_nh {
    struct net_device *fib_nh_dev;  /* Output device */
    unsigned char fib_nh_scope;
    unsigned char fib_nh_flags;
    unsigned char fib_nh_weight;    /* Weight for load balancing */
    __be32 fib_nh_gw4;              /* Gateway IPv4 */
    int fib_nh_oif;                 /* Output interface index */
    /* ... */
};
```

Next hop selection uses weighted round-robin or flow-based hashing for per-flow consistency.

### RCU Protection

All routing table operations use RCU (Read-Copy-Update) for lockless reads:

```c
rcu_read_lock();
/* Read routing tables without locks */
rt = ip_route_output_key(net, &fl4);
/* ... use route ... */
rcu_read_unlock();
```

Benefits:
- Readers never block
- Multiple CPUs can lookup simultaneously
- Zero contention on read path
- Critical for routing performance at high packet rates

Writers (route updates) use RCU synchronization to ensure old routes aren't freed while readers use them.

## Local Delivery Path Implementation

When routing determines a packet is destined for the local host, `dst->input` is set to `ip_local_deliver()`.

### `ip_local_deliver()` Entry Point

```c
/* From net/ipv4/ip_input.c */
int ip_local_deliver(struct sk_buff *skb)
{
    struct net *net = dev_net(skb->dev);
    
    /* Handle fragmented packets */
    if (ip_is_fragment(ip_hdr(skb))) {
        if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
            return 0;  /* Queued for reassembly or dropped */
    }
    
    /* Pass through netfilter LOCAL_IN hook */
    return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
                  net, NULL, skb, skb->dev, NULL,
                  ip_local_deliver_finish);
}
```

### Fragment Reassembly: `ip_defrag()`

IP fragmentation allows large packets to be split across multiple smaller packets. Reassembly reconstructs the original packet:

```c
/* From net/ipv4/ip_fragment.c */
int ip_defrag(struct net *net, struct sk_buff *skb, u32 user)
{
    struct net_device *dev = skb->dev ? : skb_dst(skb)->dev;
    int vif = l3mdev_master_ifindex_rcu(dev);
    struct ipq *qp;
    
    __IP_INC_STATS(net, IPSTATS_MIB_REASMREQDS);
    
    /* Find or create fragment queue for this packet */
    qp = ip_find_or_create_frag_queue(net, ip_hdr(skb), user, vif);
    if (!qp) {
        kfree_skb(skb);
        return -ENOMEM;
    }
    
    /* Add fragment to queue */
    spin_lock(&qp->q.lock);
    
    if (qp->q.flags & INET_FRAG_COMPLETE)
        goto err;  /* Already complete */
    
    /* Insert fragment in queue (ordered by offset) */
    if (ip_frag_queue(qp, skb))
        goto err;  /* Error or still incomplete */
    
    /* All fragments received! */
    spin_unlock(&qp->q.lock);
    ipq_put(qp);
    return 0;  /* Packet reassembled and reinjected */
    
err:
    spin_unlock(&qp->q.lock);
    ipq_put(qp);
    return -EINVAL;
}
```

### Fragment Queue Structure

```c
/* From net/ipv4/ip_fragment.c */
struct ipq {
    struct inet_frag_queue q;  /* Generic fragment queue */
    
    u8 ecn;                    /* ECN bits from IP header */
    u16 max_df_size;           /* Max fragment size seen (with DF) */
    int iif;                   /* Input interface */
    unsigned int rid;
    struct inet_peer *peer;
    
    /* Fragments stored as linked list of skbs */
    struct sk_buff *fragments; /* First fragment */
    struct sk_buff *fragments_tail; /* Last fragment */
    
    /* Fragment map (bitmask of received fragments) */
    /* ... */
};
```

Fragment queues are indexed by a hash of (src IP, dst IP, ID, protocol):

```c
static unsigned int ipqhashfn(__be16 id, __be32 saddr, __be32 daddr, u8 prot)
{
    return jhash_3words((__force u32)id << 16 | prot,
                       (__force u32)saddr, (__force u32)daddr,
                       ip_frag_hashrnd) & (INETFRAGS_HASHSZ - 1);
}
```

### Reassembly Process

```c
/* From net/ipv4/ip_fragment.c */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
    struct net *net = container_of(qp->q.net, struct net, ipv4.frags);
    struct sk_buff *prev, *next;
    struct net_device *dev;
    unsigned int fragsize;
    int flags, offset;
    int ihl, end;
    int err = -ENOENT;
    u8 ecn;
    
    /* Fragment offset is in 8-byte units */
    offset = ntohs(ip_hdr(skb)->frag_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;
    offset <<= 3;  /* Convert to bytes */
    
    ihl = ip_hdrlen(skb);
    end = offset + skb->len - skb_network_offset(skb) - ihl;
    
    /* Check for overlap with existing fragments */
    /* ... overlap detection and handling ... */
    
    /* Find insertion point (keep fragments ordered by offset) */
    prev = qp->q.fragments_tail;
    if (!prev || FRAG_CB(prev)->offset < offset) {
        /* Append to end */
        next = NULL;
        goto found;
    }
    
    prev = NULL;
    for (next = qp->q.fragments; next != NULL; next = next->next) {
        if (FRAG_CB(next)->offset >= offset)
            break;
        prev = next;
    }
    
found:
    /* Insert fragment */
    FRAG_CB(skb)->offset = offset;
    skb->next = next;
    if (prev)
        prev->next = skb;
    else
        qp->q.fragments = skb;
    
    /* Update queue stats */
    qp->q.stamp = skb->tstamp;
    qp->q.meat += skb->len;
    qp->ecn |= ecn;
    add_frag_mem_limit(qp->q.net, skb->truesize);
    
    /* Check if complete */
    if (offset == 0)
        qp->q.flags |= INET_FRAG_FIRST_IN;
    
    if (!(flags & IP_MF))
        qp->q.flags |= INET_FRAG_LAST_IN;
    
    if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
        qp->q.meat == qp->q.len) {
        /* All fragments received - reassemble! */
        unsigned long orefdst = skb->_skb_refdst;
        
        skb->_skb_refdst = 0UL;
        err = ip_frag_reasm(qp, skb, prev, dev);
        skb->_skb_refdst = orefdst;
        if (err)
            qp->q.fragments = NULL;
        return err;
    }
    
    skb_dst_drop(skb);
    return -EINPROGRESS;  /* Still waiting for more fragments */
}
```

### Reassembly Completion

```c
static int ip_frag_reasm(struct ipq *qp, struct sk_buff *skb,
                        struct sk_buff *prev_tail, struct net_device *dev)
{
    struct net *net = container_of(qp->q.net, struct net, ipv4.frags);
    struct iphdr *iph;
    struct sk_buff *fp, *head = qp->q.fragments;
    int len, err;
    int sum_truesize;
    
    ipq_kill(qp);  /* Remove from hash table */
    
    /* Calculate total length */
    len = 0;
    sum_truesize = 0;
    fp = head;
    while (fp) {
        len += fp->len - skb_network_offset(fp) - ip_hdrlen(fp);
        sum_truesize += fp->truesize;
        fp = fp->next;
    }
    len += ip_hdrlen(head);
    
    /* Build reassembled packet */
    if (len > 65535)
        goto out_oversize;
    
    /* Merge fragments into first skb */
    fp = head;
    while (fp) {
        struct sk_buff *next = fp->next;
        
        if (fp != head) {
            /* Copy data from this fragment */
            if (skb_try_coalesce(head, fp, &fragstolen, &delta)) {
                /* Coalesced into head */
            } else {
                /* Add as paged data */
                if (!skb_shinfo(head)->frag_list)
                    skb_shinfo(head)->frag_list = fp;
                else
                    prev_tail->next = fp;
                prev_tail = fp;
            }
        }
        fp = next;
    }
    
    /* Update IP header */
    iph = ip_hdr(head);
    iph->tot_len = htons(len);
    iph->frag_off = 0;
    
    /* Clear fragment info */
    IPCB(head)->flags &= ~IPSKB_FRAG_COMPLETE;
    
    /* Resubmit reassembled packet */
    __IP_INC_STATS(net, IPSTATS_MIB_REASMOKS);
    qp->q.rb_fragments = RB_ROOT;
    qp->q.fragments_tail = NULL;
    qp->q.last_run_head = NULL;
    return 0;
    
out_oversize:
    net_info_ratelimited("Oversized IP packet from %pI4\n", &qp->q.key.v4.saddr);
    __IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
    return -EMSGSIZE;
}
```

Reassembled packets are reinjected into `ip_local_deliver()` (already past the `ip_defrag()` check).

### Fragment Timeout and Limits

Fragments have timeouts to prevent resource exhaustion:

```c
/* Default values */
#define IP_FRAG_TIME (30 * HZ)  /* 30 seconds */
#define IP_FRAG_MAX_MEM (4 * 1024 * 1024)  /* 4 MB */

/* Configurable via sysctl */
/proc/sys/net/ipv4/ipfrag_time
/proc/sys/net/ipv4/ipfrag_high_thresh
/proc/sys/net/ipv4/ipfrag_low_thresh
```

Incomplete fragment queues are discarded after timeout, sending ICMP Time Exceeded.

### Protocol Demultiplexing: `ip_local_deliver_finish()`

After netfilter and reassembly, the packet is delivered to the appropriate protocol handler:

```c
/* From net/ipv4/ip_input.c */
static int ip_local_deliver_finish(struct net *net, struct sock *sk,
                                  struct sk_buff *skb)
{
    __skb_pull(skb, skb_network_header_len(skb));  /* Remove IP header */
    
    rcu_read_lock();
    {
        const struct net_protocol *ipprot;
        int protocol = ip_hdr(skb)->protocol;
        
resubmit:
        /* Look up protocol handler */
        ipprot = rcu_dereference(inet_protos[protocol]);
        if (ipprot) {
            int ret;
            
            /* Deliver to protocol handler */
            ret = ipprot->handler(skb);
            if (ret < 0) {
                protocol = -ret;  /* Tunneling: retry with new protocol */
                goto resubmit;
            }
            __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
        } else {
            /* No handler registered */
            if (!raw_sk_rcv(net, skb, protocol)) {
                /* Not consumed by raw socket either */
                __IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
                
                /* Send ICMP Protocol Unreachable */
                icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, 0);
            }
            kfree_skb(skb);
        }
    }
    rcu_read_unlock();
    
    return 0;
}
```

### Protocol Handler Array

The `inet_protos` array maps protocol numbers to handlers:

```c
/* From net/ipv4/protocol.c */
const struct net_protocol __rcu *inet_protos[MAX_INET_PROTOS] __read_mostly;

/* Register a protocol */
int inet_add_protocol(const struct net_protocol *prot, unsigned char protocol)
{
    return !cmpxchg((const struct net_protocol **)&inet_protos[protocol],
                   NULL, prot) ? 0 : -1;
}

/* Common protocols */
inet_protos[IPPROTO_ICMP] = &icmp_protocol;  /* 1 */
inet_protos[IPPROTO_TCP] = &tcp_protocol;    /* 6 */
inet_protos[IPPROTO_UDP] = &udp_protocol;    /* 17 */
```

After `ipprot->handler(skb)` is called:
- For TCP: enters `tcp_v4_rcv()` → TCP state machine (see [udp_tcp.md](udp_tcp.md))
- For UDP: enters `udp_rcv()` → socket lookup and delivery
- For ICMP: enters `icmp_rcv()` → ICMP processing (covered below)

The IP layer's job is complete once the packet is handed to the transport layer.

## Forwarding Path Implementation

When routing determines a packet should be forwarded to another host, `dst->input` is set to `ip_forward()`.

### `ip_forward()` Core Implementation

```c
/* From net/ipv4/ip_forward.c */
int ip_forward(struct sk_buff *skb)
{
    u32 mtu;
    struct iphdr *iph = ip_hdr(skb);
    struct rtable *rt = skb_rtable(skb);
    struct net *net = dev_net(rt->dst.dev);
    
    /* Check if forwarding is enabled */
    if (!net->ipv4.sysctl_ip_forward)
        goto drop;
    
    /* Drop packets with strict source routing */
    if (ip_hdr(skb)->option & htonl(0x00800000))  /* SSRR or LSRR */
        goto sr_failed;
    
    /* Check TTL */
    if (ip_hdr(skb)->ttl <= 1)
        goto too_many_hops;
    
    /* Decrement TTL and update checksum */
    ip_decrease_ttl(iph);
    
    /* Check MTU */
    mtu = ip_dst_mtu_maybe_forward(&rt->dst, true);
    if (ip_exceeds_mtu(skb, mtu)) {
        /* Packet too big */
        if (ip_hdr(skb)->frag_off & htons(IP_DF)) {
            /* DF set: send ICMP, don't fragment */
            icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
                     htonl(mtu));
            goto drop;
        }
        /* Will fragment in ip_forward_finish */
    }
    
    /* Pass through netfilter FORWARD hook */
    return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD,
                  net, NULL, skb, skb->dev, rt->dst.dev,
                  ip_forward_finish);
    
too_many_hops:
    /* TTL expired */
    icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
    kfree_skb(skb);
    return NET_RX_DROP;
    
sr_failed:
    /* Source routing failed */
    icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
    goto drop;
}
```

### TTL Handling

```c
/* From include/net/ip.h */
static inline int ip_decrease_ttl(struct iphdr *iph)
{
    u32 check = (__force u32)iph->check;
    
    /* Decrement TTL */
    check += (__force u32)htons(0x0100);  /* Increment checksum */
    iph->check = (__force __sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}
```

This clever trick updates both TTL and checksum without recalculating the entire header checksum.

### Path MTU Discovery

When a packet is too large and DF (Don't Fragment) is set:

```c
void icmp_send(struct sk_buff *skb_in, int type, int code, __be32 info)
{
    /* For ICMP_FRAG_NEEDED, info contains MTU */
    if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED) {
        /* Store MTU in routing cache */
        dst_update_pmtu(&rt->dst, NULL, skb_in, ntohl(info));
    }
    
    /* Build and send ICMP packet */
    /* ... */
}
```

The sender receives this ICMP and reduces its sending MTU, avoiding future fragmentation.

### Forward Completion

```c
/* From net/ipv4/ip_forward.c */
static int ip_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct ip_options *opt = &IPCB(skb)->opt;
    
    __IP_INC_STATS(net, IPSTATS_MIB_OUTFORWDATAGRAMS);
    
    /* Handle IP options that need updating */
    if (unlikely(opt->optlen))
        ip_forward_options(skb);
    
    skb_sender_cpu_clear(skb);
    
    /* Send packet out */
    return dst_output(net, sk, skb);
}

/* dst_output calls the output function from routing */
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    return skb_dst(skb)->output(net, sk, skb);
}
```

The output function is typically `ip_output()`, leading to the transmit path.

## Transmit Path (TX) Implementation

The TX path handles locally-generated packets and forwarded packets.

### Entry from Transport Layer: `ip_queue_xmit()`

TCP/UDP call `ip_queue_xmit()` to send packets:

```c
/* From net/ipv4/ip_output.c */
int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,
                   __u8 tos)
{
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct ip_options_rcu *inet_opt;
    struct rtable *rt;
    struct iphdr *iph;
    int res;
    
    /* Check for cached route on socket */
    rcu_read_lock();
    rt = (struct rtable *)__sk_dst_check(sk, 0);
    if (!rt) {
        /* No cached route, perform lookup */
        struct flowi4 fl4;
        __be32 daddr;
        
        /* Build flow key */
        daddr = inet->inet_daddr;
        if (inet_opt && inet_opt->opt.srr)
            daddr = inet_opt->opt.faddr;
        
        flowi4_init_output(&fl4, sk->sk_bound_dev_if, sk->sk_mark,
                          tos, RT_SCOPE_UNIVERSE, sk->sk_protocol,
                          inet_sk_flowi_flags(sk),
                          daddr, inet->inet_saddr,
                          inet->inet_dport, inet->inet_sport,
                          sk->sk_uid);
        
        security_sk_classify_flow(sk, flowi4_to_flowi(&fl4));
        rt = ip_route_output_flow(net, &fl4, sk);
        if (IS_ERR(rt)) {
            res = PTR_ERR(rt);
            goto no_route;
        }
        
        /* Cache route on socket */
        sk_setup_caps(sk, &rt->dst);
    }
    rcu_read_unlock();
    
    /* Reserve space for IP header */
    skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    
    /* Build IP header */
    iph->version = 4;
    iph->ihl = 5 + (inet_opt ? inet_opt->opt.optlen >> 2 : 0);
    iph->tos = inet->tos;
    iph->tot_len = htons(skb->len);
    iph->id = htons(atomic_add_return(1, &net->ipv4.ip_ident));
    iph->frag_off = 0;
    if (ip_dont_fragment(sk, &rt->dst))
        iph->frag_off = htons(IP_DF);
    iph->ttl = ip_select_ttl(inet, &rt->dst);
    iph->protocol = sk->sk_protocol;
    iph->saddr = fl4->saddr;
    iph->daddr = fl4->daddr;
    
    /* Copy IP options */
    if (inet_opt)
        memcpy(iph + 1, inet_opt->opt.__data, inet_opt->opt.optlen);
    
    /* Calculate checksum */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        skb->csum_start = skb_transport_header(skb) - skb->head;
        skb->csum_offset = offsetof(struct tcphdr, check);  /* Or udphdr */
    }
    
    ip_send_check(iph);
    
    /* Send via IP output */
    res = ip_local_out(net, sk, skb);
    return res;
    
no_route:
    __IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
    kfree_skb(skb);
    return -EHOSTUNREACH;
}
```

Key steps:
1. **Route lookup** (or use cached route)
2. **Build IP header** (version, TTL, protocol, addresses)
3. **Set IP ID** for fragmentation identification
4. **Calculate checksum**
5. **Call `ip_local_out()`**

### Source Address Selection

If the socket doesn't have a bound source address:

```c
/* From net/ipv4/route.c */
static int ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4, /* ... */)
{
    /* ... */
    
    /* Select source address */
    if (!fl4->saddr) {
        if (fl4->flowi4_oif) {
            /* Use address of output interface */
            fl4->saddr = inet_select_addr(dev, fl4->daddr, RT_SCOPE_LINK);
        } else {
            /* Use address from routing table */
            fl4->saddr = fib_result_prefsrc(net, res);
        }
    }
    
    /* ... */
}
```

### IP Output: `ip_local_out()` and `ip_output()`

```c
/* From net/ipv4/ip_output.c */
int ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    int err;
    
    /* Pass through netfilter LOCAL_OUT hook */
    err = NF_HOOK_COND(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
                      net, sk, skb, NULL, skb_dst(skb)->dev,
                      dst_output,
                      !(IPCB(skb)->flags & IPSKB_REROUTED));
    if (likely(err == 1))
        err = dst_output(net, sk, skb);
    
    return err;
}

int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_device *dev = skb_dst(skb)->dev;
    
    __IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);
    
    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    
    /* Pass through netfilter POST_ROUTING hook */
    return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
                       net, sk, skb, NULL, dev,
                       ip_finish_output,
                       !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```

### Fragmentation Decision: `ip_finish_output()`

```c
/* From net/ipv4/ip_output.c */
static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    unsigned int mtu;
    int ret;
    
    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    /* ... */
    
    mtu = ip_skb_dst_mtu(sk, skb);
    if (skb_is_gso(skb))
        return ip_finish_output_gso(net, sk, skb, mtu);
    
    if (skb->len > mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU))
        return ip_fragment(net, sk, skb, mtu, ip_finish_output2);
    
    return ip_finish_output2(net, sk, skb);
}
```

GSO (Generic Segmentation Offload) packets are handled specially - the NIC will segment them.

### Neighbor Resolution: `ip_finish_output2()`

The final step before handing to the link layer:

```c
/* From net/ipv4/ip_output.c */
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct dst_entry *dst = skb_dst(skb);
    struct rtable *rt = (struct rtable *)dst;
    struct net_device *dev = dst->dev;
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    struct neighbour *neigh;
    bool is_v6gw = false;
    
    /* Ensure space for link-layer header */
    if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
        skb = skb_expand_head(skb, hh_len);
        if (!skb)
            return -ENOMEM;
    }
    
    /* Determine next hop */
    if (rt->rt_gw_family == AF_INET)
        neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
    else
        neigh = dst_neigh_output(dst, skb);
    
    if (!IS_ERR(neigh)) {
        int res;
        
        sock_confirm_neigh(skb, neigh);
        
        /* Send via neighbor */
        res = neigh_output(neigh, skb, is_v6gw);
        
        rcu_read_unlock_bh();
        return res;
    }
    
    /* No neighbor entry */
    kfree_skb(skb);
    return -EINVAL;
}
```

### Neighbor Output

The neighbor subsystem handles ARP resolution:

```c
/* From net/core/neighbour.c */
int neigh_output(struct neighbour *neigh, struct sk_buff *skb, bool is_v6gw)
{
    const struct hh_cache *hh = &neigh->hh;
    
    /* Fast path: cached link-layer header */
    if ((neigh->nud_state & NUD_CONNECTED) && hh->hh_len)
        return neigh_hh_output(hh, skb);
    
    /* Slow path: need ARP resolution */
    return neigh_resolve_output(neigh, skb);
}

static int neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb)
{
    int rc = 0;
    
    if (!neigh_event_send(neigh, skb)) {
        /* ARP resolution in progress or complete */
        struct net_device *dev = neigh->dev;
        unsigned int seq;
        
        /* Build link-layer header */
        do {
            seq = read_seqbegin(&neigh->ha_lock);
            rc = dev_hard_header(skb, dev, ntohs(skb->protocol),
                                neigh->ha, NULL, skb->len);
        } while (read_seqretry(&neigh->ha_lock, seq));
        
        if (rc >= 0)
            rc = dev_queue_xmit(skb);  /* Send to NIC driver! */
    } else {
        /* Queued for ARP resolution */
        rc = 0;
    }
    
    return rc;
}
```

If ARP resolution is needed, `neigh_event_send()` queues the packet and sends an ARP request. When the ARP reply arrives, queued packets are transmitted.

Finally, `dev_queue_xmit()` passes the packet to the NIC driver (see [nics.md](nics.md)).

## IP Fragmentation Implementation

When a packet exceeds the MTU and the DF flag is not set, the IP layer fragments it.

### Fragmentation Trigger

```c
/* From net/ipv4/ip_output.c */
int ip_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
               unsigned int mtu,
               int (*output)(struct net *, struct sock *, struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    int ptr;
    unsigned int hlen = iph->ihl * 4;
    unsigned int left = skb->len - hlen;  /* Data to fragment */
    unsigned int offset = ntohs(iph->frag_off) & IP_OFFSET;
    int not_last_frag = iph->frag_off & htons(IP_MF);
    __be16 frag_id = iph->id;
    
    /* MTU must accommodate at least 8 bytes of data per fragment */
    if (unlikely((mtu < hlen + 8) || (left + hlen > 65535)))
        goto fail;
    
    /* Fast path: linear skb */
    if (skb_is_gso(skb))
        return __ip_fragment_gso(net, sk, skb, mtu, output);
    
    /* Slow path: actual fragmentation */
    return ip_do_fragment(net, sk, skb, output);
    
fail:
    kfree_skb(skb);
    return -EMSGSIZE;
}
```

### Fragmentation Algorithm

```c
static int ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
                         int (*output)(struct net *, struct sock *, struct sk_buff *))
{
    struct iphdr *iph;
    struct sk_buff *skb2;
    struct rtable *rt = skb_rtable(skb);
    unsigned int mtu, hlen, left, len;
    int offset;
    int not_last_frag;
    __be16 frag_id;
    int ptr;
    int err = 0;
    
    iph = ip_hdr(skb);
    mtu = ip_skb_dst_mtu(sk, skb);
    hlen = iph->ihl * 4;
    left = skb->len - hlen;
    
    offset = ntohs(iph->frag_off) & IP_OFFSET;
    not_last_frag = iph->frag_off & htons(IP_MF);
    frag_id = iph->id;
    
    /* Fragment offset is in 8-byte units */
    ptr = hlen;
    
    /* Calculate fragment size (must be multiple of 8) */
    len = left;
    if (len > mtu)
        len = ((mtu - hlen) & ~7);  /* Round down to 8-byte boundary */
    
    left -= len;
    
    while (left > 0) {
        /* Allocate new fragment */
        if ((skb2 = alloc_skb(len + hlen + rt->dst.header_len + 15,
                              GFP_ATOMIC)) == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        
        /* Reserve space for link-layer header */
        skb_reserve(skb2, (rt->dst.header_len + 15) & ~15);
        
        /* Copy IP header */
        skb_put(skb2, hlen);
        skb_reset_network_header(skb2);
        skb2->transport_header = skb2->network_header + hlen;
        memcpy(skb_network_header(skb2), iph, hlen);
        
        /* Copy data */
        if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
            BUG();
        
        /* Update IP header for this fragment */
        iph = ip_hdr(skb2);
        iph->tot_len = htons(len + hlen);
        iph->frag_off = htons(offset >> 3);  /* Offset in 8-byte units */
        
        if (left > 0 || not_last_frag)
            iph->frag_off |= htons(IP_MF);  /* More Fragments */
        
        /* Recalculate checksum */
        ip_send_check(iph);
        
        /* Send this fragment */
        err = output(net, sk, skb2);
        if (err)
            goto fail;
        
        /* Move to next fragment */
        ptr += len;
        offset += len;
        left -= len;
        
        /* Calculate next fragment size */
        if (left > 0) {
            len = left;
            if (len > mtu)
                len = ((mtu - hlen) & ~7);
        }
    }
    
    /* Send the final fragment (original skb modified) */
    iph = ip_hdr(skb);
    iph->tot_len = htons(skb->len - hlen);
    iph->frag_off = htons(offset >> 3);
    if (not_last_frag)
        iph->frag_off |= htons(IP_MF);
    ip_send_check(iph);
    
    err = output(net, sk, skb);
    
    if (err == 0)
        __IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
    
    return err;
    
fail:
    kfree_skb(skb);
    __IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
    return err;
}
```

Key points:
- **Fragment size**: Must be multiple of 8 bytes (except last fragment)
- **Fragment offset**: Stored in 13 bits, in units of 8 bytes (max 8192 * 8 = 65536 bytes)
- **IP ID**: Same for all fragments of a packet
- **MF flag**: Set on all fragments except the last

Fragment example:
```
Original: 4000 bytes
MTU: 1500 bytes
Header: 20 bytes

Fragment 1: offset=0, len=1480, MF=1
Fragment 2: offset=1480, len=1480, MF=1
Fragment 3: offset=2960, len=1040, MF=0
```

## ICMP Implementation

ICMP handles control messages and errors.

### ICMP Handler Registration and Dispatch

```c
/* From net/ipv4/icmp.c */
static const struct icmp_control icmp_pointers[NR_ICMP_TYPES + 1] = {
    [ICMP_ECHOREPLY] = {
        .handler = ping_rcv,
    },
    [ICMP_DEST_UNREACH] = {
        .handler = icmp_unreach,
        .error = 1,
    },
    [ICMP_SOURCE_QUENCH] = {
        .handler = icmp_unreach,
        .error = 1,
    },
    [ICMP_REDIRECT] = {
        .handler = icmp_redirect,
        .error = 1,
    },
    [ICMP_ECHO] = {
        .handler = icmp_echo,
    },
    [ICMP_TIME_EXCEEDED] = {
        .handler = icmp_unreach,
        .error = 1,
    },
    [ICMP_PARAMETERPROB] = {
        .handler = icmp_unreach,
        .error = 1,
    },
    /* ... */
};

int icmp_rcv(struct sk_buff *skb)
{
    struct icmphdr *icmph;
    struct rtable *rt = skb_rtable(skb);
    struct net *net = dev_net(rt->dst.dev);
    
    /* Validate ICMP header */
    if (!pskb_pull(skb, sizeof(*icmph)))
        goto error;
    
    icmph = icmp_hdr(skb);
    
    /* Verify checksum */
    if (skb_checksum_simple_validate(skb))
        goto csum_error;
    
    /* Dispatch to handler */
    if (icmph->type > NR_ICMP_TYPES)
        goto error;
    
    return icmp_pointers[icmph->type].handler(skb);
    
csum_error:
    __ICMP_INC_STATS(net, ICMP_MIB_CSUMERRORS);
error:
    __ICMP_INC_STATS(net, ICMP_MIB_INERRORS);
    kfree_skb(skb);
    return 0;
}
```

### Echo Request/Reply (Ping) Implementation

```c
/* From net/ipv4/icmp.c */
static bool icmp_echo(struct sk_buff *skb)
{
    struct net *net = dev_net(skb_dst(skb)->dev);
    
    /* Rate limit check */
    if (!icmp_global_allow())
        return false;
    
    /* Reply to echo request */
    return icmp_reply(net, skb, ICMP_ECHOREPLY, 0);
}

static bool icmp_reply(struct net *net, struct sk_buff *skb, int type, int code)
{
    struct iphdr *iph = ip_hdr(skb);
    struct icmphdr *icmph = icmp_hdr(skb);
    struct rtable *rt = skb_rtable(skb);
    struct sock *sk;
    struct inet_sock *inet;
    __be32 daddr, saddr;
    u32 mark = IP4_REPLY_MARK(net, skb->mark);
    int err;
    
    /* Swap addresses */
    daddr = iph->saddr;
    saddr = iph->daddr;
    
    /* Build ICMP reply */
    {
        struct sk_buff *nskb;
        struct icmphdr *nicmph;
        
        /* Allocate reply packet */
        nskb = alloc_skb(MAX_HEADER + sizeof(struct iphdr) + 
                        sizeof(struct icmphdr) + skb->len, GFP_ATOMIC);
        if (!nskb)
            return false;
        
        /* Reserve space */
        skb_reserve(nskb, MAX_HEADER + sizeof(struct iphdr));
        
        /* Build ICMP header */
        nicmph = skb_put(nskb, sizeof(struct icmphdr));
        nicmph->type = type;
        nicmph->code = code;
        nicmph->un.echo.id = icmph->un.echo.id;
        nicmph->un.echo.sequence = icmph->un.echo.sequence;
        
        /* Copy payload */
        skb_copy_bits(skb, sizeof(struct icmphdr),
                     skb_put(nskb, skb->len - sizeof(struct icmphdr)),
                     skb->len - sizeof(struct icmphdr));
        
        /* Calculate checksum */
        nicmph->checksum = 0;
        nicmph->checksum = ip_compute_csum((unsigned char *)nicmph,
                                          nskb->len);
        
        /* Send reply */
        err = ip_push_pending_frames(sk, &fl4, nskb);
    }
    
    return true;
}
```

### ICMP Error Generation

```c
/* From net/ipv4/icmp.c */
void icmp_send(struct sk_buff *skb_in, int type, int code, __be32 info)
{
    struct iphdr *iph;
    int room;
    struct icmp_bxm icmp_param;
    struct rtable *rt = skb_rtable(skb_in);
    struct ipcm_cookie ipc;
    struct flowi4 fl4;
    __be32 saddr;
    u8 tos;
    u32 mark;
    struct net *net;
    struct sock *sk;
    
    if (!rt)
        goto out;
    
    net = dev_net(rt->dst.dev);
    
    /* Don't send ICMP errors about ICMP errors */
    if (rt->rt_flags & RTCF_BROADCAST)
        goto out;
    
    iph = ip_hdr(skb_in);
    
    /* Rate limiting */
    if (!icmpv4_xrlim_allow(net, rt, &fl4, type, code))
        goto out;
    
    /* Build ICMP packet */
    icmp_param.data.icmph.type = type;
    icmp_param.data.icmph.code = code;
    icmp_param.data.icmph.un.gateway = info;
    icmp_param.data.icmph.checksum = 0;
    
    /* Copy offending packet's IP header + 8 bytes */
    icmp_param.skb = skb_in;
    icmp_param.offset = skb_network_offset(skb_in);
    
    /* Route for ICMP packet */
    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt))
        goto out_unlock;
    
    /* Send ICMP packet */
    icmp_push_reply(&icmp_param, &fl4, &ipc, &rt);
    
out_unlock:
    return;
out:
    __ICMP_INC_STATS(net, ICMP_MIB_OUTERRORS);
    goto out_unlock;
}
```

### ICMP Rate Limiting

To prevent ICMP floods:

```c
/* From net/ipv4/icmp.c */
static bool icmpv4_xrlim_allow(struct net *net, struct rtable *rt,
                              struct flowi4 *fl4, int type, int code)
{
    struct dst_entry *dst = &rt->dst;
    struct inet_peer *peer;
    bool rc = true;
    int vif;
    
    if (icmp_global_allow()) {
        vif = l3mdev_master_ifindex_rcu(dst->dev);
        peer = inet_getpeer_v4(net->ipv4.peers, fl4->daddr, vif, 1);
        rc = inet_peer_xrlim_allow(peer, net->ipv4.sysctl_icmp_ratelimit);
        if (peer)
            inet_putpeer(peer);
    }
    return rc;
}

/* Token bucket rate limiting */
bool inet_peer_xrlim_allow(struct inet_peer *peer, int timeout)
{
    unsigned long now, token;
    bool rc = false;
    
    if (!peer)
        return true;
    
    token = peer->rate_token;
    now = jiffies;
    token += now - peer->rate_last;
    peer->rate_last = now;
    if (token > XRLIM_BURST_FACTOR * timeout)
        token = XRLIM_BURST_FACTOR * timeout;
    
    if (token >= timeout) {
        token -= timeout;
        rc = true;
    }
    peer->rate_token = token;
    return rc;
}
```

Default: 1000 ICMP messages per second per destination (`/proc/sys/net/ipv4/icmp_ratelimit`).

## Performance Considerations and Cross-References

### Fast Path Optimizations

Key optimizations in the IP layer:

1. **Early Demux** (~30-40% RX improvement for TCP)
   - Direct socket lookup before routing
   - Bypasses FIB trie traversal
   - Per-socket route caching

2. **RCU for Lockless Reads**
   - Zero contention on routing lookups
   - Critical for multi-core scalability
   - Readers never block

3. **Per-CPU Caching**
   - IP ID generation (`ip_idents`)
   - Statistics counters
   - Fragment queues

4. **Inline Functions**
   - `ip_hdr()`, `skb_rtable()` - hot path accessors
   - `ip_decrease_ttl()` - optimized TTL/checksum update

5. **LC-Trie for Routing**
   - O(log n) lookup with excellent cache locality
   - Level compression reduces memory footprint
   - ~100-200 cycles for cached lookup, ~200-400 for FIB miss

### Typical Performance Metrics

On modern hardware (AMD64, 3GHz CPU, 10GbE NIC):

- **IP RX fast path**: ~300-500 CPU cycles per packet
  - Early demux hit: ~50-100 cycles
  - Route lookup (cached): ~100-200 cycles
  - Route lookup (FIB): ~200-400 cycles
  - Netfilter (per active hook): +100-300 cycles
  
- **IP TX path**: ~200-400 CPU cycles per packet
  - Route lookup (socket cached): ~50 cycles
  - Header construction: ~100 cycles
  - Checksum: ~20-30 cycles (or offloaded)
  
- **Fragmentation/Reassembly**: ~2000-5000 cycles per packet
  - Should be avoided when possible (use Path MTU Discovery)
  
- **ICMP processing**: ~500-1000 cycles per message

Total IP layer overhead: typically 5-10% of overall packet processing time at line rate.

### Cross-References to Other Chapters

#### From NIC Driver
See [nics.md](nics.md):
- Packets enter via `netif_receive_skb()` → protocol handlers
- `ip_packet_type` registered for `ETH_P_IP`
- GRO may aggregate packets before IP layer

#### To Transport Layer
See [udp_tcp.md](udp_tcp.md):
- After `ip_local_deliver_finish()`, calls `tcp_v4_rcv()` / `udp_rcv()`
- Transport protocols call `ip_queue_xmit()` for transmission
- Socket route caching critical for performance

#### Softirq Context
See [Linux Interrupt Handling](linux_interrupts.md):
- IP RX in `NET_RX_SOFTIRQ` context (no sleeping)
- Must use `GFP_ATOMIC` for allocations
- Processing budget limits prevent starvation

#### System Call Integration
See [syscalls.md](syscalls.md):
- `setsockopt(IP_TTL, IP_TOS, IP_PKTINFO, etc.)`
- `sendto()`/`recvfrom()` traverse IP layer
- `SO_BINDTODEVICE` affects routing

#### Scheduler Impact
See [scheduler.md](scheduler.md):
- Softirq processing competes with normal tasks
- High packet rates can monopolize CPU
- `ksoftirqd` handles overflow

The IP layer is the glue between link and transport layers, providing addressing, routing, and fragmentation while maintaining high performance through careful optimization of the fast path.

