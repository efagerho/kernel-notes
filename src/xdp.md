# XDP (eXpress Data Path) Implementation

## Overview

**XDP (eXpress Data Path)** is a high-performance, programmable packet processing framework in the Linux kernel. XDP allows eBPF (extended Berkeley Packet Filter) programs to run at the earliest point in the network receive path - directly in the NIC driver before SKB (socket buffer) allocation.

### What Makes XDP Fast?

Traditional Linux networking path:
```
NIC → DMA → Driver → Allocate SKB → IP layer → TCP/UDP → Socket → Application
                     ↑
              ~3000-5000 CPU cycles per packet
```

XDP path:
```
NIC → DMA → Driver → XDP Program → Action (drop/pass/tx/redirect)
                     ↑
              ~50-500 CPU cycles per packet
```

Key performance advantages:

1. **No SKB allocation**: Process packets before creating the heavyweight SKB structure
2. **Early processing**: Make decisions (drop, forward, modify) at the driver level
3. **JIT compilation**: eBPF programs are compiled to native machine code
4. **Batch processing**: XDP runs in NAPI softirq context with batching
5. **Zero-copy to userspace**: AF_XDP sockets enable zero-copy packet delivery

### Why XDP?

XDP enables specialized high-performance networking use cases:

- **DDoS mitigation**: Drop malicious packets at line rate (10+ Mpps per core)
- **Load balancing**: Fast L3/L4 packet forwarding without full TCP/IP stack
- **Packet filtering**: Programmable firewall with sub-microsecond latency
- **Monitoring/Sampling**: Efficient packet capture and statistics
- **Traffic shaping**: Early packet classification and marking

### XDP as a Complement, Not Replacement

XDP doesn't replace the kernel network stack - it complements it:

- **XDP_DROP**: Drop unwanted packets early (DDoS mitigation)
- **XDP_PASS**: Pass interesting packets to full network stack
- **XDP_TX**: Fast packet reflection (respond without allocating SKB)
- **XDP_REDIRECT**: Fast forwarding or delivery to AF_XDP sockets

Traditional sockets, TCP, routing, etc. continue to work unchanged. XDP provides a fast path for specific workloads while the kernel stack handles everything else.

### Relationship to Kernel Networking

```
User Space:
    Application ←──────────────┐
         ↑                      │
    [syscall]              [AF_XDP]
         ↑                      │
Kernel Space:                   │
    Socket Layer               │
         ↑                      │
    TCP/UDP ←─── XDP_PASS      │
         ↑            ↑         │
    IP Layer         │         │
         ↑            │         │
    Link Layer       │         │
         ↑            │         │
    Network Driver   │         │
         ↑            │         │
    XDP Program ─────┴─────────┘
         ↑         (XDP_REDIRECT)
    [DMA from NIC]
```

XDP sits at the lowest software layer, making decisions before the packet enters the normal networking stack.

## XDP Execution Modes

XDP supports three modes of operation, offering different trade-offs between performance and compatibility.

### Native XDP (Driver Mode)

**Native XDP** is the highest-performance mode, where XDP programs run directly inside the network driver's receive path.

#### Location and Timing

```
Packet flow with Native XDP:

1. Packet arrives at NIC
2. NIC DMAs packet data to memory (driver's RX ring buffer)
3. Driver processes RX descriptor
4. ═══════════════════════════════════════════════
   ║ XDP PROGRAM RUNS HERE (Native Mode)       ║
   ║ - Packet data in DMA buffer                 ║
   ║ - No SKB allocated yet                      ║
   ║ - Minimal overhead                          ║
   ═══════════════════════════════════════════════
5. Based on XDP verdict:
   - XDP_DROP: Free buffer, done (~50-100 cycles total)
   - XDP_PASS: Allocate SKB, continue to network stack
   - XDP_TX: Transmit on same interface
   - XDP_REDIRECT: Forward to another interface or AF_XDP
```

#### Implementation in ixgbe Driver

The ixgbe driver (Intel 10GbE) integrates XDP in its NAPI poll function:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
                              struct ixgbe_ring *rx_ring,
                              int budget)
{
    unsigned int total_rx_bytes = 0, total_rx_packets = 0;
    struct xdp_buff xdp;
    struct bpf_prog *xdp_prog;
    u32 xdp_act = 0;
    
    /* Get XDP program (RCU protected) */
    xdp_prog = READ_ONCE(rx_ring->xdp_prog);
    
    /* Setup XDP buffer info (once per batch) */
    xdp.rxq = &rx_ring->xdp_rxq;
    xdp.frame_sz = ixgbe_rx_frame_truesize(rx_ring, 0);
    
    while (likely(total_rx_packets < budget)) {
        union ixgbe_adv_rx_desc *rx_desc;
        struct ixgbe_rx_buffer *rx_buffer;
        unsigned int size;
        
        /* Get next descriptor */
        rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);
        
        /* Check if descriptor is ready (DD bit set by hardware) */
        if (!ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_DD))
            break;
        
        /* Ensure descriptor writes are visible */
        dma_rmb();
        
        rx_buffer = ixgbe_get_rx_buffer(rx_ring, rx_desc, &size);
        
        /* Run XDP program if attached */
        if (xdp_prog) {
            u32 act;
            
            /* Setup XDP context pointing to DMA buffer */
            xdp.data_hard_start = page_address(rx_buffer->page) +
                                  rx_buffer->page_offset - headroom;
            xdp.data = xdp.data_hard_start + headroom;
            xdp.data_end = xdp.data + size;
            xdp.data_meta = xdp.data;
            
            /* Execute XDP program */
            act = bpf_prog_run_xdp(xdp_prog, &xdp);
            
            /* Handle XDP verdict */
            switch (act) {
            case XDP_PASS:
                /* Continue to SKB allocation below */
                break;
                
            case XDP_DROP:
                /* Drop packet - just reuse the buffer */
                ixgbe_reuse_rx_buffer(rx_ring, rx_buffer);
                xdp_act |= IXGBE_XDP_CONSUMED;
                break;
                
            case XDP_TX:
                /* Transmit packet out same interface */
                xdp_act = ixgbe_xdp_xmit_back(adapter, &xdp);
                break;
                
            case XDP_REDIRECT:
                /* Redirect to another interface or AF_XDP socket */
                if (!xdp_do_redirect(rx_ring->netdev, &xdp, xdp_prog))
                    xdp_act |= IXGBE_XDP_REDIR;
                else
                    ixgbe_reuse_rx_buffer(rx_ring, rx_buffer);
                break;
                
            default:
                bpf_warn_invalid_xdp_action(act);
                /* fall through */
            case XDP_ABORTED:
                trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
                /* fall through -- handle aborts by dropping */
                ixgbe_reuse_rx_buffer(rx_ring, rx_buffer);
                break;
            }
            
            /* If packet was consumed by XDP, move to next */
            if (xdp_act & (IXGBE_XDP_CONSUMED | IXGBE_XDP_REDIR)) {
                total_rx_packets++;
                total_rx_bytes += size;
                
                /* Move to next descriptor */
                ixgbe_inc_rx_ntc(rx_ring);
                continue;
            }
        }
        
        /* XDP_PASS or no XDP program: allocate SKB and continue */
        skb = ixgbe_construct_skb(rx_ring, rx_buffer, &xdp, rx_desc);
        if (!skb) {
            /* SKB allocation failed */
            rx_ring->rx_stats.alloc_rx_buff_failed++;
            rx_buffer->pagecnt_bias++;
            break;
        }
        
        /* Continue normal packet processing (GRO, protocol handlers, etc.) */
        ixgbe_process_skb_fields(rx_ring, rx_desc, skb);
        napi_gro_receive(&q_vector->napi, skb);
        
        /* Update statistics */
        total_rx_bytes += skb->len;
        total_rx_packets++;
    }
    
    /* Update ring statistics */
    u64_stats_update_begin(&rx_ring->syncp);
    rx_ring->stats.packets += total_rx_packets;
    rx_ring->stats.bytes += total_rx_bytes;
    u64_stats_update_end(&rx_ring->syncp);
    
    return total_rx_packets;
}
```

Key points:

- **Before SKB allocation**: XDP runs on raw DMA buffer data
- **Same CPU**: XDP runs on the CPU that received the interrupt (RSS affinity)
- **Softirq context**: Part of NAPI polling (see [Linux Interrupt Handling](linux_interrupts.md))
- **Direct buffer access**: `xdp.data` points directly into the DMA-mapped page
- **Zero overhead for XDP_DROP**: Just reuse the buffer, no allocations

#### Driver Support Requirements

For native XDP, drivers must:

1. **Expose DMA buffers**: XDP needs direct access to packet data before SKB
2. **Reserve headroom**: Space before packet data for encapsulation
3. **Support XDP TX**: Ability to transmit XDP frames
4. **Implement XDP_REDIRECT**: For AF_XDP and device-to-device forwarding

Drivers with native XDP support:
- **Intel**: ixgbe, i40e, ice, igb
- **Mellanox**: mlx4, mlx5
- **Others**: virtio_net, tun/tap, veth, many more

Check driver support:
```bash
# Check if driver supports XDP
ethtool -i eth0  # Look for driver name
ip link set dev eth0 xdp obj xdp_prog.o  # Will fail if unsupported
```

### Offloaded XDP (Hardware Mode)

**Offloaded XDP** runs the XDP program on the NIC's hardware (SmartNIC), offloading processing from the host CPU entirely.

#### How It Works

```
Traditional XDP:
NIC → DMA to host → Host CPU runs XDP program → Action

Offloaded XDP:
NIC → SmartNIC CPU runs XDP program → Action
      (Packet may never reach host!)
```

#### Advantages and Limitations

**Advantages:**
- **Zero host CPU usage**: XDP program runs on NIC processor
- **Lowest latency**: Decisions made before DMA to host
- **Higher throughput**: Host CPU free for other work

**Limitations:**
- **Limited eBPF features**: Hardware may not support all eBPF instructions
- **Smaller programs**: Limited program size due to hardware memory
- **SmartNIC required**: Expensive hardware (Netronome NFP, Mellanox ConnectX-6 Dx)
- **Harder debugging**: Limited visibility into hardware execution

Usage:
```bash
# Offload XDP program to NIC hardware
ip link set dev eth0 xdpoffload obj xdp_prog.o
```

Offloaded XDP is mainly used in specialized deployments (cloud providers, telcos) where every CPU cycle matters.

### Generic XDP (SKB Mode)

**Generic XDP** is a fallback mode that works with any network driver, but runs after SKB allocation.

#### When It's Used

```
Packet flow with Generic XDP:

1. Packet arrives at NIC
2. NIC DMAs packet data
3. Driver processes descriptor
4. Driver allocates SKB    ← SKB already created!
5. ═══════════════════════════════════════════════
   ║ XDP PROGRAM RUNS HERE (Generic Mode)       ║
   ║ - Packet data in SKB                        ║
   ║ - SKB allocation cost already paid          ║
   ║ - Much slower than native XDP               ║
   ═══════════════════════════════════════════════
6. Based on XDP verdict: continue processing
```

#### Implementation

Generic XDP hooks into the network core after drivers:

```c
/* From net/core/dev.c */
static int __netif_receive_skb_core(struct sk_buff *skb, bool pfmemalloc)
{
    struct bpf_prog *xdp_prog = NULL;
    
    /* Check for generic XDP program */
    xdp_prog = rcu_dereference(skb->dev->xdp_prog);
    if (xdp_prog) {
        struct xdp_buff xdp;
        u32 act;
        
        /* Convert SKB to XDP buffer */
        xdp.data_hard_start = skb->data - skb_headroom(skb);
        xdp.data = skb->data;
        xdp.data_end = skb->data + skb_headlen(skb);
        xdp.data_meta = xdp.data;
        
        /* Run XDP program */
        act = bpf_prog_run_xdp(xdp_prog, &xdp);
        
        switch (act) {
        case XDP_PASS:
            break;
        case XDP_DROP:
            kfree_skb(skb);
            return NET_RX_DROP;
        /* ... other actions ... */
        }
    }
    
    /* Continue normal processing */
    /* ... */
}
```

#### When to Use Generic XDP

Generic XDP is useful for:
- **Development and testing**: Test XDP programs without native-XDP-capable hardware
- **Unsupported drivers**: Use XDP with any network device
- **Compatibility**: Ensure XDP programs work before deploying to production

**Do NOT use Generic XDP for production performance-critical applications.** It defeats the main purpose of XDP (avoiding SKB allocation overhead).

Enable Generic XDP:
```bash
# Force generic XDP mode
ip link set dev eth0 xdpgeneric obj xdp_prog.o
```

### Mode Comparison

| Feature | Native XDP | Offloaded XDP | Generic XDP |
|---------|-----------|---------------|-------------|
| **Location** | Driver | NIC hardware | Network core |
| **Timing** | Before SKB | Before DMA | After SKB |
| **Performance** | ~100-500 cycles | ~0 host cycles | ~1000+ cycles |
| **Driver support** | Required | SmartNIC required | All drivers |
| **Throughput** | 10+ Mpps/core | 100+ Mpps | ~3-5 Mpps/core |
| **Use case** | Production | Specialized | Development |

For production deployments, **always use Native XDP** when available.

## XDP Data Structures

### The `xdp_buff` Structure

The `xdp_buff` is the core data structure that XDP programs interact with. It provides direct access to packet data in the DMA buffer.

```c
/* From include/net/xdp.h */
struct xdp_buff {
    void *data;              /* Pointer to start of packet data */
    void *data_end;          /* Pointer to end of packet data */
    void *data_meta;         /* Pointer to metadata area (before data) */
    void *data_hard_start;   /* Pointer to start of DMA buffer (includes headroom) */
    struct xdp_rxq_info *rxq; /* RX queue metadata */
    struct xdp_txq_info *txq; /* TX queue metadata (for XDP_TX) */
    u32 frame_sz;            /* Total frame size (data_hard_start to end) */
};
```

#### Memory Layout

```
Complete DMA Buffer:

┌─────────────────────────────────────────────────────────────┐
│                  DMA-mapped Page (e.g., 4096 bytes)         │
├──────────────┬──────────┬────────────────┬─────────────────┤
│   Headroom   │ Metadata │ Packet Data    │   Tailroom      │
│  (256 bytes) │(optional)│  (1500 bytes)  │  (remaining)    │
└──────────────┴──────────┴────────────────┴─────────────────┘
▲              ▲          ▲                ▲                  ▲
│              │          │                │                  │
data_hard_start│      data (packet start) │                  │
               │                      data_end               │
          data_meta                                     frame_sz

Accessible to XDP program:
- data to data_end: Actual packet (must bounds-check!)
- data_meta to data: Metadata added by XDP program
- Headroom: Space for adding headers (encapsulation)
- Tailroom: Space for adding trailers

XDP program can:
- Read: data to data_end (with bounds checking)
- Modify: Packet contents within bounds
- Adjust pointers: Move data/data_end (within limits)
- Add metadata: Use bpf_xdp_adjust_meta()
```

#### Pointer Rules and Constraints

```c
/* XDP program MUST obey these rules: */

/* 1. Always bounds check before accessing data */
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
struct ethhdr *eth = data;

if (data + sizeof(*eth) > data_end)
    return XDP_DROP;  /* Out of bounds! */

/* 2. data_end is inclusive - points just past last byte */
int pkt_len = data_end - data;  /* Packet length */

/* 3. Pointers must stay within frame */
/* data >= data_hard_start */
/* data_end <= data_hard_start + frame_sz */

/* 4. Metadata must be before data */
/* data_meta <= data */
```

### RX Queue Information

```c
/* From include/net/xdp.h */
struct xdp_rxq_info {
    struct net_device *dev;  /* Network device */
    u32 queue_index;         /* Which RX queue (for multi-queue NICs) */
    u32 reg_state;           /* Registration state */
    struct xdp_mem_info mem; /* Memory model info */
} ____cacheline_aligned;

struct xdp_mem_info {
    u32 type;  /* Memory type: PAGE_SHARED, PAGE_ORDER0, PAGE_POOL, etc. */
    u32 id;    /* Memory region ID */
};
```

Memory types determine how buffers are managed:

- **XDP_MEM_TYPE_PAGE_SHARED**: Normal page allocator, pages may be shared
- **XDP_MEM_TYPE_PAGE_ORDER0**: Single pages (4096 bytes)
- **XDP_MEM_TYPE_PAGE_POOL**: Page pool for efficient recycling
- **XDP_MEM_TYPE_ZERO_COPY**: AF_XDP zero-copy UMEM

The memory type affects performance - page pools provide fastest allocation/free.

### XDP Program Context (`xdp_md`)

From the XDP program's perspective (userspace view):

```c
/* From include/uapi/linux/bpf.h */
struct xdp_md {
    __u32 data;           /* Offset to packet data */
    __u32 data_end;       /* Offset to end of data */
    __u32 data_meta;      /* Offset to metadata */
    __u32 ingress_ifindex; /* Input interface index */
    __u32 rx_queue_index; /* RX queue index */
    __u32 egress_ifindex; /* Output interface (for XDP_REDIRECT) */
};
```

The eBPF verifier translates these 32-bit offsets to actual kernel pointers when loading the program. XDP programs see `xdp_md`, but the kernel uses `xdp_buff` internally.

## XDP Program Invocation and eBPF Integration

### Attaching XDP Programs to Network Devices

XDP programs are eBPF programs of type `BPF_PROG_TYPE_XDP`. They're attached to network devices via netlink.

#### User Space: Loading and Attaching

```c
/* Typical flow using libbpf */
struct bpf_object *obj;
struct bpf_program *prog;
int prog_fd, ifindex;

/* 1. Load eBPF program from ELF file */
obj = bpf_object__open_file("xdp_prog.o", NULL);
bpf_object__load(obj);

/* 2. Get program file descriptor */
prog = bpf_object__find_program_by_name(obj, "xdp_filter");
prog_fd = bpf_program__fd(prog);

/* 3. Attach to network device */
ifindex = if_nametoindex("eth0");
bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
```

Or via `ip` command:
```bash
# Attach XDP program
ip link set dev eth0 xdp obj xdp_prog.o sec xdp

# Verify
ip link show dev eth0
# ... xdp/id:42 ... (program ID 42 attached)

# Detach
ip link set dev eth0 xdp off
```

#### Kernel Side: Program Attachment

```c
/* From net/core/dev.c */
int dev_change_xdp_fd(struct net_device *dev, struct netlink_ext_ack *extack,
                     int fd, int expected_fd, u32 flags)
{
    const struct net_device_ops *ops = dev->netdev_ops;
    struct bpf_prog *prog = NULL;
    bpf_op_t bpf_op;
    int err;
    
    /* Determine mode: native, offload, or generic */
    if (flags & XDP_FLAGS_HW_MODE)
        bpf_op = ops->ndo_bpf;  /* Hardware offload */
    else if (flags & XDP_FLAGS_SKB_MODE)
        bpf_op = generic_xdp_install;  /* Generic mode */
    else
        bpf_op = ops->ndo_bpf;  /* Native mode (driver) */
    
    /* Get eBPF program from file descriptor */
    if (fd >= 0) {
        prog = bpf_prog_get_type_dev(fd, BPF_PROG_TYPE_XDP,
                                     bpf_op == ops->ndo_bpf);
        if (IS_ERR(prog))
            return PTR_ERR(prog);
        
        /* Verify program is compatible with device features */
        if (prog->expected_attach_type == BPF_XDP_DEVMAP &&
            !dev->netdev_ops->ndo_xdp_xmit) {
            NL_SET_ERR_MSG(extack, "Native XDP not supported");
            bpf_prog_put(prog);
            return -EOPNOTSUPP;
        }
    }
    
    /* Install the program */
    err = dev_xdp_install(dev, bpf_op, extack, flags, prog);
    if (err < 0 && prog)
        bpf_prog_put(prog);
    
    return err;
}

static int dev_xdp_install(struct net_device *dev, bpf_op_t bpf_op,
                          struct netlink_ext_ack *extack, u32 flags,
                          struct bpf_prog *prog)
{
    struct netdev_bpf xdp;
    
    memset(&xdp, 0, sizeof(xdp));
    xdp.command = XDP_SETUP_PROG;
    xdp.extack = extack;
    xdp.flags = flags;
    xdp.prog = prog;
    
    /* Call into driver's ndo_bpf handler */
    return bpf_op(dev, &xdp);
}
```

#### Driver Side: Storing the Program

In ixgbe driver:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_xdp_setup(struct net_device *dev, struct bpf_prog *prog)
{
    struct ixgbe_adapter *adapter = netdev_priv(dev);
    struct bpf_prog *old_prog;
    int i;
    
    /* Verify ring parameters are XDP-compatible */
    if (adapter->ring_feature[RING_F_RSS].limit <= 1) {
        netdev_warn(dev, "XDP requires at least 2 RX queues\n");
        return -EINVAL;
    }
    
    old_prog = xchg(&adapter->xdp_prog, prog);
    
    /* Attach program to each RX ring */
    for (i = 0; i < adapter->num_rx_queues; i++) {
        struct ixgbe_ring *ring = adapter->rx_ring[i];
        
        WRITE_ONCE(ring->xdp_prog, prog);
        if (prog)
            ring->flags |= IXGBE_RING_FLAG_XDP;
        else
            ring->flags &= ~IXGBE_RING_FLAG_XDP;
    }
    
    /* If interface is running, configure TX rings for XDP_TX */
    if (netif_running(dev)) {
        if (prog)
            ixgbe_setup_xdp_tx_resources(adapter);
        else
            ixgbe_free_xdp_tx_resources(adapter);
    }
    
    if (old_prog)
        bpf_prog_put(old_prog);
    
    return 0;
}
```

Key points:
- Program stored in each RX ring (`ring->xdp_prog`)
- Protected by RCU (READ_ONCE in datapath)
- Driver validates compatibility (queue count, buffer sizes, etc.)
- Additional TX rings allocated for XDP_TX action

### Executing XDP Programs

#### The `bpf_prog_run_xdp()` Function

```c
/* From include/linux/filter.h */
static __always_inline u32 bpf_prog_run_xdp(const struct bpf_prog *prog,
                                           struct xdp_buff *xdp)
{
    u32 ret;
    
    /* Execute the eBPF program
     * BPF_PROG_RUN invokes the JIT-compiled code
     */
    ret = BPF_PROG_RUN(prog, xdp);
    
    /* Validate return value */
    if (unlikely(ret > XDP_REDIRECT))
        ret = XDP_ABORTED;
    
    return ret;
}

/* BPF_PROG_RUN macro expands to direct function call */
#define BPF_PROG_RUN(prog, ctx) \
    (*(prog)->bpf_func)(ctx, (prog)->insnsi)
```

The `bpf_func` pointer points to:
- **JIT-compiled native machine code** (x86-64, ARM64, etc.) - typical case
- **Interpreter** (`__bpf_prog_run`) - if JIT disabled or not supported

#### JIT Compilation on AMD64

When an XDP program is loaded, the kernel JIT compiler translates eBPF bytecode to native x86-64 instructions:

```
eBPF Bytecode          →          x86-64 Machine Code
─────────────────                 ───────────────────
r0 = *(u32 *)(r1 + 0)    →       mov rax, [rdi]
r0 >>= 8                 →       shr rax, 8
if r0 == 0x08 goto +2    →       cmp rax, 0x08
                                 je .L1
return XDP_DROP          →       mov eax, 1
                                 ret
.L1:                            .L1:
return XDP_PASS          →       xor eax, eax
                                 ret
```

JIT compilation is enabled by default on most architectures:

```bash
# Check JIT status
sysctl net.core.bpf_jit_enable
# net.core.bpf_jit_enable = 1

# View JIT-compiled code (requires root, debug kernel)
bpftool prog dump jited id 42
```

#### Execution Overhead

Typical CPU cycles per XDP program invocation:

- **Function call overhead**: ~5-10 cycles (bpf_prog_run_xdp call)
- **Program execution**: 10-100 cycles (depends on program complexity)
- **Verdict handling**: 10-50 cycles (depends on action)

Total: **~50-200 cycles** for simple programs (compare to ~3000-5000 for full network stack)

Example simple XDP program:

```c
/* Drop all TCP packets, pass everything else */
SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    
    /* Bounds check: Ethernet header */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    /* Check if IPv4 */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = (struct iphdr *)(eth + 1);
    
    /* Bounds check: IP header */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    /* Drop if TCP */
    if (ip->protocol == IPPROTO_TCP)
        return XDP_DROP;
    
    return XDP_PASS;
}
```

This compiles to ~20-30 x86-64 instructions, executing in ~50-80 CPU cycles.

## Execution Context and Task Context

### XDP Runs in Softirq Context

**Critical point**: XDP programs run in **softirq context**, specifically as part of the `NET_RX_SOFTIRQ` softirq handler. They do NOT run in process context.

#### Complete Call Stack

```
1. Hardware Interrupt (Hard IRQ)
   ixgbe NIC raises interrupt
        ↓
   CPU jumps to interrupt handler
        ↓
   ixgbe_msix_clean_rings()
        ↓
   Calls napi_schedule(&q_vector->napi)
        ↓
   Raises NET_RX_SOFTIRQ
        ↓
   Returns from hard IRQ
        (Hard IRQ handler complete: ~500-1000 cycles)

2. Softirq Processing
   Kernel checks pending softirqs
        ↓
   net_rx_action() [NET_RX_SOFTIRQ handler]
        ↓
   Calls napi->poll() for scheduled NAPI instances
        ↓
   ixgbe_poll(napi, budget)
        ↓
   ixgbe_clean_rx_irq(q_vector, rx_ring, budget)
        ↓
   For each received packet:
        READ_ONCE(rx_ring->xdp_prog)
        ↓
        ═══════════════════════════════════════════
        ║ bpf_prog_run_xdp(xdp_prog, &xdp)      ║
        ║                                         ║
        ║ XDP PROGRAM EXECUTES HERE               ║
        ║ - In softirq context                    ║
        ║ - Preemption disabled                   ║
        ║ - Cannot sleep                          ║
        ║ - Same CPU as interrupt                 ║
        ═══════════════════════════════════════════
        ↓
   Handle XDP verdict (DROP/PASS/TX/REDIRECT)
```

For detailed softirq mechanics, see [Linux Interrupt Handling](linux_interrupts.md).

### Softirq Context Constraints

Because XDP runs in softirq context, it has strict limitations:

#### Cannot Sleep

```c
/* These are FORBIDDEN in XDP programs: */
- mutex_lock()      /* Would sleep */
- msleep()          /* Would sleep */
- wait_event()      /* Would sleep */
- schedule()        /* Would sleep */
- Any blocking I/O
```

Only non-blocking BPF helper functions are allowed:
- `bpf_map_lookup_elem()` - Always non-blocking
- `bpf_xdp_adjust_head()` - Adjust packet pointers
- `bpf_xdp_adjust_meta()` - Adjust metadata
- `bpf_redirect_map()` - Redirect to another interface

#### Cannot Be Preempted

Softirqs run with preemption disabled:

```c
/* Simplified softirq execution */
local_bh_disable();     /* Disable bottom halves (softirqs) */
__local_bh_enable();    /* Runs pending softirqs with preempt disabled */

/* Inside softirq: */
preempt_disable();
while (pending_softirqs) {
    run_softirq_handler();  /* ← XDP runs here */
}
preempt_enable();
```

This means:
- XDP cannot be interrupted by normal kernel preemption
- XDP must complete quickly (bounded execution time)
- Long-running XDP programs hurt system responsiveness

Exception: If softirqs are deferred to `ksoftirqd` kernel thread, they CAN be preempted, but this only happens under extreme load.

#### No Direct User Space Access

```c
/* CANNOT do this in XDP: */
copy_to_user(user_ptr, data, len);   /* Not allowed! */
access_ok(user_ptr, len);             /* No user addresses */
```

XDP operates entirely on kernel memory (DMA buffers). For user space delivery, use AF_XDP sockets (covered below).

### CPU Core Affinity with RSS

Modern NICs use **RSS (Receive Side Scaling)** to distribute packets across multiple RX queues, each bound to a specific CPU core.

#### RSS Configuration

```
NIC with 4 RX Queues:

        ┌─────────────────────┐
        │       NIC           │
        │                     │
        │  [RSS Hash Logic]   │  ← Hashes packet (src IP, dst IP, ports)
        │         ↓           │
        │   ┌─────┴─────┐     │
        │   │ Flow      │     │
        │   │ Director  │     │
        │   └─┬─┬─┬─┬───┘     │
        └─────│─│─│─│─────────┘
              │ │ │ │
        ┌─────┘ │ │ └─────┐
        │   ┌───┘ └───┐   │
        │   │         │   │
        ↓   ↓         ↓   ↓
      Queue0 Queue1 Queue2 Queue3
        │    │       │     │
        │    │       │     │ IRQ Affinity
        ↓    ↓       ↓     ↓
      CPU 0  CPU 1  CPU 2  CPU 3
```

Set up RSS affinity:
```bash
# View current IRQ CPU affinity
cat /proc/interrupts | grep eth0

# Set queue 0 to CPU 0
echo 1 > /proc/irq/125/smp_affinity  # Bitmask: 0001 = CPU 0

# Set queue 1 to CPU 1
echo 2 > /proc/irq/126/smp_affinity  # Bitmask: 0010 = CPU 1
```

#### XDP Execution Follows Interrupt CPU

When a packet arrives on Queue N:
1. NIC raises interrupt for Queue N
2. Interrupt delivered to CPU N (based on IRQ affinity)
3. Hard IRQ handler runs on CPU N
4. Softirq scheduled on CPU N
5. **XDP program runs on CPU N**

```
Example: Packet arrives on Queue 2

Queue 2 → IRQ to CPU 2 → Softirq on CPU 2 → XDP runs on CPU 2
```

This has important performance implications:

**Benefits:**
- **Cache locality**: Packet data in CPU 2's cache
- **No cross-CPU traffic**: No need to touch other CPUs
- **Parallelism**: Each CPU processes its queue independently

**Considerations:**
- **Load distribution**: RSS hash must distribute flows evenly
- **CPU pinning**: Keep related processing on same CPU for cache efficiency
- **NUMA awareness**: Prefer CPU on same NUMA node as NIC

Check RSS hash configuration:
```bash
# View RSS hash function
ethtool -x eth0

# Configure RSS hash (e.g., hash on src/dst IP + ports)
ethtool -X eth0 hfunc toeplitz equal 4
```

### `current` Task in Softirq Context

Even though XDP runs in softirq context, the `current` macro still points to the task that was running when the softirq was invoked.

```c
/* In softirq context: */
struct task_struct *task = current;
/* task points to whatever process was running when interrupt arrived
 * (could be ANY process - application, kernel thread, idle task, etc.)
 */
```

**Important**: XDP must NOT rely on `current` for anything meaningful. The interrupted task is arbitrary and unrelated to packet processing.

### Softirq Execution Timing

Softirqs can execute at several points:

1. **Return from hardirq**: Most common case
```c
irq_exit() {
    invoke_softirq();  /* Check pending softirqs */
}
```

2. **Return from system call**:
```c
syscall_exit_to_user_mode() {
    local_bh_enable();  /* Re-enable softirqs, run if pending */
}
```

3. **`ksoftirqd` kernel thread**: If softirqs are backlogged
```c
/* Per-CPU kernel thread runs pending softirqs */
while (1) {
    wait_for_softirqs();
    run_ksoftirqd();  /* XDP could run here if deferred */
}
```

In high-performance scenarios, XDP almost always runs in case (1) - immediately after the hardirq that scheduled it.

## XDP Verdicts and Packet Flow

XDP programs must return one of five verdict codes, each directing different packet handling.

### XDP Return Values

```c
/* From include/uapi/linux/bpf.h */
enum xdp_action {
    XDP_ABORTED = 0,   /* Error occurred, abort and trace */
    XDP_DROP,          /* Drop packet immediately */
    XDP_PASS,          /* Pass packet to network stack */
    XDP_TX,            /* Transmit packet out same interface */
    XDP_REDIRECT,      /* Redirect to another interface or AF_XDP socket */
};
```

### XDP_DROP: Early Packet Drop

**Purpose**: Drop unwanted packets with minimal CPU overhead.

**Use cases**: DDoS mitigation, firewall, invalid packet filtering

**Implementation in ixgbe**:

```c
case XDP_DROP:
    /* No SKB allocation, no further processing */
    ixgbe_reuse_rx_buffer(rx_ring, rx_buffer);
    
    /* Update statistics */
    rx_ring->xdp_stats.drops++;
    
    /* Buffer returned to ring, ready for next packet */
    total_rx_packets++;
    ixgbe_inc_rx_ntc(rx_ring);
    continue;  /* Next packet */

static void ixgbe_reuse_rx_buffer(struct ixgbe_ring *rx_ring,
                                  struct ixgbe_rx_buffer *old_buf)
{
    struct ixgbe_rx_buffer *new_buf;
    u16 nta = rx_ring->next_to_alloc;
    
    new_buf = &rx_ring->rx_buffer_info[nta];
    
    /* Copy buffer info */
    *new_buf = *old_buf;
    
    /* Increment page count */
    page_ref_inc(old_buf->page);
    
    /* Update next_to_alloc */
    nta++;
    rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;
}
```

**Cost**: ~50-100 CPU cycles total per packet (compare to ~3000+ for iptables DROP)

**Example XDP program**:

```c
/* Drop all packets from specific IP address */
SEC("xdp")
int xdp_drop_ip(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 blocked_ip = 0x0a000001;  /* 10.0.0.1 */
    
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    /* Drop if from blocked IP */
    if (ip->saddr == htonl(blocked_ip))
        return XDP_DROP;
    
    return XDP_PASS;
}
```

### XDP_PASS: Normal Stack Processing

**Purpose**: Pass packet to the normal Linux network stack.

**Use cases**: Selective processing (drop some, pass others), monitoring, classification

**Implementation in ixgbe**:

```c
case XDP_PASS:
    /* Allocate SKB and build it from XDP buffer */
    skb = ixgbe_construct_skb(rx_ring, rx_buffer, &xdp, rx_desc);
    if (!skb) {
        /* Allocation failed */
        rx_ring->rx_stats.alloc_rx_buff_failed++;
        break;
    }
    
    /* Continue normal processing */
    ixgbe_process_skb_fields(rx_ring, rx_desc, skb);
    
    /* Hand off to GRO */
    napi_gro_receive(&q_vector->napi, skb);

/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static struct sk_buff *ixgbe_construct_skb(struct ixgbe_ring *rx_ring,
                                           struct ixgbe_rx_buffer *rx_buffer,
                                           struct xdp_buff *xdp,
                                           union ixgbe_adv_rx_desc *rx_desc)
{
    unsigned int size = xdp->data_end - xdp->data;
    unsigned int headroom = xdp->data - xdp->data_hard_start;
    struct sk_buff *skb;
    
    /* Allocate SKB with space for data */
    skb = napi_alloc_skb(&rx_ring->q_vector->napi,
                        IXGBE_RX_HDR_SIZE);
    if (unlikely(!skb))
        return NULL;
    
    /* If packet is small, copy into SKB linear space */
    if (size <= IXGBE_RX_HDR_SIZE) {
        memcpy(__skb_put(skb, size), xdp->data, size);
        ixgbe_reuse_rx_buffer(rx_ring, rx_buffer);
        return skb;
    }
    
    /* For larger packets, use page frags (avoid copy) */
    skb_reserve(skb, headroom);
    skb_add_rx_frag(skb, 0, rx_buffer->page,
                   xdp->data - page_address(rx_buffer->page),
                   size, truesize);
    
    return skb;
}
```

After XDP_PASS, the packet continues through the normal path:
```
SKB → IP layer (ip_rcv) → TCP/UDP → Socket → Application
```

See [ip.md](ip.md) for IP layer details.

### XDP_TX: Packet Reflection

**Purpose**: Transmit packet back out the same interface it arrived on.

**Use cases**: Packet reflection, simple responders (e.g., ICMP echo without full stack)

**Implementation in ixgbe**:

```c
case XDP_TX:
    result = ixgbe_xdp_xmit_back(adapter, &xdp);
    
    if (result == IXGBE_XDP_CONSUMED) {
        /* Successfully queued for TX */
        rx_ring->xdp_stats.tx++;
        ixgbe_inc_rx_ntc(rx_ring);
        continue;
    }
    /* Fall through to error handling */

static int ixgbe_xdp_xmit_back(struct ixgbe_adapter *adapter,
                              struct xdp_buff *xdp)
{
    struct ixgbe_ring *tx_ring;
    int cpu = smp_processor_id();
    
    /* Get per-CPU XDP TX ring */
    tx_ring = adapter->xdp_ring[cpu];
    
    /* Queue packet for transmission */
    return ixgbe_xmit_xdp_ring(tx_ring, xdp);
}

static int ixgbe_xmit_xdp_ring(struct ixgbe_ring *tx_ring,
                              struct xdp_buff *xdp)
{
    struct ixgbe_tx_buffer *tx_buffer;
    union ixgbe_adv_tx_desc *tx_desc;
    u32 len = xdp->data_end - xdp->data;
    u16 i = tx_ring->next_to_use;
    dma_addr_t dma;
    
    /* Check if space available in TX ring */
    if (ixgbe_desc_unused(tx_ring) < 1)
        return IXGBE_XDP_CONSUMED;  /* Ring full, drop */
    
    /* Map packet data for DMA */
    dma = dma_map_single(tx_ring->dev, xdp->data, len, DMA_TO_DEVICE);
    if (dma_mapping_error(tx_ring->dev, dma))
        return IXGBE_XDP_CONSUMED;
    
    /* Fill TX descriptor */
    tx_buffer = &tx_ring->tx_buffer_info[i];
    tx_buffer->bytecount = len;
    tx_buffer->gso_segs = 1;
    
    tx_desc = IXGBE_TX_DESC(tx_ring, i);
    tx_desc->read.buffer_addr = cpu_to_le64(dma);
    tx_desc->read.cmd_type_len = cpu_to_le32(
        IXGBE_TXD_CMD_EOP | IXGBE_TXD_CMD_RS | len);
    
    /* Update next_to_use */
    i++;
    tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;
    
    /* Ring doorbell (tell NIC to transmit) */
    writel(tx_ring->next_to_use, tx_ring->tail);
    
    return IXGBE_XDP_TX;
}
```

**Key points**:
- Separate TX ring per CPU for XDP_TX (avoids locking)
- Packet data stays in same DMA buffer (zero-copy transmit)
- Very fast: ~100-200 cycles for packet reflection

**Example**: ICMP echo responder

```c
SEC("xdp")
int xdp_icmp_echo(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct icmphdr *icmp;
    __u32 tmp_ip;
    __u8 tmp_mac[6];
    
    /* Parse headers */
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;
    
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP) return XDP_PASS;
    
    icmp = (struct icmphdr *)(ip + 1);
    if ((void *)(icmp + 1) > data_end) return XDP_PASS;
    if (icmp->type != ICMP_ECHO) return XDP_PASS;
    
    /* Swap MAC addresses */
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);
    
    /* Swap IP addresses */
    tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    
    /* Change ICMP type to echo reply */
    icmp->type = ICMP_ECHOREPLY;
    
    /* Recalculate checksum */
    icmp->checksum += htons(0x0100);  /* Simple increment works for this case */
    
    /* Transmit back out same interface */
    return XDP_TX;
}
```

This implements a ping responder in ~50-100 CPU cycles!

### XDP_REDIRECT: Forward to Another Interface

**Purpose**: Fast packet forwarding to another network interface or AF_XDP socket.

**Use cases**: Load balancing, routing, AF_XDP delivery

**Implementation**:

```c
case XDP_REDIRECT:
    err = xdp_do_redirect(adapter->netdev, &xdp, xdp_prog);
    if (!err) {
        /* Successfully redirected */
        rx_ring->xdp_stats.redirect++;
        ixgbe_inc_rx_ntc(rx_ring);
        continue;
    }
    /* Fall through to error handling */

/* From net/core/filter.c */
int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp,
                   struct bpf_prog *xdp_prog)
{
    struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
    enum bpf_map_type map_type = ri->map_type;
    u32 index = ri->tgt_index;
    void *fwd;
    
    /* Redirect target set by bpf_redirect_map() helper in XDP program */
    
    if (map_type == BPF_MAP_TYPE_DEVMAP ||
        map_type == BPF_MAP_TYPE_DEVMAP_HASH) {
        /* Redirect to another network device */
        fwd = __dev_map_lookup_elem(ri->map, index);
        if (unlikely(!fwd))
            return -EINVAL;
        
        return dev_map_enqueue(fwd, xdp, dev);
        
    } else if (map_type == BPF_MAP_TYPE_XSKMAP) {
        /* Redirect to AF_XDP socket */
        return __xsk_map_redirect(ri->map, xdp, __xsk_map_lookup_elem);
        
    } else if (map_type == BPF_MAP_TYPE_CPUMAP) {
        /* Redirect to remote CPU */
        return cpu_map_enqueue(ri->map, xdp, dev);
    }
    
    return -EBADRQC;
}
```

**Example**: Redirect to another interface

```c
/* BPF map: device index → net_device */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} tx_port SEC(".maps");

SEC("xdp")
int xdp_redirect_forward(struct xdp_md *ctx)
{
    __u32 out_ifindex = 3;  /* Forward to interface index 3 */
    
    /* Redirect packet to another interface */
    return bpf_redirect_map(&tx_port, out_ifindex, 0);
}
```

XDP_REDIRECT for AF_XDP is covered in detail below.

### XDP_ABORTED: Error Path

**Purpose**: Indicate an error occurred during XDP processing.

**Use cases**: Internal errors, debugging

```c
case XDP_ABORTED:
    /* Trace the error */
    trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
    
    /* Fall through - treat as DROP */
    ixgbe_reuse_rx_buffer(rx_ring, rx_buffer);
    break;
```

XDP_ABORTED triggers a tracepoint, useful for debugging:

```bash
# Monitor XDP exceptions
trace-cmd record -e xdp:xdp_exception
```

Most XDP programs should never return XDP_ABORTED - use XDP_DROP instead.

## AF_XDP Sockets: Zero-Copy to User Space

**AF_XDP (Address Family XDP)** is a socket type that enables ultra-fast packet delivery to user space applications with zero-copy semantics.

### What Problem Does AF_XDP Solve?

Traditional packet capture (e.g., AF_PACKET/libpcap):

```
NIC → DMA → Driver → SKB → AF_PACKET socket → Copy to user → Application
                     ↑                         ↑
                 Overhead 1              Overhead 2 (copy!)
```

Cost: ~3000-5000 CPU cycles, packet data copied multiple times

AF_XDP path:

```
NIC → DMA to UMEM → XDP_REDIRECT → Descriptor to RX Ring → Application reads UMEM
           ↑                                                       ↑
      Zero copies! Packet data stays in shared memory (UMEM)
```

Cost: ~500-1000 CPU cycles, zero packet data copies

### AF_XDP Architecture

```
Kernel Space:                         User Space:
                                     
┌──────────────────┐                 ┌─────────────────────┐
│ NIC RX Ring      │                 │   Application       │
│  [descriptors]   │                 │                     │
└────────┬─────────┘                 │   AF_XDP Socket     │
         │ DMA                       │   (File Descriptor) │
         ↓                           │                     │
┌──────────────────┐                 │   ┌─────────────┐   │
│ UMEM (Shared)    │←────mmap()──────┼───│ UMEM        │   │
│ ┌──────────────┐ │                 │   │ (User View) │   │
│ │ Frame 0      │ │                 │   └─────────────┘   │
│ ├──────────────┤ │                 │                     │
│ │ Frame 1      │ │                 │   Ring Buffers:     │
│ ├──────────────┤ │                 │   ┌─────────────┐   │
│ │ Frame 2      │ │←────mmap()──────┼───│ RX Ring     │   │
│ ├──────────────┤ │                 │   ├─────────────┤   │
│ │ ...          │ │                 │   │ TX Ring     │   │
│ └──────────────┘ │                 │   ├─────────────┤   │
└──────────────────┘                 │   │ Fill Ring   │   │
         ↑                           │   ├─────────────┤   │
         │                           │   │ Compl Ring  │   │
┌────────┴─────────┐                 │   └─────────────┘   │
│ XDP Program      │                 └─────────────────────┘
│                  │
│ XDP_REDIRECT ────┼──→ Add descriptor to RX Ring
│                  │    (descriptor points to frame in UMEM)
└──────────────────┘
```

Key components:

1. **UMEM**: Shared memory region, mapped into both kernel and user space
2. **Four ring buffers**: Fill Queue, RX Queue, TX Queue, Completion Queue
3. **Descriptors**: Point to frames within UMEM
4. **Zero-copy**: Packet data never copied, stays in UMEM

### UMEM: User Memory Region

```c
/* From include/net/xdp_sock.h */
struct xdp_umem {
    void *addrs;              /* Kernel mapping of UMEM */
    u64 size;                 /* Total UMEM size */
    u32 headroom;             /* Headroom per frame (for headers) */
    u32 chunk_size;           /* Frame size (e.g., 2048 bytes) */
    u32 chunks;               /* Number of frames */
    u32 npgs;                 /* Number of pages */
    struct page **pgs;        /* Page array */
    int id;                   /* UMEM ID */
    bool zc;                  /* Zero-copy enabled? */
    struct xdp_umem_fq_reuse *fq_reuse;  /* Frame reuse optimization */
    struct xsk_queue *fq;     /* Fill Queue */
    struct xsk_queue *cq;     /* Completion Queue */
    /* ... */
};
```

UMEM setup from user space:

```c
#include <linux/if_xdp.h>
#include <bpf/xsk.h>

/* 1. Create AF_XDP socket */
int xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
if (xsk_fd < 0) {
    perror("socket");
    exit(1);
}

/* 2. Allocate UMEM (e.g., 4MB = 2048 frames of 2048 bytes each) */
#define UMEM_SIZE (4 * 1024 * 1024)
#define FRAME_SIZE 2048
#define NUM_FRAMES (UMEM_SIZE / FRAME_SIZE)

void *umem_area = mmap(NULL, UMEM_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                      -1, 0);
if (umem_area == MAP_FAILED) {
    /* Fallback without huge pages */
    umem_area = mmap(NULL, UMEM_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);
}

/* 3. Register UMEM with kernel */
struct xdp_umem_reg umem_reg = {
    .addr = (__u64)umem_area,
    .len = UMEM_SIZE,
    .chunk_size = FRAME_SIZE,
    .headroom = 0,  /* Or XDP_PACKET_HEADROOM (256 bytes) */
    .flags = 0
};

if (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG,
              &umem_reg, sizeof(umem_reg)) < 0) {
    perror("XDP_UMEM_REG");
    exit(1);
}

/* 4. Create ring buffers */
int ring_size = 2048;  /* Number of descriptors */

setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
          &ring_size, sizeof(ring_size));
setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
          &ring_size, sizeof(ring_size));
setsockopt(xsk_fd, SOL_XDP, XDP_RX_RING,
          &ring_size, sizeof(ring_size));
setsockopt(xsk_fd, SOL_XDP, XDP_TX_RING,
          &ring_size, sizeof(ring_size));

/* 5. mmap() ring buffers */
struct xdp_mmap_offsets offsets;
socklen_t optlen = sizeof(offsets);
getsockopt(xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen);

/* Fill Queue */
void *fq_map = mmap(NULL, offsets.fr.desc + ring_size * sizeof(__u64),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   xsk_fd, XDP_UMEM_PGOFF_FILL_RING);

/* RX Queue */
void *rx_map = mmap(NULL, offsets.rx.desc + ring_size * sizeof(struct xdp_desc),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   xsk_fd, XDP_PGOFF_RX_RING);

/* TX Queue */
void *tx_map = mmap(NULL, offsets.tx.desc + ring_size * sizeof(struct xdp_desc),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   xsk_fd, XDP_PGOFF_TX_RING);

/* Completion Queue */
void *cq_map = mmap(NULL, offsets.cr.desc + ring_size * sizeof(__u64),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING);

/* 6. Bind socket to interface and queue */
struct sockaddr_xdp sxdp = {
    .sxdp_family = AF_XDP,
    .sxdp_ifindex = if_nametoindex("eth0"),
    .sxdp_queue_id = 0,  /* Bind to RX queue 0 */
    .sxdp_flags = XDP_ZEROCOPY  /* Request zero-copy mode */
};

if (bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
    perror("bind");
    /* May fallback to copy mode if zero-copy not supported */
}
```

### The Four Ring Buffers

AF_XDP uses four lock-free single-producer-single-consumer (SPSC) ring buffers:

#### 1. Fill Queue (FQ): App → Kernel

```
Application provides free frame descriptors to kernel

Producer: Application
Consumer: Kernel (XDP)

┌─────────────────────────────────────┐
│  Fill Queue (FQ)                    │
│                                     │
│  [producer idx]  [consumer idx]     │
│       ↓               ↑             │
│  ┌───────┬───────┬───────┬───────┐  │
│  │ 0x000 │ 0x800 │0x1000 │       │  │ ← Frame offsets in UMEM
│  └───────┴───────┴───────┴───────┘  │
│     ↑       ↑       ↑                │
│     │       │       │                │
│  App fills these with free frame    │
│  offsets. Kernel consumes them      │
│  to store received packets.         │
└─────────────────────────────────────┘
```

Application code:

```c
/* Populate Fill Queue with free frames */
for (int i = 0; i < NUM_FRAMES / 2; i++) {
    __u64 frame_addr = i * FRAME_SIZE;
    *xsk_ring_prod__fill_addr(&fq, i) = frame_addr;
}
xsk_ring_prod__submit(&fq, NUM_FRAMES / 2);
```

#### 2. RX Queue: Kernel → App

```
Kernel provides descriptors of received packets

Producer: Kernel (XDP)
Consumer: Application

┌──────────────────────────────────────────┐
│  RX Queue                                │
│                                          │
│  [producer idx]  [consumer idx]          │
│       ↓               ↑                  │
│  ┌─────────────┬─────────────┬────────┐  │
│  │addr:0x1000  │addr:0x2000  │        │  │
│  │len: 64      │len: 128     │        │  │
│  └─────────────┴─────────────┴────────┘  │
│       ↑             ↑                    │
│       │             │                    │
│  Kernel fills with received packets.    │
│  App consumes and processes them.       │
└──────────────────────────────────────────┘
```

Descriptor structure:

```c
/* From include/uapi/linux/if_xdp.h */
struct xdp_desc {
    __u64 addr;     /* Offset into UMEM where packet is */
    __u32 len;      /* Packet length */
    __u32 options;  /* Reserved */
};
```

Application code:

```c
/* Poll for received packets */
unsigned int rcvd = xsk_ring_cons__peek(&rx, &idx, BATCH_SIZE);

for (unsigned int i = 0; i < rcvd; i++) {
    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx, idx++);
    
    /* Access packet data in UMEM (zero-copy!) */
    void *pkt_data = xsk_umem__get_data(umem_area, desc->addr);
    unsigned int pkt_len = desc->len;
    
    /* Process packet */
    process_packet(pkt_data, pkt_len);
    
    /* Return frame to Fill Queue for reuse */
    *xsk_ring_prod__fill_addr(&fq, fq_idx++) = desc->addr;
}

/* Release processed descriptors */
xsk_ring_cons__release(&rx, rcvd);

/* Submit frames back to Fill Queue */
xsk_ring_prod__submit(&fq, rcvd);
```

#### 3. TX Queue: App → Kernel

```
Application provides packets to transmit

Producer: Application
Consumer: Kernel

┌──────────────────────────────────────────┐
│  TX Queue                                │
│                                          │
│  [producer idx]  [consumer idx]          │
│       ↓               ↑                  │
│  ┌─────────────┬─────────────┬────────┐  │
│  │addr:0x4000  │addr:0x5000  │        │  │
│  │len: 128     │len: 256     │        │  │
│  └─────────────┴─────────────┴────────┘  │
│       ↑             ↑                    │
│       │             │                    │
│  App fills with packets to send.        │
│  Kernel consumes and transmits them.    │
└──────────────────────────────────────────┘
```

Application code:

```c
/* Get frame from Completion Queue (recycled TX frames) */
unsigned int compl = xsk_ring_cons__peek(&cq, &idx, 1);
if (compl > 0) {
    xsk_ring_cons__release(&cq, compl);
}

/* Prepare packet in UMEM */
__u64 frame_addr = 0x4000;
void *pkt = xsk_umem__get_data(umem_area, frame_addr);
build_packet(pkt, &pkt_len);  /* Application builds packet */

/* Submit to TX Queue */
struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tx, 0);
tx_desc->addr = frame_addr;
tx_desc->len = pkt_len;
xsk_ring_prod__submit(&tx, 1);

/* Kick kernel to transmit */
sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
```

#### 4. Completion Queue (CQ): Kernel → App

```
Kernel returns frame descriptors after transmission

Producer: Kernel
Consumer: Application

┌─────────────────────────────────────┐
│  Completion Queue (CQ)              │
│                                     │
│  [producer idx]  [consumer idx]     │
│       ↓               ↑             │
│  ┌───────┬───────┬───────┬───────┐  │
│  │0x4000 │0x5000 │       │       │  │ ← Frame offsets now free
│  └───────┴───────┴───────┴───────┘  │
│     ↑       ↑                       │
│     │       │                       │
│  Kernel returns transmitted frames. │
│  App can reuse them.                │
└─────────────────────────────────────┘
```

### Zero-Copy vs Copy Mode

#### Zero-Copy Mode (Best Performance)

Requirements:
- Driver must support AF_XDP zero-copy (i40e, ixgbe, ice, mlx5)
- UMEM must be suitable for NIC DMA

```
NIC → DMA directly to UMEM frame → XDP sees data in UMEM → Descriptor to RX Ring
                                                                ↓
                                                          App reads UMEM
```

**Zero memory copies!** Packet data written once by NIC DMA, read directly by application.

#### Copy Mode (Fallback)

When zero-copy not available:

```
NIC → DMA to driver buffer → memcpy to UMEM frame → Descriptor to RX Ring
                                  ↑                        ↓
                             One copy                 App reads UMEM
```

Still faster than traditional socket (only one copy), but not true zero-copy.

Check mode:

```c
/* After bind(), check if zero-copy succeeded */
int optlen = sizeof(int);
int copy_mode;
getsockopt(xsk_fd, SOL_XDP, XDP_OPTIONS, &copy_mode, &optlen);

if (copy_mode & XDP_OPTIONS_ZEROCOPY)
    printf("Zero-copy mode enabled\n");
else
    printf("Copy mode (fallback)\n");
```

## AF_XDP Packet Path: Complete Zero-Copy Flow

### Zero-Copy RX Path (Detailed)

The complete path from NIC to application with zero memory copies:

#### Step 1: Application Provides Free Frames

```c
/* Application startup: populate Fill Queue */
for (int i = 0; i < NUM_FRAMES; i++) {
    __u64 frame_offset = i * FRAME_SIZE;
    *xsk_ring_prod__fill_addr(&fq, i) = frame_offset;
}
xsk_ring_prod__submit(&fq, NUM_FRAMES);

/* Application is now waiting for packets */
```

Fill Queue now contains frame offsets like: 0x0000, 0x0800, 0x1000, 0x1800, ...

#### Step 2: NIC Receives Packet

```
Packet arrives at NIC
    ↓
NIC raises interrupt
    ↓
CPU receives interrupt (based on RSS affinity)
    ↓
Hard IRQ handler: ixgbe_msix_clean_rings()
    ↓
Schedules NAPI (raises NET_RX_SOFTIRQ)
```

#### Step 3: NAPI Poll and XDP Execution

```c
/* In softirq context on the RSS-selected CPU */

/* From drivers/net/ethernet/intel/i40e/i40e_xsk.c
 * (i40e has better AF_XDP support than ixgbe)
 */
int i40e_clean_rx_irq_zc(struct i40e_ring *rx_ring, int budget)
{
    struct xdp_buff *xdp = &rx_ring->xdp;
    struct xdp_umem *umem = rx_ring->xsk_umem;
    struct bpf_prog *xdp_prog = READ_ONCE(rx_ring->xdp_prog);
    u16 cleaned_count = 0;
    
    while (likely(total_rx_packets < budget)) {
        union i40e_rx_desc *rx_desc;
        unsigned int size;
        u64 handle;
        
        /* Check if descriptor is ready */
        rx_desc = I40E_RX_DESC(rx_ring, ntc);
        if (!i40e_test_staterr(rx_desc, I40E_RXD_DD))
            break;
        
        /* Get handle to UMEM frame
         * In zero-copy mode, NIC DMA'd directly to UMEM!
         */
        handle = rx_desc->wb.qword1.handle;
        
        /* Get frame from UMEM */
        xdp->data = xsk_buff_raw_get_data(umem, handle);
        xdp->data_end = xdp->data + size;
        xdp->data_meta = xdp->data;
        xdp->data_hard_start = xdp->data - headroom;
        xdp->handle = handle;
        
        /* Run XDP program (if attached) */
        if (xdp_prog) {
            u32 act = bpf_prog_run_xdp(xdp_prog, xdp);
            
            switch (act) {
            case XDP_PASS:
                /* Pass to network stack (build SKB) */
                break;
                
            case XDP_DROP:
                /* Drop packet */
                xsk_buff_free(xdp);
                continue;
                
            case XDP_REDIRECT:
                /* Check if redirecting to AF_XDP socket */
                if (xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog) == 0) {
                    /* Successfully redirected to AF_XDP! */
                    total_rx_packets++;
                    continue;
                }
                /* Redirect failed, free buffer */
                xsk_buff_free(xdp);
                continue;
                
            default:
                bpf_warn_invalid_xdp_action(act);
                /* fall through */
            case XDP_ABORTED:
                xsk_buff_free(xdp);
                continue;
            }
        }
        
        /* If we get here, XDP_PASS: build SKB */
        /* ... SKB allocation code ... */
    }
    
    /* Refill RX ring with frames from Fill Queue */
    if (cleaned_count)
        i40e_alloc_rx_buffers_zc(rx_ring, cleaned_count);
    
    return total_rx_packets;
}
```

#### Step 4: XDP_REDIRECT to AF_XDP Socket

```c
/* From net/xdp/xsk.c */
int __xsk_map_redirect(struct bpf_map *map, struct xdp_buff *xdp,
                      struct xdp_sock *xs)
{
    struct xsk_buff_pool *pool = xs->pool;
    u64 addr;
    int err;
    
    /* Get frame address in UMEM */
    addr = xdp->data - pool->addrs;
    
    /* Add descriptor to RX Ring */
    err = xsk_rcv(xs, xdp);
    if (err)
        return err;
    
    /* Get new frame from Fill Queue for next packet */
    if (xsk_buff_pool_peek(pool))
        xsk_buff_alloc(xs->rx_ring);
    
    return 0;
}

static int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
    struct xsk_buff_pool *pool = xs->pool;
    u64 addr = xdp->data - pool->addrs;
    u32 len = xdp->data_end - xdp->data;
    struct xdp_desc desc;
    
    /* Check if space in RX Ring */
    if (xskq_prod_reserve(xs->rx)) {
        xs->rx_dropped++;
        return -ENOSPC;
    }
    
    /* Fill descriptor */
    desc.addr = addr;
    desc.len = len;
    desc.options = 0;
    
    /* Add to RX Ring (lock-free, single producer) */
    xskq_prod_submit(xs->rx, &desc);
    
    /* Wake up application if needed */
    if (xs->dev->flags & IFF_UP)
        xs->sk.sk_data_ready(&xs->sk);
    
    return 0;
}
```

#### Step 5: Application Polls and Processes

```c
/* Application main loop */
while (running) {
    unsigned int rcvd, i;
    
    /* Poll RX Ring (non-blocking check) */
    rcvd = xsk_ring_cons__peek(&rx, &idx, BATCH_SIZE);
    
    if (rcvd > 0) {
        /* Process each packet */
        for (i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx, idx++);
            
            /* ═════════════════════════════════════════════
             * ZERO-COPY ACCESS TO PACKET DATA!
             * Packet still in UMEM, written once by NIC DMA
             * ═════════════════════════════════════════════
             */
            void *pkt_data = xsk_umem__get_data(umem_area, desc->addr);
            unsigned int pkt_len = desc->len;
            
            /* Process packet (application-specific logic) */
            struct ethhdr *eth = pkt_data;
            printf("Received packet: proto=0x%04x, len=%u\n",
                   ntohs(eth->h_proto), pkt_len);
            
            /* Return frame to Fill Queue (recycle) */
            *xsk_ring_prod__fill_addr(&fq, fq_idx++) = desc->addr;
        }
        
        /* Release processed descriptors from RX Ring */
        xsk_ring_cons__release(&rx, rcvd);
        
        /* Submit recycled frames back to Fill Queue */
        xsk_ring_prod__submit(&fq, rcvd);
    }
    
    /* Optional: block waiting for more packets */
    if (rcvd == 0) {
        struct pollfd pfd = {
            .fd = xsk_socket__fd(xsk),
            .events = POLLIN,
        };
        poll(&pfd, 1, 1000);  /* Wait up to 1 second */
    }
}
```

### The Complete Zero-Copy Flow Diagram

```
Timeline of Zero-Copy RX:

T0: Setup
    App: Allocate UMEM, create rings, bind socket
    App: Populate Fill Queue with frame offsets
         Fill Queue: [0x0000, 0x0800, 0x1000, ...]
    
T1: Packet Arrives
    NIC: Packet arrives
    NIC: Consumes frame offset from Fill Queue → 0x0800
    NIC: DMA packet data directly to UMEM at offset 0x0800
         ┌─────────────────────────┐
         │ UMEM                    │
         │ ...                     │
         │ 0x0800: [PACKET DATA]   │ ← Written by NIC DMA (only write!)
         │ ...                     │
         └─────────────────────────┘
    NIC: Raises interrupt
    
T2: Interrupt Processing (CPU X)
    Hardirq: ixgbe_msix_handler()
    Hardirq: napi_schedule()
    
T3: Softirq Processing (CPU X, same CPU)
    Softirq: net_rx_action()
    Softirq: i40e_clean_rx_irq_zc()
    Softirq: XDP program runs
             xdp.data → points to UMEM offset 0x0800 (no copy!)
             XDP program examines packet in place
             Returns XDP_REDIRECT
    Softirq: xdp_do_redirect()
             __xsk_map_redirect()
             Add descriptor to RX Ring:
                 RX Ring: [{addr: 0x0800, len: 64}]
    Softirq: Wake up application if blocked
    
T4: Application Processing (Userspace)
    App: xsk_ring_cons__peek() → finds descriptor
    App: Read descriptor: addr=0x0800, len=64
    App: Access packet: umem_area + 0x0800
         ┌─────────────────────────┐
         │ UMEM                    │
         │ ...                     │
         │ 0x0800: [PACKET DATA]   │ ← Read by application (no copy!)
         │ ...                     │
         └─────────────────────────┘
    App: Process packet (parse headers, etc.)
    App: Return frame to Fill Queue: [0x0800]
    App: xsk_ring_cons__release()

Packet data flow: NIC DMA → UMEM (write once) → XDP reads → App reads
                  ZERO COPIES FROM NIC TO APPLICATION!
```

### TX Path: Zero-Copy Transmission

The transmission path is also zero-copy:

```c
/* Application builds packet in UMEM */
__u64 frame_addr = get_free_frame();  /* From Completion Queue */
void *pkt = xsk_umem__get_data(umem_area, frame_addr);

/* Build packet directly in UMEM */
struct ethhdr *eth = pkt;
memcpy(eth->h_dest, dst_mac, ETH_ALEN);
memcpy(eth->h_source, src_mac, ETH_ALEN);
eth->h_proto = htons(ETH_P_IP);
/* ... build rest of packet ... */
unsigned int pkt_len = build_packet(pkt);

/* Submit to TX Ring */
struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tx, 0);
tx_desc->addr = frame_addr;
tx_desc->len = pkt_len;
xsk_ring_prod__submit(&tx, 1);

/* Kick kernel to transmit */
sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

/* Kernel TX path (in syscall or triggered by sendto): */
/* NIC reads directly from UMEM at frame_addr (zero-copy DMA) */
/* After transmission, frame returned to Completion Queue */
```

Complete TX flow:

```
1. App builds packet in UMEM frame
   ┌─────────────────────────┐
   │ UMEM                    │
   │ 0x4000: [PACKET DATA]   │ ← Built by application
   └─────────────────────────┘

2. App submits descriptor to TX Ring
   TX Ring: [{addr: 0x4000, len: 128}]

3. Kernel processes TX Ring
   NIC reads UMEM at 0x4000 (DMA)
   ┌─────────────────────────┐
   │ UMEM                    │
   │ 0x4000: [PACKET DATA]   │ ← Read by NIC DMA (no copy!)
   └─────────────────────────┘
   NIC transmits packet

4. After TX complete:
   Kernel adds frame to Completion Queue
   Completion Queue: [0x4000]

5. App consumes Completion Queue
   Frame 0x4000 now free for reuse

Zero copies: App writes UMEM → NIC DMA reads UMEM → Wire
```

### Copy Mode Path (For Comparison)

When zero-copy is not supported:

```
RX Path with Copy Mode:

1. NIC DMA to driver buffer:
   Driver RX Ring Buffer: [PACKET DATA]
                              ↓
                         ═════════════
                         COPY HERE! (memcpy)
                         ═════════════
                              ↓
2. Copy to UMEM:
   UMEM: [PACKET DATA]

3. XDP runs on UMEM copy
   Add descriptor to RX Ring

4. App reads UMEM

One copy (driver buffer → UMEM), still faster than normal stack
(which does: NIC → driver → SKB → socket buffer → user buffer = 3+ copies)
```

Zero-copy mode eliminates this memcpy, achieving true NIC-to-application zero-copy.

## Context Switches with AF_XDP on Same CPU

### Scenario: XDP Program and Application on Same Core

Consider the common case where:
- Application uses AF_XDP socket on CPU X
- NIC RX queue bound to CPU X (via RSS)
- XDP program executes on CPU X (follows interrupt affinity)

**Question**: Do context switches occur between XDP program and application?

**Answer**: **No process context switch**, but the application IS interrupted by the softirq.

### Understanding Interrupts vs Context Switches

It's critical to distinguish:

1. **Interrupt**: CPU temporarily stops current task, executes interrupt/softirq handler, then resumes task
2. **Context switch**: CPU switches from one process/thread to another (saves/restores full CPU state)

See [context_switch.md](context_switch.md) for detailed context switch mechanics.

### Timeline: Application Polling on CPU X

```
CPU Core X Timeline:

Time  │ What's Running         │ Context (Task)
──────┼────────────────────────┼─────────────────────────────
  0   │ Application            │ User mode, Process PID=1234
      │ (polling RX ring)      │ task_struct *current = app
      │   while (1) {          │
      │     poll_rx_ring();    │
      │   }                    │
──────┼────────────────────────┼─────────────────────────────
  1   │ [PACKET ARRIVES]       │
      │ NIC raises interrupt   │
──────┼────────────────────────┼─────────────────────────────
  2   │ HARDIRQ Handler        │ Interrupt context
      │ (preempts application) │ current = app (still!)
      │   save app state       │
      │   ixgbe_msix_handler() │ Preemption disabled
      │   napi_schedule()      │
      │   raise NET_RX_SOFTIRQ │
      │   restore app state    │
      │   <return from irq>    │
──────┼────────────────────────┼─────────────────────────────
  3   │ Check pending softirqs │ Interrupt exit path
      │ invoke_softirq()       │ current = app (still!)
──────┼────────────────────────┼─────────────────────────────
  4   │ SOFTIRQ Handler        │ Softirq context
      │ net_rx_action()        │ current = app (still!)
      │   ixgbe_poll()         │ Preemption disabled
      │     ixgbe_clean_rx()   │
      │     ════════════════   │
      │     XDP PROGRAM RUNS   │ current = app (still!)
      │     ════════════════   │
      │     returns XDP_REDIRECT
      │     xdp_do_redirect()  │
      │       add desc to      │
      │       RX Ring          │
──────┼────────────────────────┼─────────────────────────────
  5   │ Softirq complete       │
      │ <return to user mode>  │
──────┼────────────────────────┼─────────────────────────────
  6   │ Application resumes    │ User mode, Process PID=1234
      │ (exactly where it was) │ current = app
      │   poll_rx_ring();      │ ← Next iteration
      │   /* Finds data! */    │
──────┼────────────────────────┼─────────────────────────────
  7   │ Application processes  │ User mode, Process PID=1234
      │   process_packet();    │ current = app
      │   /* Access UMEM */    │
```

### Key Points

#### No Process Context Switch

**The application process is never switched out.** The `current` task pointer remains pointing to the application's `task_struct` throughout:

```c
/* Throughout the entire flow: */
current == application_task_struct  /* Never changes! */
current->pid == 1234                /* Same process */
```

A **context switch** (as described in [context_switch.md](context_switch.md)) would involve:
- Calling `schedule()`
- Selecting a different task from the run queue
- Calling `context_switch()` to switch page tables, registers, stack, etc.

**This does NOT happen here!** The interrupt simply preempts the application temporarily.

#### Interrupt Preemption Is Not a Context Switch

What happens:

1. **Application interrupted**: CPU saves minimal state (RIP, RSP, RFLAGS) on kernel stack
2. **Hardirq runs**: On application's kernel stack (switch to ring 0)
3. **Softirq runs**: Still on application's kernel stack
4. **XDP runs**: Part of softirq, same kernel stack
5. **Return to user mode**: Restore saved state, resume application

CPU state during interrupt:

```
Before Interrupt:           During Interrupt:          After Interrupt:
┌──────────────┐            ┌──────────────┐           ┌──────────────┐
│ User Mode    │            │ Kernel Mode  │           │ User Mode    │
│ Application  │  ────────► │ Softirq      │  ───────► │ Application  │
│              │   INT       │   XDP prog   │   IRET    │              │
│ RIP: 0x...   │            │              │           │ RIP: 0x...   │
│ RSP: user    │            │ RSP: kernel  │           │ RSP: user    │
│ CR3: app_pgd │            │ CR3: app_pgd │           │ CR3: app_pgd │
└──────────────┘            └──────────────┘           └──────────────┘
   Process 1234                Process 1234              Process 1234
   ↑                           ↑                         ↑
   Same process, just temporarily in kernel mode!
```

**CR3 never changes** - still using application's page tables.
**No call to `switch_to()`** - never switches to a different thread.

#### What Gets "Switched"

Only CPU privilege level and stack pointer:

```
User mode → Kernel mode:
    CS:  User CS  → Kernel CS     (Ring 3 → Ring 0)
    RSP: User RSP → Kernel RSP    (Switch to kernel stack)
    
Kernel mode → User mode (IRET):
    CS:  Kernel CS  → User CS     (Ring 0 → Ring 3)
    RSP: Kernel RSP → User RSP    (Back to user stack)
```

This is handled by the CPU's interrupt mechanism (`syscall`/`sysret` or `int`/`iret`), NOT by the kernel's context switch machinery.

### Polling vs Blocking: Different Latency Characteristics

#### Blocking Mode: Application Sleeps

```c
/* Application blocks waiting for packets */
struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
poll(&pfd, 1, -1);  /* Block indefinitely */
```

Timeline:

```
1. Application calls poll() → enters kernel → blocks
   (Context switch: Application → Another Task)
   
2. Packet arrives → Interrupt → XDP → Add to RX Ring
   
3. wake_up() called on socket wait queue
   
4. Scheduler picks application to run
   (Context switch: Another Task → Application)
   
5. Application wakes, returns from poll()
   
Latency: ~5-10 µs (includes context switches + scheduler overhead)
```

#### Busy Polling Mode: Zero Latency

```c
/* Application polls without blocking */
while (1) {
    rcvd = xsk_ring_cons__peek(&rx, &idx, BATCH_SIZE);
    if (rcvd > 0)
        process_packets();
    /* No blocking! Continuously poll */
}
```

Timeline:

```
1. Application polling (busy loop in user mode)
   
2. Packet arrives → Interrupt preempts application
   
3. XDP runs in softirq → Adds to RX Ring
   
4. Return to user mode → Application resumes polling
   
5. Very next poll finds data!
   
Latency: ~1-3 µs (just interrupt + softirq overhead, no context switches)
```

With busy polling, **zero context switches** occur. The application consumes one CPU core at 100% but achieves minimum latency.

Enable busy polling mode:

```c
/* Disable interrupts, use busy polling */
int opt = 1;
setsockopt(xsk_fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &opt, sizeof(opt));

/* Set busy poll timeout (microseconds) */
opt = 0;  /* Don't block at all */
setsockopt(xsk_fd, SOL_SOCKET, SO_BUSY_POLL, &opt, sizeof(opt));
```

With these options, the kernel disables interrupts for the RX queue and polls in the application's context:

```c
/* When application calls poll() or recvmsg() */
/* Kernel checks for packets WITHOUT sleeping */
napi_poll(napi_struct);  /* Poll in syscall context */
```

### CPU Affinity Best Practices

For lowest latency with AF_XDP:

1. **Pin application to specific CPU**:
```bash
taskset -c 2 ./my_xdp_app
```

2. **Pin RX queue interrupt to same CPU**:
```bash
echo 4 > /proc/irq/125/smp_affinity  # CPU 2 (bitmask: 1 << 2 = 4)
```

3. **Isolate CPU from scheduler** (optional, for ultra-low latency):
```bash
# Boot parameter: isolcpus=2
# Prevents normal scheduler from using CPU 2
```

This ensures:
- Packet arrives → Interrupt on CPU 2
- XDP runs on CPU 2 (softirq)
- Application runs on CPU 2
- All data stays in CPU 2's cache (no cross-CPU traffic)
- No process migrations, no TLB flushes

### Summary: Context Switches and AF_XDP

| Scenario | Context Switches | Notes |
|----------|-----------------|-------|
| **XDP + App on same CPU (busy polling)** | **0** | Application interrupted by softirq, but same process |
| **XDP + App on same CPU (blocking)** | **2 per packet** | Sleep → wake transitions |
| **XDP on CPU A, App on CPU B** | **2 per packet** | Plus cache/memory traffic overhead |
| **Traditional socket (no XDP)** | **≥2 per packet** | Plus full network stack overhead |

For absolute minimum latency: **Same CPU + busy polling = zero context switches**.

Cost comparison:

- **Context switch**: ~1000-3000 cycles (see [context_switch.md](context_switch.md))
- **Interrupt + softirq**: ~200-500 cycles
- **Busy polling (no interrupt)**: ~50-100 cycles (just ring buffer check)

AF_XDP with busy polling achieves sub-microsecond user space packet processing by eliminating both context switches AND interrupts.

## Performance Analysis

### Packet Processing Latency Comparison

#### Traditional Linux Network Stack

```
NIC → Interrupt → Softirq → IP Layer → TCP/UDP → Socket → Application

Breakdown:
- Interrupt + NAPI:        ~500-1000 cycles
- SKB allocation:          ~200-300 cycles
- IP layer processing:     ~500-1000 cycles
- TCP/UDP processing:      ~1000-2000 cycles
- Socket wake + context:   ~1000-2000 cycles
─────────────────────────────────────────────
Total: ~4000-7000 cycles = ~1-3 µs @ 2 GHz
       ~10-50 µs wall-clock (with scheduling)
```

#### XDP_DROP (Firewall/DDoS Mitigation)

```
NIC → Interrupt → Softirq → XDP Program → DROP

Breakdown:
- Interrupt + NAPI:        ~500-1000 cycles
- XDP program execution:   ~50-200 cycles
- Buffer recycle:          ~20-50 cycles
─────────────────────────────────────────────
Total: ~600-1300 cycles = ~0.3-0.7 µs @ 2 GHz
```

**Speedup: 5-10x faster than iptables DROP**

#### XDP_PASS (Selective Processing)

```
NIC → Interrupt → Softirq → XDP Program → PASS → IP Stack

Breakdown:
- Interrupt + NAPI:        ~500-1000 cycles
- XDP program execution:   ~50-200 cycles
- SKB allocation:          ~200-300 cycles
- IP/TCP/UDP:              ~2000-3000 cycles
─────────────────────────────────────────────
Total: ~3000-5000 cycles = ~1.5-2.5 µs @ 2 GHz
```

**Overhead: XDP adds ~100-200 cycles to normal path (minimal)**

#### AF_XDP Zero-Copy (User Space Processing)

```
NIC → Interrupt → Softirq → XDP_REDIRECT → RX Ring → Application (busy polling)

Breakdown:
- Interrupt + NAPI:        ~500-1000 cycles
- XDP program execution:   ~50-100 cycles
- Redirect to AF_XDP:      ~100-200 cycles
- Application poll:        ~50-100 cycles
─────────────────────────────────────────────
Total: ~700-1400 cycles = ~0.4-0.7 µs @ 2 GHz
       ~2-5 µs wall-clock (with interrupts)
       ~1-2 µs (busy polling, no interrupts)
```

**Speedup: 10-20x faster than AF_PACKET**

### Throughput Comparison

#### 10 Gigabit Ethernet (10 GbE) Line Rate

```
10 Gbps = 10,000,000,000 bits/sec

With 64-byte packets (minimum Ethernet frame):
- Packet: 64 bytes (512 bits)
- On-wire: 64 + 8 (preamble) + 12 (IFG) = 84 bytes
- 84 bytes = 672 bits
- Line rate: 10,000,000,000 / 672 = 14,880,952 packets/sec
- ~14.88 Mpps (million packets per second)

With 1518-byte packets (maximum without jumbo):
- Line rate: ~812,743 pps
```

#### Single-Core Performance

**Traditional Stack (no XDP)**:
```
Single CPU core @ 2 GHz:
- ~5000 cycles per packet (TCP/IP processing)
- Throughput: 2,000,000,000 / 5000 = 400,000 pps
- ~3-5 Mpps max with optimizations

Cannot achieve line rate on single core!
```

**XDP_DROP**:
```
Single CPU core @ 2 GHz:
- ~1000 cycles per packet (XDP drop)
- Throughput: 2,000,000,000 / 1000 = 2,000,000 pps
- ~10-20 Mpps achievable with tight XDP programs

Can achieve or exceed 10 GbE line rate on single core!
```

**AF_XDP Zero-Copy**:
```
Single CPU core @ 2 GHz:
- ~1200 cycles per packet (XDP + user processing)
- Throughput: 2,000,000,000 / 1200 = 1,666,666 pps
- ~8-15 Mpps with efficient user code

Near line rate on single core!
```

#### Multi-Core Scaling with RSS

With 4 RX queues and 4 CPU cores:

```
XDP_DROP with 4 cores:
- Per-core: ~15 Mpps
- Total: ~60 Mpps

Can handle 10 GbE at line rate with room to spare
Can handle 40 GbE (4x 10 GbE) at line rate
Approaching 100 GbE line rate
```

XDP scales linearly with cores (no lock contention).

### CPU Cycle Breakdown

#### XDP Program Execution Cost

```c
/* Simple XDP program: drop TCP packets */
SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol == IPPROTO_TCP)
        return XDP_DROP;
    
    return XDP_PASS;
}

Compiled to ~25 x86-64 instructions
Execution: ~50-80 cycles
```

More complex programs cost more:

- **BPF map lookup**: +50-100 cycles per lookup
- **Packet modification**: +20-50 cycles per field
- **Checksum recalculation**: +100-200 cycles

Keep XDP programs tight for best performance!

#### Memory Access Patterns

```
Cache behavior:

L1 Cache Hit:  ~4 cycles
L2 Cache Hit:  ~12 cycles
L3 Cache Hit:  ~40 cycles
DRAM Access:   ~100-200 cycles

XDP program accessing packet data:
- First access: L3/DRAM (~40-100 cycles) [DMA'd data]
- Subsequent:   L1 (~4 cycles) [cached]

Good locality is critical for performance!
```

### Real-World Benchmarks

#### DDoS Mitigation (XDP_DROP)

```
Test: Drop all traffic from specific source IPs
Hardware: Intel Xeon, ixgbe 10 GbE
Packet size: 64 bytes (worst case)

Results:
- Without XDP:   ~5 Mpps (iptables)
- With XDP:      ~18 Mpps (single core)
- With XDP:      ~70 Mpps (4 cores with RSS)

CPU usage:
- Without XDP:   100% (saturated, dropping packets)
- With XDP:      ~80% (handling all packets)
```

#### Load Balancer (XDP_TX)

```
Test: Reflect packets back out same interface
Hardware: Mellanox ConnectX-5, mlx5 25 GbE
Packet size: 64 bytes

Results:
- Traditional:   ~3 Mpps (user space load balancer)
- AF_XDP:        ~12 Mpps (user space with AF_XDP)
- XDP_TX:        ~25 Mpps (in-kernel XDP)

Latency (round-trip):
- Traditional:   ~50 µs
- AF_XDP:        ~8 µs
- XDP_TX:        ~2 µs
```

#### Packet Capture (AF_XDP)

```
Test: Capture all packets to user space
Hardware: Intel i40e, 10 GbE
Packet size: 1500 bytes

Results:
- tcpdump:       ~800 Kpps (AF_PACKET, copy mode)
- AF_XDP copy:   ~2 Mpps (copy mode)
- AF_XDP zc:     ~5 Mpps (zero-copy mode)

CPU usage (single core):
- tcpdump:       ~80%
- AF_XDP zc:     ~40%
```

### Optimization Tips

#### For Lowest Latency

1. **Use busy polling**: Eliminate interrupt latency
2. **Pin to isolated CPU**: Avoid scheduler interference
3. **Same CPU for RX queue and app**: Maximize cache locality
4. **Zero-copy mode**: Eliminate memory copies
5. **Tight XDP programs**: Minimize cycles per packet

#### For Highest Throughput

1. **RSS with multiple queues**: Spread across CPUs
2. **Batch processing**: Process multiple packets per poll
3. **Huge pages for UMEM**: Reduce TLB misses
4. **BPF map preallocation**: Avoid runtime allocation
5. **Profile and optimize**: Use `perf` to find hotspots

#### Example: Optimized AF_XDP Setup

```c
/* Huge pages for UMEM */
void *umem = mmap(NULL, UMEM_SIZE,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_LOCKED,
                 -1, 0);

/* Busy polling */
int opt = 1;
setsockopt(xsk_fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &opt, sizeof(opt));

/* Zero-copy */
struct sockaddr_xdp sxdp = {
    .sxdp_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
};

/* Pin to CPU */
cpu_set_t cpuset;
CPU_ZERO(&cpuset);
CPU_SET(2, &cpuset);
pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

/* Batch processing */
#define BATCH_SIZE 64
while (1) {
    rcvd = xsk_ring_cons__peek(&rx, &idx, BATCH_SIZE);
    for (i = 0; i < rcvd; i++) {
        /* Process packet */
    }
}
```

This can achieve ~10-15 Mpps on a single core with sub-2µs latency.

## Cross-References to Other Chapters

### NIC Drivers

See [nics.md](nics.md) for details on:

- **Ring buffer architecture**: XDP reuses the NIC's RX ring buffers
- **DMA operations**: How packet data arrives in memory (XDP operates on DMA buffers)
- **NAPI polling**: XDP runs within NAPI poll context
- **`ixgbe` driver specifics**: XDP integration in Intel 10 GbE driver

XDP is tightly integrated with the driver's packet receive path.

### Interrupts and Softirqs

See [Linux Interrupt Handling](linux_interrupts.md) for details on:

- **Hard IRQ handling**: NIC interrupt that triggers XDP
- **Softirq context**: XDP programs run in `NET_RX_SOFTIRQ` handler
- **NAPI mechanism**: How softirqs batch-process packets
- **CPU affinity**: How RSS binds interrupts (and XDP) to specific CPUs

Understanding softirq context is critical for XDP programming constraints.

### Context Switches

See [context_switch.md](context_switch.md) for details on:

- **What is a context switch**: Full process/thread switch (CR3, registers, stack)
- **When context switches happen**: Scheduler decisions, blocking operations
- **Cost of context switches**: ~1000-3000 cycles on AMD64
- **Interrupt vs context switch**: Why interrupts don't change `current` process

AF_XDP avoids context switches by using busy polling.

### IP Layer

See [ip.md](ip.md) for details on:

- **`ip_rcv()` function**: Where XDP_PASS packets enter IP layer
- **SKB structure**: What XDP avoids allocating (XDP_DROP, XDP_TX)
- **Routing**: Traditional path that XDP can bypass
- **Protocol handlers**: What XDP_PASS packets eventually reach

XDP provides a fast path around the full IP stack for specialized use cases.

### Scheduling

See [scheduler.md](scheduler.md) for details on:

- **Process wake-up**: How blocking AF_XDP sockets wake applications
- **CPU affinity**: Pinning application and interrupts to same CPU
- **Real-time scheduling**: For ultra-low latency AF_XDP applications

Scheduler configuration affects AF_XDP latency in blocking mode.

---

## Summary

**XDP (eXpress Data Path)** enables Linux to process packets at unprecedented speeds by:

1. **Running eBPF programs at the driver level** - before expensive SKB allocation
2. **Providing multiple execution modes** - native (driver), offloaded (hardware), generic (fallback)
3. **Executing in softirq context** - same CPU as interrupt, with strict constraints
4. **Supporting fast verdicts** - DROP (firewall), PASS (selective), TX (reflect), REDIRECT (forward)
5. **Enabling zero-copy to user space** - AF_XDP sockets with UMEM-based ring buffers
6. **Avoiding context switches** - through busy polling and same-CPU processing
7. **Achieving line-rate performance** - 10-20 Mpps per core, 100+ Mpps multi-core

XDP is production-ready and widely deployed for DDoS mitigation, load balancing, packet filtering, and high-performance networking in cloud environments.

For applications requiring sub-microsecond latency and millions of packets per second, XDP is the state-of-the-art solution in Linux.