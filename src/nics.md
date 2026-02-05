# Network Interface Cards

## Overview

A **network interface card (NIC) driver** is the kernel software component that controls a physical or virtual network device. On Linux, NIC drivers bridge the hardware layer (DMA, interrupts, device registers) with the kernel's networking stack (TCP/IP, sockets, protocols).

### What a NIC Driver Does

The driver's primary responsibilities are:

1. **Initialize the hardware**: Configure device registers, allocate memory for DMA rings, set up interrupts
2. **Receive packets**: Handle incoming packets from the wire, DMA them to memory, and pass them to the network stack
3. **Transmit packets**: Take outgoing packets from the network stack, DMA them to the device, and signal transmission
4. **Manage device state**: Handle link up/down events, speed/duplex negotiation, power management
5. **Expose device capabilities**: Advertise hardware offload features (checksumming, segmentation, etc.)

### Role in the Networking Stack

The NIC driver sits at the bottom of Linux's networking stack:

```
Application (user space)
        ↓
Socket API (syscalls)
        ↓
Protocol Layers (TCP/IP, UDP, etc.)
        ↓
Network Device Layer (net_device)
        ↓
NIC Driver ← You are here
        ↓
Hardware (DMA, registers, PHY)
```

The driver interacts with:
- **Hardware**: Device registers, DMA engines, interrupt controllers
- **Kernel networking core**: Through the `net_device` interface
- **Interrupt subsystem**: For packet arrival notifications (see [Linux Interrupt Handling](linux_interrupts.md))
- **DMA subsystem**: For efficient data transfer between device and memory
- **PCI subsystem**: For device discovery and configuration (on PCIe NICs)

### Key Kernel Subsystems

A NIC driver integrates with several kernel subsystems:

1. **Network Device Layer**: Core abstraction for network interfaces (`struct net_device`)
2. **NAPI (New API)**: Polling interface for efficient packet reception
3. **DMA API**: Consistent and streaming DMA for packet buffers
4. **Interrupt Management**: IRQ handling and softirq processing
5. **ethtool**: User-space configuration and statistics interface

Throughout this chapter, we'll use the **ixgbe driver** (Intel 82599 10-Gigabit Ethernet) as our reference implementation. This driver supports modern features like multi-queue, RSS, and hardware offloads, making it representative of high-performance NIC drivers.

## Core Driver Interfaces

### The `net_device` Structure

Every network interface in Linux is represented by a `struct net_device`. This structure contains:
- Device metadata (name, MAC address, MTU)
- Hardware capabilities and features
- Statistics counters
- Pointers to driver-specific operations
- Queue management structures
- Device state flags

The driver allocates and registers a `net_device` during initialization:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    struct net_device *netdev;
    struct ixgbe_adapter *adapter;
    
    /* Allocate net_device with private data */
    netdev = alloc_etherdev_mq(sizeof(struct ixgbe_adapter), MAX_TX_QUEUES);
    if (!netdev)
        return -ENOMEM;
    
    /* Get driver's private data */
    adapter = netdev_priv(netdev);
    adapter->netdev = netdev;
    adapter->pdev = pdev;
    
    /* Set device name */
    strcpy(netdev->name, pci_name(pdev));
    
    /* Configure operations */
    netdev->netdev_ops = &ixgbe_netdev_ops;
    netdev->watchdog_timeo = 5 * HZ;
    
    /* Set hardware features */
    netdev->features |= NETIF_F_SG;           /* Scatter-gather */
    netdev->features |= NETIF_F_TSO;          /* TCP segmentation offload */
    netdev->features |= NETIF_F_RXCSUM;       /* RX checksumming */
    netdev->features |= NETIF_F_HW_CSUM;      /* TX checksumming */
    
    /* ... more initialization ... */
    
    /* Register with networking core */
    err = register_netdev(netdev);
    if (err)
        goto err_register;
    
    return 0;
}
```

#### Key `net_device` Fields

```c
/* From include/linux/netdevice.h */
struct net_device {
    char name[IFNAMSIZ];              /* Interface name (e.g., "eth0") */
    
    unsigned char perm_addr[MAX_ADDR_LEN];  /* Permanent MAC address */
    unsigned char *dev_addr;           /* Current MAC address */
    
    unsigned int mtu;                  /* Maximum transmission unit */
    unsigned short type;               /* Hardware type (Ethernet = ARPHRD_ETHER) */
    
    netdev_features_t features;        /* Device capabilities (offloads, etc.) */
    netdev_features_t hw_features;     /* Hardware-supported features */
    
    const struct net_device_ops *netdev_ops;  /* Driver operations */
    const struct ethtool_ops *ethtool_ops;    /* ethtool interface */
    
    struct netdev_queue *_tx;          /* TX queues */
    unsigned int num_tx_queues;        /* Number of TX queues */
    unsigned int real_num_tx_queues;   /* Active TX queues */
    
    unsigned int num_rx_queues;        /* Number of RX queues */
    unsigned int real_num_rx_queues;   /* Active RX queues */
    
    struct Qdisc *qdisc;               /* Queue discipline */
    
    unsigned long state;               /* Device state flags */
    
    void *priv;                        /* Driver private data (ixgbe_adapter) */
    
    /* Statistics */
    struct net_device_stats stats;
    
    /* ... many more fields ... */
};
```

For ixgbe, the driver allocates private data with `alloc_etherdev_mq()`:

```c
/* ixgbe private adapter structure */
struct ixgbe_adapter {
    struct timer_list service_timer;
    struct work_struct service_task;
    
    u32 flags;
    u32 flags2;
    
    /* Hardware structures */
    struct ixgbe_hw hw;
    
    /* TX/RX ring arrays */
    struct ixgbe_ring *tx_ring[MAX_TX_QUEUES];
    struct ixgbe_ring *rx_ring[MAX_RX_QUEUES];
    
    u16 num_tx_queues;
    u16 num_rx_queues;
    
    /* Interrupt vectors */
    struct msix_entry *msix_entries;
    int num_q_vectors;
    struct ixgbe_q_vector *q_vector[MAX_Q_VECTORS];
    
    /* DMA attributes */
    u64 tx_dma_mask;
    u64 rx_dma_mask;
    
    /* Device state */
    unsigned long state;
    u64 tx_busy;
    
    /* ... more fields ... */
};
```

### Required Operations: `net_device_ops`

The `net_device_ops` structure defines the operations that the networking core can invoke on the device:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static const struct net_device_ops ixgbe_netdev_ops = {
    .ndo_open               = ixgbe_open,
    .ndo_stop               = ixgbe_close,
    .ndo_start_xmit         = ixgbe_xmit_frame,
    .ndo_set_rx_mode        = ixgbe_set_rx_mode,
    .ndo_validate_addr      = eth_validate_addr,
    .ndo_set_mac_address    = ixgbe_set_mac,
    .ndo_change_mtu         = ixgbe_change_mtu,
    .ndo_tx_timeout         = ixgbe_tx_timeout,
    .ndo_get_stats64        = ixgbe_get_stats64,
    .ndo_setup_tc           = __ixgbe_setup_tc,
    .ndo_select_queue       = ixgbe_select_queue,
    .ndo_set_features       = ixgbe_set_features,
    .ndo_fix_features       = ixgbe_fix_features,
    .ndo_fdb_add            = ixgbe_ndo_fdb_add,
    .ndo_do_ioctl           = ixgbe_ioctl,
    /* ... more operations ... */
};
```

#### `ndo_open()` - Bringing the Interface Up

Called when the interface is enabled (e.g., `ip link set eth0 up`):

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_open(struct net_device *netdev)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    int err;
    
    /* Allocate TX/RX descriptor rings and buffers */
    err = ixgbe_setup_all_tx_resources(adapter);
    if (err)
        goto err_setup_tx;
    
    err = ixgbe_setup_all_rx_resources(adapter);
    if (err)
        goto err_setup_rx;
    
    /* Configure the hardware */
    ixgbe_configure(adapter);
    
    /* Request IRQs */
    err = ixgbe_request_irq(adapter);
    if (err)
        goto err_req_irq;
    
    /* Enable NAPI polling */
    ixgbe_napi_enable_all(adapter);
    
    /* Enable interrupts */
    ixgbe_irq_enable(adapter);
    
    /* Start the hardware */
    err = ixgbe_up_complete(adapter);
    if (err)
        goto err_up;
    
    /* Notify stack that link is up */
    netif_tx_start_all_queues(netdev);
    
    return 0;
    
err_up:
    ixgbe_irq_disable(adapter);
err_req_irq:
    ixgbe_free_all_rx_resources(adapter);
err_setup_rx:
    ixgbe_free_all_tx_resources(adapter);
err_setup_tx:
    return err;
}
```

Key operations in `ndo_open()`:
1. Allocate DMA ring buffers
2. Configure hardware registers
3. Request IRQ lines (MSI-X vectors for ixgbe)
4. Enable NAPI polling
5. Enable device interrupts
6. Start transmit queues

#### `ndo_stop()` - Bringing the Interface Down

Called when the interface is disabled (e.g., `ip link set eth0 down`):

```c
static int ixgbe_close(struct net_device *netdev)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    
    /* Stop all TX queues */
    netif_tx_stop_all_queues(netdev);
    
    /* Disable NAPI */
    ixgbe_napi_disable_all(adapter);
    
    /* Disable interrupts */
    ixgbe_irq_disable(adapter);
    
    /* Free IRQs */
    ixgbe_free_irq(adapter);
    
    /* Stop hardware */
    ixgbe_down(adapter);
    
    /* Free ring resources */
    ixgbe_free_all_tx_resources(adapter);
    ixgbe_free_all_rx_resources(adapter);
    
    return 0;
}
```

#### `ndo_start_xmit()` - Transmitting Packets

Called by the network stack to transmit a packet:

```c
static netdev_tx_t ixgbe_xmit_frame(struct sk_buff *skb,
                                    struct net_device *netdev)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    struct ixgbe_ring *tx_ring;
    
    /* Select transmit queue (for multi-queue devices) */
    tx_ring = adapter->tx_ring[skb->queue_mapping];
    
    /* Check if queue has space */
    if (ixgbe_maybe_stop_tx(tx_ring, skb->len)) {
        /* TX ring full, stop queue */
        netif_stop_subqueue(netdev, tx_ring->queue_index);
        return NETDEV_TX_BUSY;
    }
    
    /* Perform the actual transmission */
    return ixgbe_xmit_frame_ring(skb, adapter, tx_ring);
}
```

We'll cover the detailed transmission flow in the Packet Transmission section below.

#### `ndo_get_stats64()` - Statistics Reporting

Provides network statistics to user space (e.g., `ip -s link show eth0`):

```c
static void ixgbe_get_stats64(struct net_device *netdev,
                             struct rtnl_link_stats64 *stats)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    int i;
    
    /* Aggregate statistics from all rings */
    for (i = 0; i < adapter->num_rx_queues; i++) {
        struct ixgbe_ring *ring = adapter->rx_ring[i];
        u64 bytes, packets;
        
        do {
            start = u64_stats_fetch_begin_irq(&ring->syncp);
            bytes = ring->stats.bytes;
            packets = ring->stats.packets;
        } while (u64_stats_fetch_retry_irq(&ring->syncp, start));
        
        stats->rx_bytes += bytes;
        stats->rx_packets += packets;
    }
    
    for (i = 0; i < adapter->num_tx_queues; i++) {
        struct ixgbe_ring *ring = adapter->tx_ring[i];
        u64 bytes, packets;
        
        do {
            start = u64_stats_fetch_begin_irq(&ring->syncp);
            bytes = ring->stats.bytes;
            packets = ring->stats.packets;
        } while (u64_stats_fetch_retry_irq(&ring->syncp, start));
        
        stats->tx_bytes += bytes;
        stats->tx_packets += packets;
    }
    
    /* Add hardware error counters */
    stats->rx_errors = adapter->stats.crcerrs + adapter->stats.rlec;
    stats->rx_dropped = adapter->stats.mpc;
    stats->tx_errors = adapter->stats.ecol;
}
```

#### `ndo_set_mac_address()` - MAC Address Changes

Updates the device's MAC address:

```c
static int ixgbe_set_mac(struct net_device *netdev, void *p)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    struct ixgbe_hw *hw = &adapter->hw;
    struct sockaddr *addr = p;
    
    if (!is_valid_ether_addr(addr->sa_data))
        return -EADDRNOTAVAIL;
    
    /* Update software copy */
    memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
    memcpy(hw->mac.addr, addr->sa_data, netdev->addr_len);
    
    /* Program hardware MAC filter */
    hw->mac.ops.set_rar(hw, 0, hw->mac.addr, VMDQ_P(0), IXGBE_RAH_AV);
    
    return 0;
}
```

#### `ndo_change_mtu()` - MTU Changes

Adjusts the Maximum Transmission Unit:

```c
static int ixgbe_change_mtu(struct net_device *netdev, int new_mtu)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;
    
    /* Check MTU bounds */
    if ((new_mtu < 68) || (max_frame > IXGBE_MAX_JUMBO_FRAME_SIZE))
        return -EINVAL;
    
    /* For running interfaces, need to restart */
    if (netif_running(netdev)) {
        ixgbe_down(adapter);
        netdev->mtu = new_mtu;
        ixgbe_up(adapter);
    } else {
        netdev->mtu = new_mtu;
    }
    
    return 0;
}
```

#### `ndo_do_ioctl()` - Device Control

Handles device-specific ioctl commands (used by ethtool and other tools):

```c
static int ixgbe_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
    switch (cmd) {
    case SIOCETHTOOL:
        return ixgbe_ethtool_ioctl(netdev, ifr);
    case SIOCSHWTSTAMP:
        return ixgbe_ptp_set_ts_config(adapter, ifr);
    case SIOCGHWTSTAMP:
        return ixgbe_ptp_get_ts_config(adapter, ifr);
    default:
        return -EOPNOTSUPP;
    }
}
```

### Device Registration

Once the `net_device` is configured, the driver registers it with the kernel:

```c
/* Makes the device visible to user space */
int register_netdev(struct net_device *dev)
{
    int err;
    
    /* Assign device number if needed */
    if (dev->name[0] == '\0' || strchr(dev->name, '%')) {
        err = dev_alloc_name(dev, dev->name);
        if (err < 0)
            return err;
    }
    
    /* Register with device core */
    err = netdev_register_kobject(dev);
    if (err)
        return err;
    
    /* Add to device list */
    dev_net_set(dev, &init_net);
    
    /* Notify interested parties */
    call_netdevice_notifiers(NETDEV_REGISTER, dev);
    
    return 0;
}
```

After successful registration:
- The interface appears in `/sys/class/net/`
- It can be configured with `ip` or `ifconfig` commands
- Applications can bind sockets to it
- The kernel routing subsystem can use it

This completes the core driver interfaces that every NIC driver must implement to integrate with the Linux networking stack.

## Ring Buffer Architecture

Network interface cards use **ring buffers** (also called descriptor rings) to communicate with the driver. These are circular buffers in memory where the hardware and software exchange information about packet transfers via **descriptors**.

### Why Ring Buffers?

Ring buffers provide an efficient mechanism for:
1. **Asynchronous operation**: Hardware and software work independently without waiting
2. **Batch processing**: Multiple packets can be queued before processing
3. **Zero-copy transfers**: DMA directly to/from final packet buffers
4. **Lock-free operation**: Using head/tail pointers avoids most locking

### Ring Buffer Concept

A ring buffer consists of:
- **Descriptors**: Small structures containing DMA addresses, lengths, and flags
- **Buffers**: Actual packet data in memory
- **Pointers**: Head and tail indices tracking position

```
Ring Buffer (Circular Array of Descriptors):

    tail                head
     ↓                   ↓
    [D0][D1][D2][D3][D4][D5][D6][D7]
     ↓   ↓   ↓   ↓                ↑
     B0  B1  B2  B3               |
                                  wrap around
Descriptors point to packet buffers (B0, B1, etc.)
```

The ring "wraps" when it reaches the end: index 7 → 0.

### TX Ring (Transmit)

The transmit ring uses a **producer/consumer** model:
- **Producer (CPU/Driver)**: Writes descriptors for packets to send
- **Consumer (NIC)**: Reads descriptors and transmits packets

```
TX Ring Operation:

CPU (Producer)                    NIC (Consumer)
     │                                 │
     │ 1. Write descriptor             │
     │    with DMA address             │
     ├──────────────┐                  │
     │              ↓                  │
     │         [Descriptor]            │
     │              │                  │
     │ 2. Update    │                  │
     │    tail ptr  │                  │
     ├──────────────┘                  │
     │                                 │
     │                            3. Read descriptor
     │                            4. DMA from buffer
     │                            5. Transmit packet
     │                            6. Write back status
     │                            7. Update head ptr
     │                                 │
     │ 8. Read head ptr                │
     │    (in completion)              │
     │ 9. Free buffer                  │
```

#### TX Descriptor Structure (ixgbe)

The ixgbe driver uses the following TX descriptor format:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_type.h */

/* Advanced TX Descriptor (used by ixgbe) */
union ixgbe_adv_tx_desc {
    struct {
        __le64 buffer_addr;       /* Address of descriptor's data buffer */
        __le32 cmd_type_len;      /* Command, type, and length */
        __le32 olinfo_status;     /* Offload info and status */
    } read;                        /* Format for driver to write */
    
    struct {
        __le64 rsvd;              /* Reserved */
        __le32 nxtseq_seed;       /* Next sequence and seed */
        __le32 status;            /* Descriptor status */
    } wb;                          /* Format for hardware write-back */
};

/* TX descriptor command bits */
#define IXGBE_TXD_CMD_EOP    0x01000000  /* End of Packet */
#define IXGBE_TXD_CMD_IFCS   0x02000000  /* Insert FCS (CRC) */
#define IXGBE_TXD_CMD_RS     0x08000000  /* Report Status (request completion) */
#define IXGBE_TXD_CMD_DEXT   0x20000000  /* Descriptor extension */

/* TX descriptor status bits (write-back) */
#define IXGBE_TXD_STAT_DD    0x00000001  /* Descriptor Done */
```

Each descriptor is 16 bytes (128 bits) and contains:
- **buffer_addr**: Physical DMA address of the packet buffer
- **cmd_type_len**: Command flags, packet type, and length
- **olinfo_status**: Hardware offload information

#### TX Ring Structure (ixgbe)

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe.h */
struct ixgbe_ring {
    struct ixgbe_ring *next;        /* Linked list of rings */
    struct ixgbe_q_vector *q_vector; /* Backpointer to q_vector */
    struct net_device *netdev;       /* Netdev ring belongs to */
    struct device *dev;              /* Device for DMA mapping */
    
    void *desc;                      /* Descriptor ring memory (virtual) */
    dma_addr_t dma;                  /* Physical address of descriptor ring */
    
    u16 count;                       /* Number of descriptors */
    u16 next_to_use;                 /* Next descriptor to fill (tail) */
    u16 next_to_clean;               /* Next descriptor to check (head) */
    
    union {
        struct ixgbe_tx_buffer *tx_buffer_info;  /* TX buffer tracking */
        struct ixgbe_rx_buffer *rx_buffer_info;  /* RX buffer tracking */
    };
    
    u8 queue_index;                  /* Logical queue number */
    u8 reg_idx;                      /* Hardware register index */
    u16 numa_node;                   /* NUMA node for allocation */
    
    /* Statistics */
    struct u64_stats_sync syncp;
    struct ixgbe_queue_stats stats;
    
    /* ... more fields ... */
} ____cacheline_internodealigned;

/* Per-buffer metadata for TX */
struct ixgbe_tx_buffer {
    union ixgbe_adv_tx_desc *next_to_watch;  /* Last descriptor for this packet */
    struct sk_buff *skb;                      /* Socket buffer being transmitted */
    unsigned int bytecount;                   /* Bytes in this buffer */
    unsigned short gso_segs;                  /* GSO segment count */
    
    DEFINE_DMA_UNMAP_ADDR(dma);               /* DMA address */
    DEFINE_DMA_UNMAP_LEN(len);                /* DMA length */
    u32 tx_flags;                             /* TX flags (VLAN, TSO, etc.) */
};
```

#### TX Ring Allocation

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_setup_tx_resources(struct ixgbe_ring *tx_ring)
{
    struct device *dev = tx_ring->dev;
    int size;
    
    /* Calculate size: count * descriptor_size */
    size = sizeof(struct ixgbe_tx_buffer) * tx_ring->count;
    
    /* Allocate TX buffer info array (per-buffer metadata) */
    tx_ring->tx_buffer_info = vzalloc(size);
    if (!tx_ring->tx_buffer_info)
        return -ENOMEM;
    
    /* Round up to nearest 4K for descriptor ring */
    tx_ring->size = tx_ring->count * sizeof(union ixgbe_adv_tx_desc);
    tx_ring->size = ALIGN(tx_ring->size, 4096);
    
    /* Allocate coherent DMA memory for descriptors */
    tx_ring->desc = dma_alloc_coherent(dev, tx_ring->size,
                                       &tx_ring->dma, GFP_KERNEL);
    if (!tx_ring->desc) {
        vfree(tx_ring->tx_buffer_info);
        return -ENOMEM;
    }
    
    /* Initialize pointers */
    tx_ring->next_to_use = 0;
    tx_ring->next_to_clean = 0;
    
    return 0;
}
```

Key points:
- **Descriptor ring**: DMA-coherent memory (no cache, CPU and NIC see same values)
- **Buffer info array**: Normal kernel memory for driver bookkeeping
- **Ring size**: Typically 256-4096 descriptors (power of 2 for efficiency)

### RX Ring (Receive)

The receive ring also uses producer/consumer, but roles are reversed:
- **Producer (NIC)**: Writes received packets to buffers, updates descriptors
- **Consumer (CPU/Driver)**: Reads descriptors and processes packets

```
RX Ring Operation:

CPU (Consumer)                    NIC (Producer)
     │                                 │
     │ 1. Allocate buffer              │
     │ 2. Write descriptor             │
     │    with DMA address             │
     ├──────────────┐                  │
     │              ↓                  │
     │         [Descriptor]            │
     │              │                  │
     │ 3. Update    │                  │
     │    tail ptr  │                  │
     ├──────────────┘                  │
     │                                 │
     │                            4. Packet arrives
     │                            5. DMA to buffer
     │                            6. Write descriptor status
     │                            7. Update head ptr
     │                                 │
     │ 8. Poll ring                    │
     │ 9. Read descriptor              │
     │10. Process packet               │
     │11. Refill with new buffer       │
```

#### RX Descriptor Structure (ixgbe)

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_type.h */

/* Advanced RX Descriptor */
union ixgbe_adv_rx_desc {
    struct {
        __le64 pkt_addr;          /* Packet buffer address */
        __le64 hdr_addr;          /* Header buffer address (header split) */
    } read;                        /* Format for driver to write */
    
    struct {
        struct {
            __le32 data;
            struct {
                __le16 pkt_info;  /* RSS type, packet type */
                __le16 hdr_info;  /* Header length, SPH */
            } hi_dword;
        } lower;
        struct {
            __le32 status_error;   /* Status and error bits */
            __le16 length;         /* Packet length */
            __le16 vlan;           /* VLAN tag */
        } upper;
    } wb;                          /* Format for hardware write-back */
};

/* RX descriptor status bits (write-back) */
#define IXGBE_RXD_STAT_DD       0x01  /* Descriptor Done */
#define IXGBE_RXD_STAT_EOP      0x02  /* End of Packet */

/* RX descriptor error bits */
#define IXGBE_RXD_ERR_CE        0x01  /* CRC Error */
#define IXGBE_RXD_ERR_LE        0x02  /* Length Error */
#define IXGBE_RXD_ERR_PE        0x08  /* Packet Error */
#define IXGBE_RXD_ERR_RXE       0x20  /* RX Data Error */
```

#### RX Buffer Management (ixgbe)

ixgbe uses a page-based RX model for efficiency:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe.h */
struct ixgbe_rx_buffer {
    struct page *page;             /* Page for received data */
    dma_addr_t dma;                /* DMA address of page */
    unsigned int page_offset;      /* Offset into page */
    unsigned int pagecnt_bias;     /* Page reference count bias */
};
```

Instead of allocating an skb for each descriptor upfront, ixgbe:
1. Allocates pages for DMA
2. Maps pages for DMA
3. On packet arrival, builds skb from page fragments
4. Reuses pages when possible (multiple packets per page)

#### RX Ring Allocation

```c
static int ixgbe_setup_rx_resources(struct ixgbe_ring *rx_ring)
{
    struct device *dev = rx_ring->dev;
    int size;
    
    /* Allocate RX buffer info array */
    size = sizeof(struct ixgbe_rx_buffer) * rx_ring->count;
    rx_ring->rx_buffer_info = vzalloc(size);
    if (!rx_ring->rx_buffer_info)
        return -ENOMEM;
    
    /* Allocate descriptor ring (coherent DMA) */
    rx_ring->size = rx_ring->count * sizeof(union ixgbe_adv_rx_desc);
    rx_ring->size = ALIGN(rx_ring->size, 4096);
    
    rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size,
                                       &rx_ring->dma, GFP_KERNEL);
    if (!rx_ring->desc) {
        vfree(rx_ring->rx_buffer_info);
        return -ENOMEM;
    }
    
    rx_ring->next_to_clean = 0;
    rx_ring->next_to_use = 0;
    
    /* Allocate and map RX buffers */
    ixgbe_alloc_rx_buffers(rx_ring, ixgbe_desc_unused(rx_ring));
    
    return 0;
}
```

#### Refilling RX Buffers

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
void ixgbe_alloc_rx_buffers(struct ixgbe_ring *rx_ring, u16 cleaned_count)
{
    union ixgbe_adv_rx_desc *rx_desc;
    struct ixgbe_rx_buffer *bi;
    u16 i = rx_ring->next_to_use;
    
    /* Nothing to do if no buffers to allocate */
    if (!cleaned_count)
        return;
    
    rx_desc = IXGBE_RX_DESC(rx_ring, i);
    bi = &rx_ring->rx_buffer_info[i];
    
    do {
        /* Allocate a new page if needed */
        if (!bi->page) {
            bi->page = alloc_page(GFP_ATOMIC | __GFP_NOWARN);
            if (!bi->page) {
                rx_ring->rx_stats.alloc_rx_page_failed++;
                break;
            }
            
            /* Map page for DMA */
            bi->dma = dma_map_page(rx_ring->dev, bi->page, 0,
                                   PAGE_SIZE, DMA_FROM_DEVICE);
            
            if (dma_mapping_error(rx_ring->dev, bi->dma)) {
                __free_page(bi->page);
                bi->page = NULL;
                rx_ring->rx_stats.alloc_rx_page_failed++;
                break;
            }
            
            bi->page_offset = 0;
        }
        
        /* Fill descriptor with DMA address */
        rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + bi->page_offset);
        
        /* Move to next descriptor */
        rx_desc++;
        bi++;
        i++;
        if (i == rx_ring->count) {
            rx_desc = IXGBE_RX_DESC(rx_ring, 0);
            bi = rx_ring->rx_buffer_info;
            i = 0;
        }
        
        cleaned_count--;
    } while (cleaned_count);
    
    /* Update tail pointer to give buffers to hardware */
    if (rx_ring->next_to_use != i) {
        rx_ring->next_to_use = i;
        
        /* Force write to memory before updating tail */
        wmb();
        
        /* Write tail register */
        writel(i, rx_ring->tail);
    }
}
```

### DMA Considerations

#### Coherent vs Streaming DMA

**Coherent DMA** (used for descriptor rings):
```c
/* Allocate memory that is cache-coherent between CPU and device */
void *desc = dma_alloc_coherent(dev, size, &dma_handle, GFP_KERNEL);
```
- CPU and device always see the same values
- No explicit cache management needed
- Slower than cached memory
- Used for descriptor rings (frequent hardware access)

**Streaming DMA** (used for packet buffers):
```c
/* Map existing memory for DMA */
dma_addr_t dma = dma_map_single(dev, data, size, direction);

/* Before device reads: */
dma_sync_single_for_device(dev, dma, size, direction);

/* After device writes: */
dma_sync_single_for_cpu(dev, dma, size, direction);
```
- Uses cached memory
- Requires explicit synchronization
- Better performance for large buffers
- Used for packet data

#### Memory Barriers

Ring buffer updates require memory barriers to ensure correct ordering:

```c
/* TX: Before updating tail register */
wmb();  /* Write Memory Barrier: ensure descriptor writes complete */
writel(tx_ring->next_to_use, tx_ring->tail);

/* RX: Before reading descriptor status */
rmb();  /* Read Memory Barrier: ensure status read is fresh */
status = le32_to_cpu(rx_desc->wb.upper.status_error);
```

On AMD64 (x86-64):
- `wmb()` is typically a `sfence` instruction (store fence)
- `rmb()` is often a compiler barrier (loads aren't reordered on x86)
- `mb()` is `mfence` (full memory barrier)

#### Cache Coherency

On cache-coherent systems (like x86-64), hardware ensures:
- Writes to coherent DMA memory are visible to device
- Device writes to memory are visible to CPU
- No explicit cache flushing needed for coherent memory

For streaming DMA on x86-64:
- `dma_sync_single_for_device()`: flushes CPU caches
- `dma_sync_single_for_cpu()`: invalidates CPU caches

#### Physical vs Bus Addresses

```c
/* Virtual address (what driver sees) */
void *vaddr = rx_buffer->page;

/* Physical address (what MMU translates to) */
phys_addr_t phys = virt_to_phys(vaddr);

/* DMA/bus address (what device sees) */
dma_addr_t dma = dma_map_page(dev, page, offset, size, direction);
```

On most systems, `phys == dma`, but:
- **IOMMU**: Can remap physical addresses for isolation
- **Bounce buffers**: Used when device can't access certain memory
- **PAE/PAT**: Physical address extensions may affect mapping

The driver must always use `dma_addr_t` returned by DMA API, never assume physical == bus addresses.

### Ring Management Examples

#### Checking Ring Space (TX)

```c
static bool ixgbe_maybe_stop_tx(struct ixgbe_ring *tx_ring, u16 size)
{
    /* Calculate available descriptors */
    u16 used = tx_ring->next_to_use;
    u16 clean = tx_ring->next_to_clean;
    u16 avail = (clean > used) ? (clean - used - 1) :
                                  (tx_ring->count - used + clean - 1);
    
    if (avail < size) {
        /* Not enough space, stop queue */
        netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);
        return true;
    }
    
    return false;
}
```

#### Wrapping Ring Indices

```c
/* Increment with wrap */
static inline void ixgbe_ring_increment(struct ixgbe_ring *ring, u16 *index)
{
    (*index)++;
    if (*index == ring->count)
        *index = 0;
}

/* Or using modulo (less efficient) */
*index = (*index + 1) % ring->count;

/* Or using mask (requires power-of-2 size) */
*index = (*index + 1) & (ring->count - 1);
```

The ring buffer architecture provides the foundation for efficient packet I/O, enabling high-performance networking with minimal CPU overhead through DMA, batching, and hardware/software parallelism.

## Socket Buffers (sk_buff)

Before diving into packet processing, we need to understand the `struct sk_buff` (commonly called "skb"), which is the fundamental data structure representing network packets throughout the Linux kernel.

### Purpose and Design

The socket buffer serves multiple critical purposes:

1. **Universal packet representation**: From the moment a packet arrives at the NIC until it reaches a socket (or vice versa), it's represented as an skb
2. **Efficient header manipulation**: Protocol layers can add/remove headers without copying packet data
3. **Memory accounting**: Tracks how much memory is consumed by each packet
4. **Metadata carrier**: Holds information about the packet (protocol, checksums, timestamps, etc.)
5. **Zero-copy support**: Can reference external memory (pages) without copying

The skb design philosophy:
- **Headers grow down**: When adding headers, move `data` pointer backward (toward `head`)
- **Data grows up**: When adding payload, move `tail` pointer forward (toward `end`)
- **No reallocation**: Avoid copying data; manipulate pointers instead

### Core Structure Fields

```c
/* From include/linux/skbuff.h (simplified) */
struct sk_buff {
    /* Linked list */
    struct sk_buff *next;
    struct sk_buff *prev;
    
    /* Network device */
    struct net_device *dev;      /* Device we arrived on/departed from */
    int skb_iif;                 /* ifindex of device we arrived on */
    
    /* Timestamps */
    ktime_t tstamp;              /* Time we arrived/left */
    
    /* Buffer pointers - THE MOST IMPORTANT FIELDS */
    unsigned char *head;         /* Start of allocated buffer */
    unsigned char *data;         /* Start of actual data */
    unsigned char *tail;         /* End of actual data */
    unsigned char *end;          /* End of allocated buffer */
    
    /* Sizes */
    unsigned int len;            /* Total length of data (including fragments) */
    unsigned int data_len;       /* Length of data in fragments (not in linear part) */
    unsigned int truesize;       /* Total memory consumed (buffer + sk_buff struct) */
    
    /* Reference counting */
    refcount_t users;            /* User count */
    
    /* Protocol information */
    __be16 protocol;             /* Packet protocol (e.g., ETH_P_IP) */
    __u16 transport_header;      /* Offset to transport header */
    __u16 network_header;        /* Offset to network header */
    __u16 mac_header;            /* Offset to MAC header */
    
    /* Checksum information */
    __wsum csum;                 /* Checksum */
    __u8 ip_summed;              /* Checksum status (CHECKSUM_NONE, CHECKSUM_UNNECESSARY, etc.) */
    
    /* Socket association */
    struct sock *sk;             /* Socket we are owned by */
    
    /* Destructor */
    void (*destructor)(struct sk_buff *skb);
    
    /* Control buffer - protocol private data */
    char cb[48] __aligned(8);    /* Control buffer (TCP, IP, etc. store data here) */
    
    /* More fields follow... */
};
```

#### The Four Key Pointers

Understanding `head`, `data`, `tail`, and `end` is crucial:

```
Memory layout of an skb:

    head                  data        tail           end
     │                     │            │             │
     ▼                     ▼            ▼             ▼
    ┌─────────────────────┬────────────┬─────────────┐
    │   Headroom          │   Data     │  Tailroom   │
    │   (reserved)        │  (packet)  │ (reserved)  │
    └─────────────────────┴────────────┴─────────────┘
    
    ◄──────── Linear buffer allocated ───────────────►

Relationships:
- headroom = data - head      (space before data)
- len = tail - data            (linear data length)
- tailroom = end - tail        (space after data)
- buffer_size = end - head     (total allocated)
```

Example when receiving an Ethernet frame:

```
Initial state (after netdev_alloc_skb with NET_SKB_PAD headroom):

head                    data/tail              end
 │                       │                      │
 ▼                       ▼                      ▼
┌───────────────────────┬──────────────────────┐
│   NET_SKB_PAD (64)    │    Empty             │
└───────────────────────┴──────────────────────┘
 ◄─── Headroom ────────►

After receiving packet and stripping Ethernet header:

head              data           tail         end
 │                 │               │           │
 ▼                 ▼               ▼           ▼
┌─────────────────┬───────────────┬───────────┐
│  ETH_HLEN (14)  │  IP packet    │ Tailroom  │
└─────────────────┴───────────────┴───────────┘
 ◄─ Headroom ────► ◄── len ──────►
```

### Linear vs Non-Linear skbs

#### Linear skbs (Simple Case)

A linear skb has all data in a contiguous buffer:

```c
/* Allocate linear skb */
struct sk_buff *skb = netdev_alloc_skb(netdev, length);

/* Or with headroom */
struct sk_buff *skb = netdev_alloc_skb(netdev, length);
skb_reserve(skb, NET_SKB_PAD);  /* Reserve headroom */
```

Characteristics:
- All packet data between `data` and `tail`
- `data_len == 0` (no paged data)
- Simple and fast for small packets
- Typically used for packets < 256 bytes

Memory layout:
```
┌─────────────────────────────────────────┐
│ sk_buff structure                       │
├─────────────────────────────────────────┤
│ Linear data buffer                      │
│ (head to end)                           │
└─────────────────────────────────────────┘
```

#### Non-Linear skbs (Fragmented)

For large packets, data can be split between a linear part and page fragments:

```c
/* Check if skb has fragments */
if (skb_is_nonlinear(skb)) {
    /* Has page fragments */
    unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
}
```

Characteristics:
- Small linear part (headers)
- Bulk data in page fragments
- `data_len > 0` (paged data count)
- Used for large packets, TSO/GSO, zero-copy RX
- Total length: `len = (tail - data) + data_len`

Memory layout:
```
┌─────────────────────────────────────────┐
│ sk_buff structure                       │
├─────────────────────────────────────────┤
│ Linear buffer (headers only)            │
│ (head to end) - small                   │
├─────────────────────────────────────────┤
│ skb_shared_info                         │
│   nr_frags = 3                          │
│   frags[0] ───────┐                     │
│   frags[1] ───────┼───┐                 │
│   frags[2] ───────┼───┼───┐             │
└───────────────────┼───┼───┼─────────────┘
                    │   │   │
                    ▼   ▼   ▼
              [Page0] [Page1] [Page2]
              (bulk packet data)
```

#### Shared Info Structure

At the end of the linear buffer, there's a `skb_shared_info` structure:

```c
/* From include/linux/skbuff.h */
struct skb_shared_info {
    unsigned char nr_frags;           /* Number of fragments */
    unsigned char tx_flags;           /* Flags for transmission */
    unsigned short gso_size;          /* GSO: size of each segment */
    unsigned short gso_segs;          /* GSO: number of segments */
    unsigned short gso_type;          /* GSO: type (TSO, UFO, etc.) */
    
    struct sk_buff *frag_list;        /* Chain of skbs (rarely used) */
    
    /* Page fragments */
    skb_frag_t frags[MAX_SKB_FRAGS];  /* Fragment array (17 on most systems) */
    
    /* Destructor for fragments */
    void (*destructor)(struct sk_buff *skb);
};

/* Access shared info */
#define skb_shinfo(SKB) ((struct skb_shared_info *)(skb_end_pointer(SKB)))
```

### Page Fragments (skb_frag_t)

Each fragment points to a page (or part of a page):

```c
/* From include/linux/skbuff.h */
typedef struct bio_vec skb_frag_t;

struct bio_vec {
    struct page *bv_page;    /* Page pointer */
    unsigned int bv_len;     /* Length in bytes */
    unsigned int bv_offset;  /* Offset into page */
};
```

Example fragment layout:
```
frag[0]: page=0xffff888100000000, offset=0, len=4096     (full page)
frag[1]: page=0xffff888100001000, offset=0, len=4096     (full page)  
frag[2]: page=0xffff888100002000, offset=0, len=1024     (partial page)

Total fragmented data: 4096 + 4096 + 1024 = 9216 bytes
```

#### How ixgbe Uses Page Fragments for RX

The ixgbe driver builds skbs with page fragments for efficiency:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static struct sk_buff *ixgbe_construct_skb(struct ixgbe_ring *rx_ring,
                                          struct ixgbe_rx_buffer *rx_buffer,
                                          union ixgbe_adv_rx_desc *rx_desc,
                                          unsigned int size)
{
    void *va = page_address(rx_buffer->page) + rx_buffer->page_offset;
    unsigned int headlen;
    struct sk_buff *skb;
    
    /* Allocate skb with headroom */
    skb = napi_alloc_skb(&rx_ring->q_vector->napi, IXGBE_RX_HDR_SIZE);
    if (!skb)
        return NULL;
    
    /* Determine how much to copy to linear part */
    if (size <= IXGBE_RX_HDR_SIZE) {
        /* Small packet - copy everything to linear part */
        memcpy(skb->data, va, size);
        headlen = size;
    } else {
        /* Large packet - copy headers to linear, rest as fragment */
        headlen = eth_get_headlen(skb->dev, va, IXGBE_RX_HDR_SIZE);
        memcpy(skb->data, va, headlen);
    }
    
    /* Update data pointers */
    skb_put(skb, headlen);
    
    /* Add remaining data as page fragment */
    if (size > headlen) {
        skb_add_rx_frag(skb, 0, rx_buffer->page,
                       rx_buffer->page_offset + headlen,
                       size - headlen, truesize);
    }
    
    return skb;
}
```

Benefits of this approach:
- **Small linear part**: Only headers (Ethernet, IP, TCP) in linear buffer
- **Bulk data in pages**: Payload stays in DMA pages
- **No data copying**: Pages can be shared with user space (sendfile)
- **Memory efficiency**: Reuse pages for multiple packets

### Header Management

The skb design allows efficient header addition/removal without data copying:

#### Headroom and Tailroom

```c
/* Check available space */
unsigned int headroom = skb_headroom(skb);  /* data - head */
unsigned int tailroom = skb_tailroom(skb);  /* end - tail */

/* Reserve headroom when allocating */
struct sk_buff *skb = netdev_alloc_skb(dev, size);
skb_reserve(skb, NET_SKB_PAD);  /* Move data pointer forward */
```

#### Adding Headers (skb_push)

```c
/* Add header by moving data pointer backward */
struct ethhdr *eth = (struct ethhdr *)skb_push(skb, ETH_HLEN);

/* What happens internally: */
// data -= ETH_HLEN;
// len += ETH_HLEN;
// return data;

Before skb_push(skb, 14):
head        data              tail     end
 │           │                  │       │
 ▼           ▼                  ▼       ▼
┌───────────┬──────────────────┬───────┐
│ Headroom  │   IP packet      │  ...  │
└───────────┴──────────────────┴───────┘

After skb_push(skb, 14):
head   data                    tail     end
 │      │                       │       │
 ▼      ▼                       ▼       ▼
┌──────┬──────────────────────┬───────┐
│ Head │Eth│  IP packet        │  ...  │
└──────┴──────────────────────┴───────┘
        ◄─► ETH_HLEN (14 bytes)
```

#### Removing Headers (skb_pull)

```c
/* Remove header by moving data pointer forward */
skb_pull(skb, ETH_HLEN);

/* What happens internally: */
// data += ETH_HLEN;
// len -= ETH_HLEN;

Before skb_pull(skb, 14):
head   data                    tail     end
 │      │                       │       │
 ▼      ▼                       ▼       ▼
┌──────┬──────────────────────┬───────┐
│ Head │Eth│  IP packet        │  ...  │
└──────┴──────────────────────┴───────┘

After skb_pull(skb, 14):
head        data              tail     end
 │           │                  │       │
 ▼           ▼                  ▼       ▼
┌───────────┬──────────────────┬───────┐
│ Headroom  │   IP packet      │  ...  │
└───────────┴──────────────────┴───────┘
```

#### Extending Data (skb_put)

```c
/* Add data by moving tail pointer forward */
unsigned char *ptr = skb_put(skb, len);
memcpy(ptr, data, len);

/* What happens internally: */
// tail += len;
// len += len;
// return old_tail;
```

#### Reallocation (pskb_expand_head)

When there's insufficient headroom/tailroom:

```c
/* Reallocate skb with more space */
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp);

/* Example: need more headroom for encapsulation */
if (skb_headroom(skb) < needed) {
    if (pskb_expand_head(skb, needed, 0, GFP_ATOMIC))
        return -ENOMEM;
}
```

This allocates a new buffer, copies data, and updates pointers. **Expensive operation** - avoid when possible.

### Clone vs Copy

#### skb_clone() - Shallow Copy

```c
/* Create a clone: new skb structure, shared data */
struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
```

Memory layout after clone:
```
Original skb                  Cloned skb
┌─────────────┐              ┌─────────────┐
│ sk_buff     │              │ sk_buff     │
│  (metadata) │              │  (metadata) │
├─────────────┤              ├─────────────┤
│  head ──────┼──┐           │  head ──────┼──┐
│  data ──────┼─┐│           │  data ──────┼─┐│
│  tail ──────┼┐││           │  tail ──────┼┐││
│  end ───────┼┘││           │  end ───────┼┘││
└─────────────┘ ││           └─────────────┘ ││
                ││                           ││
                └┼───────────────────────────┘│
                 └────────────────────────────┘
                            │
                            ▼
                  ┌─────────────────┐
                  │ Shared buffer   │
                  │ (reference count)│
                  └─────────────────┘
```

Use cases:
- Sending same packet to multiple destinations
- Queuing packet while processing
- Fast - no data copying

Constraints:
- **Cannot modify data** in clone (shared)
- Can modify metadata (headers, timestamps, etc.)

#### skb_copy() - Deep Copy

```c
/* Create a full copy: new skb + new data buffer */
struct sk_buff *copy = skb_copy(skb, GFP_ATOMIC);
```

Creates completely independent skb with copied data.

Use cases:
- When data needs to be modified
- Crossing protection domains
- Slow but safe

#### pskb_copy() - Partial Copy

```c
/* Copy linear part, share fragments */
struct sk_buff *copy = pskb_copy(skb, GFP_ATOMIC);
```

Use cases:
- Modify headers but keep payload
- Compromise between clone and copy

### Memory Allocation Strategies

#### Per-CPU Caches

The kernel maintains per-CPU skb caches for fast allocation:

```c
/* From net/core/skbuff.c */
static struct kmem_cache *skbuff_head_cache __read_mostly;
static struct kmem_cache *skbuff_fclone_cache __read_mostly;

/* Allocate from cache */
struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp, int flags, int node)
{
    struct sk_buff *skb;
    u8 *data;
    
    /* Get skb from slab cache */
    skb = kmem_cache_alloc_node(cache, gfp, node);
    
    /* Allocate data buffer */
    size = SKB_DATA_ALIGN(size);
    data = kmalloc_reserve(size, gfp, node, NULL);
    
    /* Initialize pointers */
    skb->head = data;
    skb->data = data;
    skb->tail = data;
    skb->end = data + size;
    
    return skb;
}
```

#### NAPI Allocation

During packet reception (NAPI context), use optimized allocation:

```c
/* Allocate skb during NAPI polling */
struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int length)
{
    /* Uses per-CPU cache, GFP_ATOMIC */
    return __napi_alloc_skb(napi, length, GFP_ATOMIC);
}
```

Benefits:
- No locks (per-CPU)
- Fast path allocation
- Proper NUMA awareness

#### Page Pool Mechanism

Modern drivers use page pools for RX buffer management:

```c
/* Page pool configuration */
struct page_pool_params pp_params = {
    .order = 0,                    /* Single pages */
    .flags = PP_FLAG_DMA_MAP,      /* DMA map pages */
    .pool_size = ring_size,        /* Pool size */
    .nid = numa_node,              /* NUMA node */
    .dev = dev,                    /* Device for DMA */
    .dma_dir = DMA_FROM_DEVICE,    /* RX direction */
};

/* Create page pool */
struct page_pool *pool = page_pool_create(&pp_params);

/* Allocate page from pool */
struct page *page = page_pool_alloc_pages(pool, GFP_ATOMIC);
```

Benefits:
- Page recycling (reuse across packets)
- Reduced allocation overhead
- Better cache behavior
- DMA mapping cached

#### How ixgbe Manages skb Allocation

ixgbe uses a hybrid approach:

```c
/* Small packets: allocate linear skb */
if (size <= IXGBE_RX_HDR_SIZE) {
    skb = napi_alloc_skb(&rx_ring->q_vector->napi, size);
    memcpy(skb->data, page_addr, size);
}
/* Large packets: skb + page fragments */
else {
    skb = napi_alloc_skb(&rx_ring->q_vector->napi, IXGBE_RX_HDR_SIZE);
    skb_add_rx_frag(skb, 0, page, offset, size - headlen, truesize);
}
```

This approach:
- Minimizes allocations (small skb + reuse pages)
- Supports zero-copy to user space
- Efficient for mixed workloads

The socket buffer architecture provides the flexible, efficient packet representation needed for high-performance networking while supporting the complex operations required by protocol stacks.

## Packet Arrival Flow

Now that we understand ring buffers and socket buffers, let's trace the complete path of a packet from hardware to the network stack using the ixgbe driver as our example.

### Hardware Interrupt Path

The journey begins when a packet arrives at the NIC:

1. **Packet arrives on the wire** → Physical layer processes signal
2. **NIC receives packet** → MAC layer validates, checks FCS (Frame Check Sequence)
3. **DMA transfer** → NIC DMAs packet to pre-allocated RX buffer in memory
4. **Update descriptor** → NIC writes status to RX descriptor (DD bit set)
5. **Raise interrupt** → NIC signals CPU via MSI-X interrupt

#### ixgbe Interrupt Handler

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static irqreturn_t ixgbe_msix_clean_rings(int irq, void *data)
{
    struct ixgbe_q_vector *q_vector = data;
    
    /* Disable interrupts for this queue (no ACK needed with MSI-X) */
    ixgbe_irq_disable_queues(q_vector->adapter, BIT_ULL(q_vector->v_idx));
    
    /* Schedule NAPI polling */
    napi_schedule_irqoff(&q_vector->napi);
    
    return IRQ_HANDLED;
}
```

Key points:
- **Fast**: Just disable interrupts and schedule NAPI
- **No packet processing**: Deferred to softirq context
- **MSI-X**: Each queue can have its own interrupt vector
- **Returns immediately**: Minimize time in hardirq context

See [Linux Interrupt Handling](linux_interrupts.md) for detailed interrupt handling flow.

### NAPI Polling

NAPI (New API) is the kernel's polling interface for network drivers. It combines interrupts with polling to achieve high performance and prevent interrupt storms.

#### NAPI Structure and Registration

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe.h */
struct ixgbe_q_vector {
    struct ixgbe_adapter *adapter;
    
    int v_idx;                      /* Vector index */
    
    struct napi_struct napi;        /* NAPI structure */
    
    struct ixgbe_ring_container rx, tx;  /* Ring containers */
    
    cpumask_t affinity_mask;       /* CPU affinity */
    int numa_node;                  /* NUMA node */
    
    char name[IFNAMSIZ + 17];      /* Interrupt name */
};
```

The driver registers NAPI during initialization:

```c
static void ixgbe_configure_msix(struct ixgbe_adapter *adapter)
{
    struct ixgbe_q_vector *q_vector;
    int v_idx;
    
    for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
        q_vector = adapter->q_vector[v_idx];
        
        /* Initialize NAPI */
        netif_napi_add(adapter->netdev, &q_vector->napi,
                      ixgbe_poll, 64);  /* 64 = weight/budget */
        
        /* Enable NAPI */
        napi_enable(&q_vector->napi);
    }
}
```

#### NAPI Poll Method

The `poll()` method is the heart of packet reception:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_poll(struct napi_struct *napi, int budget)
{
    struct ixgbe_q_vector *q_vector =
        container_of(napi, struct ixgbe_q_vector, napi);
    struct ixgbe_adapter *adapter = q_vector->adapter;
    int per_ring_budget, work_done = 0;
    bool clean_complete = true;
    
    /* Process TX completions first */
    ixgbe_for_each_ring(ring, q_vector->tx) {
        if (!ixgbe_clean_tx_irq(q_vector, ring, budget))
            clean_complete = false;
    }
    
    /* If TX isn't fully cleaned, use all budget for TX */
    if (!clean_complete)
        return budget;
    
    /* Process RX packets */
    per_ring_budget = max(budget / q_vector->rx.count, 1);
    
    ixgbe_for_each_ring(ring, q_vector->rx) {
        int cleaned = ixgbe_clean_rx_irq(q_vector, ring, per_ring_budget);
        work_done += cleaned;
    }
    
    /* If we cleaned all packets, re-enable interrupts */
    if (work_done < budget) {
        napi_complete_done(napi, work_done);
        
        /* Re-enable interrupts for this queue */
        ixgbe_irq_enable_queues(adapter, BIT_ULL(q_vector->v_idx));
    }
    
    return work_done;
}
```

#### Budget and Weight Concepts

- **Weight**: Maximum packets to process per poll (64 for ixgbe)
- **Budget**: Actual limit passed to poll function
- **Work done**: Actual packets processed

```
NAPI Polling Cycle:

Interrupt arrives
     │
     ▼
Disable interrupts
     │
     ▼
napi_schedule()  ────►  Softirq raised (NET_RX_SOFTIRQ)
                              │
                              ▼
                        net_rx_action()
                              │
                              ├─► poll(budget=64)
                              │        │
                              │        ├─► Process up to 64 packets
                              │        │
                              │        ▼
                              │   work_done < budget?
                              │        │
                              │   YES  │  NO
                              │    │   │   │
                              │    ▼   │   ▼
                              │  Re-enable  Stay in
                              │  interrupts poll mode
                              │    │       │
                              │    ▼       │
                              │  Done  ◄───┘
                              │            (continue polling)
                              ▼
                        Process other devices
```

This hybrid interrupt/polling approach:
- **Low load**: Interrupts for low latency
- **High load**: Polling to avoid interrupt overhead
- **Prevents livelock**: Budget limits CPU time per device

#### napi_schedule() and napi_complete()

```c
/* Schedule NAPI polling */
static inline void napi_schedule(struct napi_struct *n)
{
    if (napi_schedule_prep(n))
        __napi_schedule(n);
}

/* Mark polling complete and re-enable interrupts */
static inline bool napi_complete_done(struct napi_struct *n, int work_done)
{
    /* Check if we can complete */
    if (unlikely(test_bit(NAPI_STATE_NPSVC, &n->state)))
        return false;
    
    /* Clear NAPI scheduled bit */
    if (!__napi_complete(n))
        return false;
    
    /* Trace point for analysis */
    trace_napi_poll(n, work_done);
    
    return true;
}
```

### Packet Processing

The actual packet reception happens in `ixgbe_clean_rx_irq()`:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c (simplified) */
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
                              struct ixgbe_ring *rx_ring,
                              int budget)
{
    unsigned int total_rx_bytes = 0, total_rx_packets = 0;
    u16 cleaned_count = ixgbe_desc_unused(rx_ring);
    
    while (likely(total_rx_packets < budget)) {
        union ixgbe_adv_rx_desc *rx_desc;
        struct ixgbe_rx_buffer *rx_buffer;
        struct sk_buff *skb;
        unsigned int size;
        
        /* Fetch next descriptor */
        rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);
        
        /* Check if descriptor is done (DD bit) */
        if (!ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_DD))
            break;  /* No more packets */
        
        /* Ensure we see updates to descriptor */
        dma_rmb();
        
        /* Get buffer info */
        rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
        size = le16_to_cpu(rx_desc->wb.upper.length);
        
        /* Sync DMA buffer for CPU access */
        dma_sync_single_range_for_cpu(rx_ring->dev, rx_buffer->dma,
                                     rx_buffer->page_offset, size,
                                     DMA_FROM_DEVICE);
        
        /* Build skb from buffer */
        skb = ixgbe_construct_skb(rx_ring, rx_buffer, rx_desc, size);
        if (!skb) {
            rx_ring->rx_stats.alloc_rx_buff_failed++;
            break;
        }
        
        /* Move to next descriptor */
        ixgbe_rx_ring_advance(rx_ring, rx_desc, rx_buffer);
        
        cleaned_count++;
        
        /* Accumulate stats */
        total_rx_bytes += skb->len;
        total_rx_packets++;
        
        /* Set protocol and device */
        skb->protocol = eth_type_trans(skb, rx_ring->netdev);
        
        /* Check hardware checksum */
        ixgbe_rx_checksum(rx_ring, rx_desc, skb);
        
        /* Extract VLAN tag if present */
        ixgbe_process_skb_fields(rx_ring, rx_desc, skb);
        
        /* Pass packet to network stack */
        napi_gro_receive(&q_vector->napi, skb);
    }
    
    /* Update statistics */
    u64_stats_update_begin(&rx_ring->syncp);
    rx_ring->stats.packets += total_rx_packets;
    rx_ring->stats.bytes += total_rx_bytes;
    u64_stats_update_end(&rx_ring->syncp);
    
    /* Refill RX ring */
    if (cleaned_count)
        ixgbe_alloc_rx_buffers(rx_ring, cleaned_count);
    
    return total_rx_packets;
}
```

#### Reading Descriptors

```c
/* Get descriptor */
rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);

/* Check DD (Descriptor Done) bit */
static inline bool ixgbe_test_staterr(union ixgbe_adv_rx_desc *rx_desc,
                                     const u32 stat_err_bits)
{
    return !!(le32_to_cpu(rx_desc->wb.upper.status_error) & stat_err_bits);
}

/* Memory barrier to ensure status is fresh */
dma_rmb();  /* On x86-64, this is typically a compiler barrier */
```

#### Building skb from DMA Buffers

We covered this in the skb section, but here's the flow:

```c
skb = ixgbe_construct_skb(rx_ring, rx_buffer, rx_desc, size);

/* This function: */
// 1. Allocates small skb (napi_alloc_skb)
// 2. Copies headers to linear part
// 3. Attaches page as fragment for bulk data
// 4. Updates page offset for reuse
```

#### Setting Protocol

```c
/* Determine packet type from Ethernet header */
skb->protocol = eth_type_trans(skb, rx_ring->netdev);
```

This function:
1. Reads Ethernet header
2. Sets `skb->protocol` (e.g., `ETH_P_IP`, `ETH_P_IPV6`)
3. Removes Ethernet header (moves `data` pointer forward)
4. Sets `skb->pkt_type` (PACKET_HOST, PACKET_BROADCAST, etc.)

#### Hardware Offload Features

##### Checksum Offload (RX)

```c
static void ixgbe_rx_checksum(struct ixgbe_ring *ring,
                              union ixgbe_adv_rx_desc *rx_desc,
                              struct sk_buff *skb)
{
    /* Skip checksum if not IP packet */
    if (!(ring->netdev->features & NETIF_F_RXCSUM))
        return;
    
    /* Check if hardware validated checksum */
    if (ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_IPCS)) {
        /* IP checksum verified */
        if (!ixgbe_test_staterr(rx_desc, IXGBE_RXDADV_ERR_IPE))
            skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
    
    /* Check L4 checksum (TCP/UDP) */
    if (ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_L4CS)) {
        if (!ixgbe_test_staterr(rx_desc, IXGBE_RXDADV_ERR_TCPE))
            skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
}
```

Checksum values:
- `CHECKSUM_NONE`: Software must verify
- `CHECKSUM_UNNECESSARY`: Hardware verified (fast path)
- `CHECKSUM_COMPLETE`: Hardware provides full checksum

##### VLAN Tag Extraction

```c
static void ixgbe_process_skb_fields(struct ixgbe_ring *rx_ring,
                                    union ixgbe_adv_rx_desc *rx_desc,
                                    struct sk_buff *skb)
{
    /* Extract VLAN tag from descriptor */
    if (ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_VP)) {
        u16 vid = le16_to_cpu(rx_desc->wb.upper.vlan);
        __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
    }
    
    /* Set RSS hash */
    ixgbe_rx_hash(rx_ring, rx_desc, skb);
    
    /* Set RX timestamp (if PTP enabled) */
    ixgbe_ptp_rx_hwtstamp(rx_ring, rx_desc, skb);
}
```

#### Passing to Network Stack

##### GRO (Generic Receive Offload)

```c
/* Pass packet with GRO */
napi_gro_receive(&q_vector->napi, skb);
```

GRO (Generic Receive Offload) aggregates multiple packets into one large packet before passing to the network stack:

```
Without GRO:
RX: [pkt1] [pkt2] [pkt3] [pkt4]  → TCP stack processes 4 packets

With GRO:
RX: [pkt1] [pkt2] [pkt3] [pkt4]  → Merge → [big_pkt] → TCP stack processes 1 packet
```

Benefits:
- Fewer trips through network stack
- Better cache utilization
- Reduced per-packet overhead
- Can achieve 2-3x throughput improvement

##### Direct Receive (without GRO)

```c
/* Pass packet directly */
netif_receive_skb(skb);
```

This enters the network stack at the protocol demultiplex layer.

### Complete Packet Flow Diagram

```
                      Packet Arrival
                           │
                           ▼
┌─────────────────────────────────────────────────┐
│  1. NIC: Packet arrives, DMA to memory          │
│     - Match filter rules                        │
│     - DMA to pre-allocated RX buffer            │
│     - Update descriptor (set DD bit)            │
│     - Raise MSI-X interrupt                     │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  2. Hardirq: ixgbe_msix_clean_rings()           │
│     - Disable interrupts                        │
│     - napi_schedule()                           │
│     - Return IRQ_HANDLED                        │
│     - Duration: <1 μs                           │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  3. Softirq: NET_RX_SOFTIRQ raised              │
│     - net_rx_action() calls poll methods        │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  4. NAPI Poll: ixgbe_poll()                     │
│     - Budget = 64 packets                       │
│     - Process up to budget                      │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  5. RX Processing: ixgbe_clean_rx_irq()         │
│     - Read RX descriptors                       │
│     - Check DD bit                              │
│     - Build skb from buffer                     │
│     - Set protocol                              │
│     - Check checksum (offload)                  │
│     - Extract VLAN (if present)                 │
│     - Duration: ~1-10 μs per packet             │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  6. GRO: napi_gro_receive()                     │
│     - Try to merge with existing flow           │
│     - Or create new flow                        │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  7. Network Stack: netif_receive_skb()          │
│     - Protocol handlers (IP, IPv6, ARP, etc.)   │
│     - Routing decision                          │
│     - Transport layer (TCP, UDP)                │
│     - Socket delivery                           │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│  8. Application: recv()/read()                  │
│     - Data available in socket buffer           │
│     - Application processes packet              │
└─────────────────────────────────────────────────┘
```

### Performance Considerations

Typical timings on modern hardware (10GbE, 3GHz CPU):

- Interrupt latency: 0.5-1 μs
- Hardirq handler: <1 μs
- Per-packet processing: 1-10 μs (depends on size, offloads)
- Total packet latency (wire to socket): 10-50 μs

At 10 Gbps with 1500-byte packets:
- Line rate: ~812,000 packets/second
- Time per packet: ~1.23 μs
- CPU budget: ~3,700 cycles per packet (at 3 GHz)

This tight timing shows why optimizations matter:
- DMA reduces copying
- NAPI reduces interrupts
- GRO reduces per-packet overhead
- Hardware offloads save CPU cycles

The packet arrival flow demonstrates how the ixgbe driver efficiently moves packets from hardware to the network stack using interrupts, NAPI polling, and hardware offloads.

## Packet Transmission

Packet transmission is the reverse path: from the network stack through the driver to the NIC. The process is more complex than reception because it involves queue management, flow control, and completion tracking.

### From Network Stack

The network stack calls the driver's `ndo_start_xmit()` function when it has a packet to send:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static netdev_tx_t ixgbe_xmit_frame(struct sk_buff *skb,
                                   struct net_device *netdev)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    struct ixgbe_ring *tx_ring;
    
    /* Select TX queue */
    tx_ring = adapter->tx_ring[skb->queue_mapping];
    
    return ixgbe_xmit_frame_ring(skb, adapter, tx_ring);
}
```

#### Queue Selection (Multi-queue)

Modern NICs have multiple TX queues for parallelism:

```c
/* Network stack selects queue before calling xmit */
u16 queue_index = skb_get_queue_mapping(skb);

/* ixgbe has multiple TX queues (typically 64-128) */
tx_ring = adapter->tx_ring[queue_index];
```

Queue selection strategies:
- **By CPU**: Each CPU has its own queue (no locking needed)
- **By flow**: Flows hashed to queues (maintain order)
- **By priority**: QoS classes get dedicated queues

### Descriptor Setup

The actual transmission happens in `ixgbe_xmit_frame_ring()`:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c (simplified) */
static netdev_tx_t ixgbe_xmit_frame_ring(struct sk_buff *skb,
                                        struct ixgbe_adapter *adapter,
                                        struct ixgbe_ring *tx_ring)
{
    struct ixgbe_tx_buffer *first;
    int tso, count;
    u32 tx_flags = 0;
    u16 first_idx;
    
    /* Check for sufficient ring space */
    count = ixgbe_xmit_descriptor_count(skb);
    if (ixgbe_maybe_stop_tx(tx_ring, count + 3)) {
        tx_ring->tx_stats.tx_busy++;
        return NETDEV_TX_BUSY;
    }
    
    /* Record first descriptor index */
    first_idx = tx_ring->next_to_use;
    first = &tx_ring->tx_buffer_info[first_idx];
    first->skb = skb;
    first->bytecount = skb->len;
    first->gso_segs = 1;
    
    /* Extract VLAN tag if present */
    if (skb_vlan_tag_present(skb)) {
        tx_flags |= skb_vlan_tag_get(skb) << IXGBE_TX_FLAGS_VLAN_SHIFT;
        tx_flags |= IXGBE_TX_FLAGS_VLAN;
    }
    
    /* Check for TSO (TCP Segmentation Offload) */
    tso = ixgbe_tso(tx_ring, first, &tx_flags);
    if (tso < 0)
        goto out_drop;
    else if (!tso)
        ixgbe_tx_csum(tx_ring, first, tx_flags);
    
    /* Map skb to DMA and build descriptors */
    ixgbe_tx_map(tx_ring, first, tx_flags);
    
    return NETDEV_TX_OK;
    
out_drop:
    dev_kfree_skb_any(skb);
    first->skb = NULL;
    return NETDEV_TX_OK;
}
```

#### Counting Descriptors Needed

```c
static int ixgbe_xmit_descriptor_count(struct sk_buff *skb)
{
    int count = 0;
    
    /* Linear part needs one descriptor */
    count += (skb_headlen(skb) + IXGBE_MAX_DATA_PER_TXD - 1) /
             IXGBE_MAX_DATA_PER_TXD;
    
    /* Each fragment needs descriptors */
    for (f = 0; f < skb_shinfo(skb)->nr_frags; f++) {
        unsigned int size = skb_frag_size(&skb_shinfo(skb)->frags[f]);
        count += (size + IXGBE_MAX_DATA_PER_TXD - 1) / IXGBE_MAX_DATA_PER_TXD;
    }
    
    return count;
}

/* Maximum data per TX descriptor (typically 16KB) */
#define IXGBE_MAX_DATA_PER_TXD  (1u << 14)
```

Large packets may need multiple descriptors if they exceed the per-descriptor limit.

### DMA Mapping

The driver must map the skb for DMA before the hardware can access it:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static void ixgbe_tx_map(struct ixgbe_ring *tx_ring,
                        struct ixgbe_tx_buffer *first,
                        const u32 tx_flags)
{
    struct sk_buff *skb = first->skb;
    struct ixgbe_tx_buffer *tx_buffer;
    union ixgbe_adv_tx_desc *tx_desc;
    dma_addr_t dma;
    unsigned int data_len, size;
    u32 cmd_type, olinfo_status;
    u16 i;
    
    cmd_type = ixgbe_tx_cmd_type(skb, tx_flags);
    olinfo_status = ixgbe_tx_olinfo_status(skb, tx_flags);
    
    i = tx_ring->next_to_use;
    tx_desc = IXGBE_TX_DESC(tx_ring, i);
    
    /* Map linear part */
    size = skb_headlen(skb);
    data_len = skb->data_len;
    
    dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);
    
    tx_buffer = first;
    
    /* Fill descriptor for linear part */
    for (;;) {
        if (dma_mapping_error(tx_ring->dev, dma))
            goto dma_error;
        
        /* Record DMA address and length */
        dma_unmap_addr_set(tx_buffer, dma, dma);
        dma_unmap_len_set(tx_buffer, len, size);
        
        /* Fill TX descriptor */
        tx_desc->read.buffer_addr = cpu_to_le64(dma);
        tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type | size);
        tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
        
        /* Move to next descriptor */
        tx_desc++;
        tx_buffer++;
        i++;
        if (i == tx_ring->count) {
            tx_desc = IXGBE_TX_DESC(tx_ring, 0);
            i = 0;
        }
        
        /* Process fragments */
        if (data_len == 0)
            break;
        
        /* Get next fragment */
        const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
        size = skb_frag_size(frag);
        data_len -= size;
        
        /* Map fragment */
        dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size, DMA_TO_DEVICE);
    }
    
    /* Set EOP (End of Packet) on last descriptor */
    cmd_type |= IXGBE_TXD_CMD_EOP;
    tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type | size);
    
    /* Set RS (Report Status) for completion notification */
    tx_desc->read.cmd_type_len |= cpu_to_le32(IXGBE_TXD_CMD_RS);
    
    /* Store last descriptor for completion check */
    first->next_to_watch = tx_desc;
    
    /* Update next_to_use */
    tx_ring->next_to_use = i;
    
    /* Prevent tail from catching head (check for ring full) */
    ixgbe_maybe_stop_tx(tx_ring, DESC_NEEDED);
    
    /* Write memory barrier */
    wmb();
    
    /* Notify hardware: write tail register */
    writel(i, tx_ring->tail);
    
    return;
    
dma_error:
    /* Unmap any successfully mapped buffers */
    dev_err(tx_ring->dev, "TX DMA map failed\n");
    
    /* Free skb */
    dev_kfree_skb_any(first->skb);
    first->skb = NULL;
}
```

Key steps:
1. **Map linear part**: `dma_map_single()` for main data
2. **Map fragments**: `skb_frag_dma_map()` for each page fragment
3. **Fill descriptors**: Write DMA addresses to descriptors
4. **Set flags**: EOP (End of Packet), RS (Report Status)
5. **Memory barrier**: `wmb()` ensures writes complete
6. **Update tail**: Write to tail register triggers NIC

#### DMA Mapping Types

```c
/* Single buffer mapping */
dma_addr_t dma = dma_map_single(dev, ptr, size, DMA_TO_DEVICE);

/* Page fragment mapping */
dma_addr_t dma = skb_frag_dma_map(dev, frag, offset, size, DMA_TO_DEVICE);

/* Later unmapped in completion: */
dma_unmap_single(dev, dma, size, DMA_TO_DEVICE);
dma_unmap_page(dev, dma, size, DMA_TO_DEVICE);
```

### TX Completion and Interrupts

After the NIC transmits packets, it needs to notify the driver so buffers can be freed.

#### TX Completion Interrupt

The NIC raises an interrupt when descriptors with RS (Report Status) bit are transmitted:

```c
/* TX completion is handled in NAPI poll */
static int ixgbe_poll(struct napi_struct *napi, int budget)
{
    /* ... */
    
    /* Clean TX completions */
    ixgbe_for_each_ring(ring, q_vector->tx) {
        if (!ixgbe_clean_tx_irq(q_vector, ring, budget))
            clean_complete = false;
    }
    
    /* ... */
}
```

#### Freeing Transmitted Buffers

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static bool ixgbe_clean_tx_irq(struct ixgbe_q_vector *q_vector,
                               struct ixgbe_ring *tx_ring,
                               int napi_budget)
{
    struct ixgbe_tx_buffer *tx_buffer;
    union ixgbe_adv_tx_desc *tx_desc;
    unsigned int total_bytes = 0, total_packets = 0;
    unsigned int budget = q_vector->tx.work_limit;
    u16 i = tx_ring->next_to_clean;
    
    tx_buffer = &tx_ring->tx_buffer_info[i];
    tx_desc = IXGBE_TX_DESC(tx_ring, i);
    
    while (budget--) {
        union ixgbe_adv_tx_desc *eop_desc = tx_buffer->next_to_watch;
        
        /* Check if this packet is complete */
        if (!eop_desc)
            break;
        
        /* Prevent speculative reads before checking DD bit */
        read_barrier_depends();
        
        /* Check DD (Descriptor Done) bit on EOP descriptor */
        if (!(eop_desc->wb.status & cpu_to_le32(IXGBE_TXD_STAT_DD)))
            break;
        
        /* Clear next_to_watch */
        tx_buffer->next_to_watch = NULL;
        
        /* Accumulate stats */
        total_bytes += tx_buffer->bytecount;
        total_packets += tx_buffer->gso_segs;
        
        /* Unmap and free buffers for this packet */
        do {
            union ixgbe_adv_tx_desc *desc = IXGBE_TX_DESC(tx_ring, i);
            struct ixgbe_tx_buffer *buf = &tx_ring->tx_buffer_info[i];
            
            /* Check for EOP */
            bool eop = (desc == eop_desc);
            
            /* Unmap DMA */
            if (dma_unmap_len(buf, len)) {
                if (buf->skb)
                    dma_unmap_single(tx_ring->dev,
                                   dma_unmap_addr(buf, dma),
                                   dma_unmap_len(buf, len),
                                   DMA_TO_DEVICE);
                else
                    dma_unmap_page(tx_ring->dev,
                                  dma_unmap_addr(buf, dma),
                                  dma_unmap_len(buf, len),
                                  DMA_TO_DEVICE);
                
                dma_unmap_len_set(buf, len, 0);
            }
            
            /* Free skb on last descriptor */
            if (eop && buf->skb) {
                napi_consume_skb(buf->skb, napi_budget);
                buf->skb = NULL;
            }
            
            /* Move to next descriptor */
            i++;
            if (i == tx_ring->count)
                i = 0;
            
            if (eop)
                break;
        } while (true);
        
        /* Move to next packet */
        tx_buffer = &tx_ring->tx_buffer_info[i];
    }
    
    /* Update clean pointer */
    tx_ring->next_to_clean = i;
    
    /* Update statistics */
    u64_stats_update_begin(&tx_ring->syncp);
    tx_ring->stats.bytes += total_bytes;
    tx_ring->stats.packets += total_packets;
    u64_stats_update_end(&tx_ring->syncp);
    
    /* Check if queue was stopped and can be restarted */
    if (unlikely(total_packets && netif_carrier_ok(tx_ring->netdev) &&
                 ixgbe_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD)) {
        /* Wake queue if it was stopped */
        if (__netif_subqueue_stopped(tx_ring->netdev, tx_ring->queue_index) &&
            !test_bit(__IXGBE_DOWN, &adapter->state)) {
            netif_wake_subqueue(tx_ring->netdev, tx_ring->queue_index);
            ++tx_ring->tx_stats.restart_queue;
        }
    }
    
    return !!budget;
}
```

### Flow Control

Flow control prevents the driver from overwhelming the TX ring when it's full.

#### Stopping the Queue

```c
static bool ixgbe_maybe_stop_tx(struct ixgbe_ring *tx_ring, u16 size)
{
    if (likely(ixgbe_desc_unused(tx_ring) >= size))
        return false;
    
    /* Not enough space - stop queue */
    netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);
    
    /* Double-check after setting stop bit (race with TX completion) */
    smp_mb();
    
    /* Check again - TX completion may have freed space */
    if (likely(ixgbe_desc_unused(tx_ring) < size))
        return true;
    
    /* Space became available - restart queue */
    netif_wake_subqueue(tx_ring->netdev, tx_ring->queue_index);
    ++tx_ring->tx_stats.restart_queue;
    
    return false;
}
```

#### Waking the Queue

In TX completion (above), the queue is woken when sufficient space is available:

```c
if (ixgbe_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD) {
    netif_wake_subqueue(tx_ring->netdev, tx_ring->queue_index);
}
```

Typical threshold: 2 * `MAX_SKB_FRAGS` (ensure large packets can be queued).

#### Per-Queue vs Global Control

```c
/* Stop specific queue (multi-queue) */
netif_stop_subqueue(netdev, queue_index);
netif_wake_subqueue(netdev, queue_index);

/* Stop all queues (single-queue or global) */
netif_stop_queue(netdev);
netif_wake_queue(netdev);

/* Check if stopped */
if (netif_queue_stopped(netdev)) {
    /* Queue is stopped */
}
```

Modern NICs use per-queue control for fine-grained parallelism.

### Backpressure Handling

When the queue is full, the network stack receives `NETDEV_TX_BUSY`:

```c
if (ixgbe_maybe_stop_tx(tx_ring, count + 3)) {
    tx_ring->tx_stats.tx_busy++;
    return NETDEV_TX_BUSY;
}
```

The network stack will:
1. Requeue the packet
2. Stop sending to this queue
3. Wait for `netif_wake_subqueue()` call

This creates backpressure through the stack:
```
Application send()
      ↓
Socket buffer (sk_buff)
      ↓
TCP (may slow down send window)
      ↓
IP
      ↓
Qdisc (traffic control)
      ↓
Driver (returns NETDEV_TX_BUSY)
      ↓
Queue full - BACKPRESSURE ↑
```

### TX Flow Diagram

```
Application send()
     │
     ▼
┌─────────────────────────────────────────┐
│ Network Stack                           │
│  - Socket layer                         │
│  - TCP/UDP                              │
│  - IP routing                           │
│  - Queue discipline (qdisc)             │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ Driver: ixgbe_xmit_frame()             │
│  1. Check ring space                    │
│  2. Map skb to DMA                      │
│  3. Fill TX descriptors                 │
│  4. Set EOP, RS bits                    │
│  5. wmb() memory barrier                │
│  6. Write tail register                 │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ Hardware: NIC                           │
│  1. Read descriptors (from tail)        │
│  2. DMA packet data from memory         │
│  3. Add Ethernet FCS                    │
│  4. Transmit on wire                    │
│  5. Write back status (DD bit)          │
│  6. Raise interrupt (if RS set)         │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ Interrupt / NAPI                        │
│  - ixgbe_msix_clean_rings()            │
│  - Schedule NAPI                        │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ TX Completion: ixgbe_clean_tx_irq()    │
│  1. Check DD bit on descriptors         │
│  2. Unmap DMA buffers                   │
│  3. Free skb                            │
│  4. Wake queue if space available       │
│  5. Update statistics                   │
└─────────────────────────────────────────┘
```

### Performance Optimization Techniques

#### Batching

Instead of notifying hardware for every packet:
```c
/* Set RS bit every N packets */
#define IXGBE_TX_FLAGS_RS_SHIFT  17

if ((tx_ring->next_to_use - first_idx) >= 32) {
    cmd_type |= IXGBE_TXD_CMD_RS;  /* Request completion */
}
```

This reduces completion interrupts by ~32x.

#### Byte Queue Limits (BQL)

BQL dynamically adjusts queue size to minimize latency:
```c
/* Before transmission */
netdev_tx_sent_queue(txq, skb->len);

/* After completion */
netdev_tx_completed_queue(txq, packets, bytes);
```

BQL automatically tunes queue size for optimal latency/throughput tradeoff.

#### TX Descriptor Prefetching

```c
/* Prefetch next descriptor */
prefetch(&tx_ring->tx_buffer_info[i]);
```

Helps hide memory latency during ring traversal.

Packet transmission demonstrates the complexity of managing hardware resources while maintaining high performance and correct flow control through the networking stack.

## Hardware Features and Offloads

Modern NICs like the Intel 82599 (ixgbe) provide hardware acceleration for common networking tasks, offloading work from the CPU and improving performance significantly.

### Checksum Offload

#### TX Checksum Offload

The driver can request the NIC to calculate and insert checksums:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_tx_csum(struct ixgbe_ring *tx_ring,
                        struct ixgbe_tx_buffer *first,
                        u32 tx_flags)
{
    struct sk_buff *skb = first->skb;
    u32 vlan_macip_lens = 0;
    u32 type_tucmd = 0;
    
    if (skb->ip_summed != CHECKSUM_PARTIAL)
        return 0;  /* No offload needed */
    
    /* Determine protocol */
    switch (skb->protocol) {
    case htons(ETH_P_IP):
        type_tucmd = IXGBE_ADVTXD_TUCMD_IPV4;
        /* Get IP header */
        struct iphdr *iph = ip_hdr(skb);
        vlan_macip_lens |= (iph->ihl << IXGBE_ADVTXD_MACLEN_SHIFT);
        
        /* Determine L4 protocol */
        switch (iph->protocol) {
        case IPPROTO_TCP:
            type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
            break;
        case IPPROTO_UDP:
            type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_UDP;
            break;
        case IPPROTO_SCTP:
            type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_SCTP;
            break;
        }
        break;
        
    case htons(ETH_P_IPV6):
        /* IPv6 header is always 40 bytes */
        vlan_macip_lens |= (sizeof(struct ipv6hdr) << IXGBE_ADVTXD_MACLEN_SHIFT);
        
        /* Determine L4 protocol from IPv6 */
        struct ipv6hdr *ipv6h = ipv6_hdr(skb);
        switch (ipv6h->nexthdr) {
        case IPPROTO_TCP:
            type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
            break;
        case IPPROTO_UDP:
            type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_UDP;
            break;
        case IPPROTO_SCTP:
            type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_SCTP;
            break;
        }
        break;
        
    default:
        return -1;  /* Unknown protocol */
    }
    
    /* Set MAC header length */
    vlan_macip_lens |= skb_network_offset(skb) << IXGBE_ADVTXD_MACLEN_SHIFT;
    
    /* Store in first descriptor */
    first->tx_flags |= IXGBE_TX_FLAGS_CSUM;
    first->vlan_macip_lens = vlan_macip_lens;
    first->type_tucmd = type_tucmd;
    
    return 0;
}
```

The hardware will:
1. Parse headers based on offsets
2. Calculate IP header checksum
3. Calculate TCP/UDP/SCTP checksum
4. Insert checksums before transmission

Benefits:
- Saves ~100-200 CPU cycles per packet
- Especially valuable for small packets
- Enables higher throughput

#### RX Checksum Offload

We covered this earlier, but here's the detail:

```c
static void ixgbe_rx_checksum(struct ixgbe_ring *ring,
                              union ixgbe_adv_rx_desc *rx_desc,
                              struct sk_buff *skb)
{
    u32 status_err = le32_to_cpu(rx_desc->wb.upper.status_error);
    
    /* Skip if feature disabled */
    if (!(ring->netdev->features & NETIF_F_RXCSUM))
        return;
    
    /* Initialize to none */
    skb->ip_summed = CHECKSUM_NONE;
    
    /* Check for IP checksum error */
    if (status_err & IXGBE_RXD_STAT_IPCS) {
        if (status_err & IXGBE_RXDADV_ERR_IPE) {
            ring->rx_stats.csum_err++;
            return;
        }
        ring->rx_stats.csum_good++;
    }
    
    /* Check for L4 checksum */
    if (!(status_err & IXGBE_RXD_STAT_L4CS))
        return;
    
    if (status_err & IXGBE_RXDADV_ERR_TCPE) {
        /* L4 checksum error */
        ring->rx_stats.csum_err++;
        return;
    }
    
    /* Checksum verified by hardware */
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    ring->rx_stats.csum_good++;
}
```

`CHECKSUM_UNNECESSARY` tells the network stack to skip software validation.

### TSO (TCP Segmentation Offload)

TSO allows the network stack to pass a large TCP segment (up to 64KB) to the driver, which programs the hardware to split it into MSS-sized packets.

#### TSO Concept

```
Without TSO:
Software: [64KB TCP segment]
            ↓ (TCP segments into MSS packets)
       [1460][1460][1460]...[1460]  (44 packets)
            ↓ (each transmitted separately)
       Hardware transmits 44 packets

With TSO:
Software: [64KB TCP segment]
            ↓ (pass to hardware as one)
       Hardware: [64KB] → splits into 44 packets automatically
```

Benefits:
- 44x fewer trips through network stack
- Fewer interrupts
- Less CPU usage
- Higher throughput

#### TSO Implementation (ixgbe)

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_tso(struct ixgbe_ring *tx_ring,
                     struct ixgbe_tx_buffer *first,
                     u32 *tx_flags)
{
    struct sk_buff *skb = first->skb;
    u32 vlan_macip_lens, type_tucmd, mss_l4len_idx;
    int err;
    
    /* Check if TSO is needed */
    if (!skb_is_gso(skb))
        return 0;
    
    /* Validate headers */
    err = skb_cow_head(skb, 0);
    if (err < 0)
        return err;
    
    /* Initialize fields */
    vlan_macip_lens = 0;
    type_tucmd = 0;
    
    /* Get IP header info */
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    
    if (skb->protocol == htons(ETH_P_IP)) {
        /* IPv4 */
        type_tucmd = IXGBE_ADVTXD_TUCMD_IPV4;
        
        /* Clear IP checksum (hardware will recalculate for each segment) */
        iph->check = 0;
        
        /* TCP checksum is pseudo-header only */
        tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
                                         0, IPPROTO_TCP, 0);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        /* IPv6 */
        struct ipv6hdr *ipv6h = ipv6_hdr(skb);
        
        /* TCP checksum is pseudo-header only */
        tcph->check = ~csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
                                       0, IPPROTO_TCP, 0);
    }
    
    /* Set protocol type */
    type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
    
    /* Build context descriptor fields */
    vlan_macip_lens |= skb_network_offset(skb) << IXGBE_ADVTXD_MACLEN_SHIFT;
    vlan_macip_lens |= skb_network_header_len(skb);
    
    /* MSS (Maximum Segment Size) and header lengths */
    mss_l4len_idx = (skb_shinfo(skb)->gso_size << IXGBE_ADVTXD_MSS_SHIFT);
    mss_l4len_idx |= (tcp_hdrlen(skb) << IXGBE_ADVTXD_L4LEN_SHIFT);
    
    /* Store TSO info */
    first->gso_segs = skb_shinfo(skb)->gso_segs;
    first->bytecount = skb->len;
    first->tx_flags |= IXGBE_TX_FLAGS_TSO;
    
    /* Write context descriptor */
    ixgbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, type_tucmd, mss_l4len_idx);
    
    return 1;
}
```

The hardware:
1. Reads the large segment
2. Splits into MSS-sized packets
3. Adjusts IP length, IP ID, TCP sequence numbers
4. Calculates checksums for each packet
5. Transmits all packets

### GSO (Generic Segmentation Offload)

GSO is TSO's software counterpart - segmentation happens in the kernel before reaching the driver:

```c
/* Network stack checks if device supports TSO */
if (netdev->features & NETIF_F_TSO) {
    /* Pass large segment to driver (TSO) */
    dev_queue_xmit(skb);
} else {
    /* Segment in software (GSO) */
    struct sk_buff *segs = __skb_gso_segment(skb, features);
    /* Send each segment */
}
```

Benefits:
- Same API for drivers with/without TSO
- Protocol stack only processes large segment once
- Segmentation happens late (right before driver)

### GRO (Generic Receive Offload)

GRO is the receive counterpart to GSO - it aggregates received packets:

```c
/* Pass to GRO */
napi_gro_receive(&q_vector->napi, skb);
```

#### GRO Aggregation

```c
/* From net/core/dev.c (simplified) */
static void napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
    skb_list_del_init(skb);
    
    /* Try to merge with existing flow */
    if (napi_gro_complete(skb) != GRO_NORMAL) {
        /* Merged - don't pass up yet */
        return;
    }
    
    /* New flow or can't merge - pass to stack */
    netif_receive_skb_internal(skb);
}
```

GRO matches packets by:
- Source/destination IP
- Source/destination port  
- TCP sequence numbers (must be consecutive)

Aggregated packet:
```
Received: [pkt1: seq=100, len=1460]
          [pkt2: seq=1560, len=1460]
          [pkt3: seq=3020, len=1460]
          
GRO creates: [big_pkt: seq=100, len=4380]
            (3 packets merged into 1)
```

The network stack processes one large packet instead of three small ones.

Constraints:
- Must be same flow
- Sequential TCP data
- No special flags (PSH, URG, etc.)
- Limited aggregation time (typically next NAPI poll)

### RSS (Receive Side Scaling)

RSS distributes incoming packets across multiple RX queues (and CPUs) based on a hash of packet headers.

#### RSS Configuration (ixgbe)

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static void ixgbe_setup_rss(struct ixgbe_adapter *adapter)
{
    struct ixgbe_hw *hw = &adapter->hw;
    u32 mrqc = 0;
    u32 rss_key[10];
    u32 reta = 0;
    int i, j;
    
    /* Generate random RSS key */
    netdev_rss_key_fill(rss_key, sizeof(rss_key));
    
    /* Write RSS key to NIC */
    for (i = 0; i < 10; i++)
        IXGBE_WRITE_REG(hw, IXGBE_RSSRK(i), rss_key[i]);
    
    /* Setup redirection table (which queue for each hash value) */
    for (i = 0, j = 0; i < 128; i++, j++) {
        if (j == adapter->ring_feature[RING_F_RSS].indices)
            j = 0;
        
        /* 4 entries per register */
        reta |= (j << (i & 0x3) * 8);
        
        if ((i & 3) == 3) {
            IXGBE_WRITE_REG(hw, IXGBE_RETA(i >> 2), reta);
            reta = 0;
        }
    }
    
    /* Enable RSS for IPv4/IPv6 TCP/UDP */
    mrqc = IXGBE_MRQC_RSSEN;
    mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4 |
            IXGBE_MRQC_RSS_FIELD_IPV4_TCP |
            IXGBE_MRQC_RSS_FIELD_IPV4_UDP |
            IXGBE_MRQC_RSS_FIELD_IPV6 |
            IXGBE_MRQC_RSS_FIELD_IPV6_TCP |
            IXGBE_MRQC_RSS_FIELD_IPV6_UDP;
    
    IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);
}
```

#### RSS Hash Calculation

The NIC calculates a hash:
```
hash = Toeplitz(secret_key, src_ip, dst_ip, src_port, dst_port)
queue = redirection_table[hash % 128]
```

Benefits:
- Packets from same flow go to same queue (same CPU)
- Flows distributed across CPUs
- Better cache locality
- Parallelism for multi-flow workloads

#### Setting RX Queue Affinity

```bash
# CPU 0 handles queue 0
echo 1 > /proc/irq/125/smp_affinity

# CPU 1 handles queue 1  
echo 2 > /proc/irq/126/smp_affinity
```

Each CPU can process its queue independently, scaling with core count.

### VLAN Offload

#### VLAN Tag Insertion (TX)

```c
/* Check for VLAN tag */
if (skb_vlan_tag_present(skb)) {
    u16 vlan_tci = skb_vlan_tag_get(skb);
    
    /* Store in descriptor */
    tx_flags |= vlan_tci << IXGBE_TX_FLAGS_VLAN_SHIFT;
    tx_flags |= IXGBE_TX_FLAGS_VLAN;
    
    /* Hardware will insert 802.1Q tag */
}
```

The NIC inserts the 4-byte VLAN tag between Ethernet header and payload.

#### VLAN Tag Stripping (RX)

```c
/* Hardware strips VLAN tag and puts in descriptor */
if (ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_VP)) {
    u16 vid = le16_to_cpu(rx_desc->wb.upper.vlan);
    __vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
}
```

The VLAN tag is removed from packet data and stored in skb metadata.

#### VLAN Filtering

```c
/* Configure VLAN filter */
static int ixgbe_vlan_rx_add_vid(struct net_device *netdev,
                                 __be16 proto, u16 vid)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    struct ixgbe_hw *hw = &adapter->hw;
    
    /* Set VLAN filter bit */
    ixgbe_set_vfta(hw, vid, VMDQ_P(0), true);
    
    set_bit(vid, adapter->active_vlans);
    
    return 0;
}
```

The NIC can filter packets by VLAN ID, dropping unwanted VLANs in hardware.

### Feature Negotiation with ethtool

Features are advertised and negotiated:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static void ixgbe_set_netdev_features(struct ixgbe_adapter *adapter)
{
    struct net_device *netdev = adapter->netdev;
    netdev_features_t features;
    
    /* Hardware features */
    features = NETIF_F_SG |              /* Scatter-gather */
               NETIF_F_TSO |             /* TCP Segmentation Offload */
               NETIF_F_TSO6 |            /* TSO for IPv6 */
               NETIF_F_RXHASH |          /* RX hash (RSS) */
               NETIF_F_RXCSUM |          /* RX checksum offload */
               NETIF_F_HW_CSUM |         /* TX checksum offload */
               NETIF_F_HW_VLAN_CTAG_TX | /* VLAN TX offload */
               NETIF_F_HW_VLAN_CTAG_RX | /* VLAN RX offload */
               NETIF_F_HW_VLAN_CTAG_FILTER; /* VLAN filtering */
    
    /* Additional features for specific hardware */
    if (adapter->flags & IXGBE_FLAG_RSS_ENABLED)
        features |= NETIF_F_RXHASH;
    
    netdev->features = features;
    netdev->hw_features = features;
    netdev->vlan_features = features;
}
```

Users can control features:
```bash
# Disable TSO
ethtool -K eth0 tso off

# Enable RX checksumming
ethtool -K eth0 rx on

# View current features
ethtool -k eth0
```

### Performance Impact

Impact of offloads on a 10 Gbps link:

| Feature | CPU Usage | Throughput | Latency |
|---------|-----------|------------|---------|
| No offloads | 100% (1 core) | ~3 Gbps | High |
| RX checksum | 90% | ~4 Gbps | High |
| TX checksum | 80% | ~5 Gbps | Medium |
| TSO/GSO | 50% | ~8 Gbps | Medium |
| All + RSS (4 cores) | 40% per core | ~10 Gbps | Low |

Hardware offloads are critical for line-rate performance with minimal CPU usage.

The combination of these hardware features allows modern NICs to achieve 10-100 Gbps with reasonable CPU utilization.

## Driver Initialization

Understanding how the ixgbe driver initializes provides insight into the complete lifecycle of a NIC driver, from hardware detection to becoming a functioning network interface.

### PCI Driver Registration

The ixgbe driver registers as a PCI driver:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */

/* PCI device IDs supported by ixgbe */
static const struct pci_device_id ixgbe_pci_tbl[] = {
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP), board_82599},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KX4), board_82599},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540T), board_X540},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550T), board_x550},
    /* ... more device IDs ... */
    {0, }  /* Terminate */
};

MODULE_DEVICE_TABLE(pci, ixgbe_pci_tbl);

static struct pci_driver ixgbe_driver = {
    .name        = ixgbe_driver_name,
    .id_table    = ixgbe_pci_tbl,
    .probe       = ixgbe_probe,       /* Called when device found */
    .remove      = ixgbe_remove,      /* Called when device removed */
    .suspend     = ixgbe_suspend,     /* Power management */
    .resume      = ixgbe_resume,
    .shutdown    = ixgbe_shutdown,
    .err_handler = &ixgbe_err_handler,
};

/* Module initialization */
static int __init ixgbe_init_module(void)
{
    pr_info("%s - version %s\n", ixgbe_driver_string, ixgbe_driver_version);
    pr_info("%s\n", ixgbe_copyright);
    
    /* Register PCI driver */
    return pci_register_driver(&ixgbe_driver);
}

module_init(ixgbe_init_module);
```

When the kernel detects a matching PCI device, it calls `ixgbe_probe()`.

### Device Probing

The probe function initializes the hardware and creates the network device:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c (simplified) */
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    struct net_device *netdev;
    struct ixgbe_adapter *adapter;
    struct ixgbe_hw *hw;
    int err, indices;
    
    /* 1. Enable PCI device */
    err = pci_enable_device_mem(pdev);
    if (err)
        return err;
    
    /* 2. Set DMA mask (64-bit preferred) */
    if (!dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
        /* 64-bit DMA supported */
    } else {
        err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
        if (err) {
            dev_err(&pdev->dev, "No usable DMA configuration\n");
            goto err_dma;
        }
    }
    
    /* 3. Request PCI regions (MMIO) */
    err = pci_request_mem_regions(pdev, ixgbe_driver_name);
    if (err)
        goto err_pci_reg;
    
    /* 4. Enable bus mastering (for DMA) */
    pci_set_master(pdev);
    
    /* 5. Allocate net_device structure */
    indices = num_possible_cpus();  /* One queue per CPU */
    netdev = alloc_etherdev_mq(sizeof(struct ixgbe_adapter), indices);
    if (!netdev) {
        err = -ENOMEM;
        goto err_alloc_etherdev;
    }
    
    SET_NETDEV_DEV(netdev, &pdev->dev);
    
    /* 6. Get adapter private data */
    adapter = netdev_priv(netdev);
    adapter->netdev = netdev;
    adapter->pdev = pdev;
    
    /* 7. Map hardware registers (MMIO) */
    hw = &adapter->hw;
    hw->back = adapter;
    hw->hw_addr = ioremap(pci_resource_start(pdev, 0),
                          pci_resource_len(pdev, 0));
    if (!hw->hw_addr) {
        err = -EIO;
        goto err_ioremap;
    }
    
    /* 8. Initialize hardware-specific functions */
    ixgbe_assign_netdev_ops(netdev);
    ixgbe_set_ethtool_ops(netdev);
    
    /* 9. Reset hardware and read MAC address */
    hw->mac.ops.reset_hw(hw);
    hw->mac.ops.get_mac_addr(hw, hw->mac.perm_addr);
    memcpy(netdev->dev_addr, hw->mac.perm_addr, netdev->addr_len);
    
    /* 10. Setup rings and queues */
    ixgbe_alloc_q_vectors(adapter);
    ixgbe_set_interrupt_capability(adapter);
    
    /* 11. Initialize statistics */
    ixgbe_update_stats(adapter);
    
    /* 12. Register network device */
    err = register_netdev(netdev);
    if (err)
        goto err_register;
    
    /* 13. Enable wake-on-lan, etc. */
    ixgbe_wol_supported(adapter);
    device_set_wakeup_enable(&adapter->pdev->dev, adapter->wol);
    
    /* 14. Print device info */
    netdev_info(netdev, "Intel(R) 10 Gigabit Network Connection\n");
    
    return 0;
    
err_register:
    ixgbe_release_hw_control(adapter);
    ixgbe_clear_interrupt_scheme(adapter);
err_ioremap:
    free_netdev(netdev);
err_alloc_etherdev:
    pci_release_mem_regions(pdev);
err_pci_reg:
err_dma:
    pci_disable_device(pdev);
    return err;
}
```

### Allocating Ring Buffers

During initialization, the driver allocates TX and RX rings:

```c
static int ixgbe_alloc_q_vectors(struct ixgbe_adapter *adapter)
{
    int q_vectors = adapter->num_q_vectors;
    int v_idx;
    
    for (v_idx = 0; v_idx < q_vectors; v_idx++) {
        struct ixgbe_q_vector *q_vector;
        int ring_count, size;
        
        /* Calculate number of rings for this vector */
        ring_count = DIV_ROUND_UP(adapter->num_rx_queues, q_vectors - v_idx);
        
        /* Allocate q_vector structure */
        size = sizeof(struct ixgbe_q_vector);
        q_vector = kzalloc(size, GFP_KERNEL);
        if (!q_vector)
            goto err_out;
        
        /* Initialize q_vector */
        q_vector->adapter = adapter;
        q_vector->v_idx = v_idx;
        q_vector->tx.count = adapter->tx_ring_count;
        q_vector->rx.count = adapter->rx_ring_count;
        
        /* Set CPU affinity */
        cpumask_set_cpu(v_idx, &q_vector->affinity_mask);
        
        /* Allocate RX rings */
        for (ring_idx = 0; ring_idx < ring_count; ring_idx++) {
            struct ixgbe_ring *ring;
            
            ring = kzalloc(sizeof(struct ixgbe_ring), GFP_KERNEL);
            if (!ring)
                goto err_out;
            
            ring->count = adapter->rx_ring_count;  /* 512 descriptors */
            ring->queue_index = rxr_idx;
            ring->numa_node = adapter->node;
            ring->dev = &adapter->pdev->dev;
            ring->netdev = adapter->netdev;
            ring->q_vector = q_vector;
            
            adapter->rx_ring[rxr_idx] = ring;
            rxr_idx++;
        }
        
        /* Similar for TX rings */
        
        adapter->q_vector[v_idx] = q_vector;
    }
    
    return 0;
    
err_out:
    /* Cleanup on error */
    return -ENOMEM;
}
```

### Setting Up DMA

DMA setup happens when the interface is brought up:

```c
static int ixgbe_setup_all_tx_resources(struct ixgbe_adapter *adapter)
{
    int i, err = 0;
    
    for (i = 0; i < adapter->num_tx_queues; i++) {
        err = ixgbe_setup_tx_resources(adapter->tx_ring[i]);
        if (err) {
            netdev_err(adapter->netdev,
                      "Allocation for Tx Queue %u failed\n", i);
            goto err_setup_tx;
        }
    }
    
    return 0;
    
err_setup_tx:
    /* Roll back allocations */
    while (i--)
        ixgbe_free_tx_resources(adapter->tx_ring[i]);
    return err;
}
```

We covered `ixgbe_setup_tx_resources()` earlier - it allocates coherent DMA memory for descriptors.

### IRQ Allocation and Setup

The driver sets up MSI-X interrupts:

```c
static void ixgbe_set_interrupt_capability(struct ixgbe_adapter *adapter)
{
    struct ixgbe_hw *hw = &adapter->hw;
    int vector, v_budget;
    
    /* Calculate vectors needed */
    v_budget = min_t(int, num_online_cpus(), hw->mac.max_msix_vectors);
    
    adapter->msix_entries = kcalloc(v_budget,
                                   sizeof(struct msix_entry),
                                   GFP_KERNEL);
    if (!adapter->msix_entries)
        goto msi_only;
    
    for (vector = 0; vector < v_budget; vector++)
        adapter->msix_entries[vector].entry = vector;
    
    /* Request MSI-X vectors */
    vector = pci_enable_msix_range(adapter->pdev,
                                  adapter->msix_entries,
                                  1, v_budget);
    
    if (vector > 0) {
        adapter->num_q_vectors = vector;
        adapter->flags |= IXGBE_FLAG_MSIX_ENABLED;
        return;
    }
    
    kfree(adapter->msix_entries);
    adapter->msix_entries = NULL;
    
msi_only:
    /* Fall back to MSI */
    if (!pci_enable_msi(adapter->pdev))
        adapter->flags |= IXGBE_FLAG_MSI_ENABLED;
}

static int ixgbe_request_irq(struct ixgbe_adapter *adapter)
{
    struct net_device *netdev = adapter->netdev;
    int err;
    
    if (adapter->flags & IXGBE_FLAG_MSIX_ENABLED) {
        /* Register handler for each MSI-X vector */
        err = ixgbe_request_msix_irqs(adapter);
    } else if (adapter->flags & IXGBE_FLAG_MSI_ENABLED) {
        /* Single MSI interrupt */
        err = request_irq(adapter->pdev->irq, ixgbe_intr, 0,
                         netdev->name, adapter);
    } else {
        /* Legacy INTx interrupt */
        err = request_irq(adapter->pdev->irq, ixgbe_intr, IRQF_SHARED,
                         netdev->name, adapter);
    }
    
    if (err)
        netdev_err(netdev, "request_irq failed, Error %d\n", err);
    
    return err;
}

static int ixgbe_request_msix_irqs(struct ixgbe_adapter *adapter)
{
    struct net_device *netdev = adapter->netdev;
    int vector, err;
    
    for (vector = 0; vector < adapter->num_q_vectors; vector++) {
        struct ixgbe_q_vector *q_vector = adapter->q_vector[vector];
        struct msix_entry *entry = &adapter->msix_entries[vector];
        
        /* Create IRQ name */
        snprintf(q_vector->name, sizeof(q_vector->name),
                "%s-TxRx-%d", netdev->name, vector);
        
        /* Request IRQ */
        err = request_irq(entry->vector, ixgbe_msix_clean_rings, 0,
                         q_vector->name, q_vector);
        if (err) {
            netdev_err(netdev, "request_irq failed for MSIX vector %d\n",
                      vector);
            goto free_queue_irqs;
        }
        
        /* Set CPU affinity */
        irq_set_affinity_hint(entry->vector, &q_vector->affinity_mask);
    }
    
    return 0;
    
free_queue_irqs:
    while (vector--) {
        irq_set_affinity_hint(adapter->msix_entries[vector].vector, NULL);
        free_irq(adapter->msix_entries[vector].vector,
                adapter->q_vector[vector]);
    }
    return err;
}
```

### Registering net_device

The final step is registering with the network subsystem:

```c
err = register_netdev(netdev);
```

This makes the device visible to userspace as `eth0`, `enp3s0`, etc.

After `register_netdev()`:
- Device appears in `ip link`
- Can be configured with `ip addr`, `ifconfig`
- Ready to be brought up with `ip link set eth0 up`

### Interface Bring-Up (ndo_open)

When the user runs `ip link set eth0 up`, the kernel calls `ndo_open()`:

```c
static int ixgbe_open(struct net_device *netdev)
{
    struct ixgbe_adapter *adapter = netdev_priv(netdev);
    int err;
    
    /* 1. Allocate ring resources */
    err = ixgbe_setup_all_tx_resources(adapter);
    if (err)
        goto err_setup_tx;
    
    err = ixgbe_setup_all_rx_resources(adapter);
    if (err)
        goto err_setup_rx;
    
    /* 2. Configure hardware */
    ixgbe_configure(adapter);
    
    /* 3. Request IRQs */
    err = ixgbe_request_irq(adapter);
    if (err)
        goto err_req_irq;
    
    /* 4. Enable NAPI */
    for (i = 0; i < adapter->num_q_vectors; i++)
        napi_enable(&adapter->q_vector[i]->napi);
    
    /* 5. Start hardware */
    ixgbe_up_complete(adapter);
    
    /* 6. Start TX queues */
    netif_tx_start_all_queues(netdev);
    
    return 0;
    
err_req_irq:
    ixgbe_free_all_rx_resources(adapter);
err_setup_rx:
    ixgbe_free_all_tx_resources(adapter);
err_setup_tx:
    ixgbe_reset(adapter);
    return err;
}

static void ixgbe_configure(struct ixgbe_adapter *adapter)
{
    struct ixgbe_hw *hw = &adapter->hw;
    
    /* Configure packet filtering */
    ixgbe_set_rx_mode(adapter->netdev);
    
    /* Restore VLAN filters */
    ixgbe_restore_vlan(adapter);
    
    /* Configure RSS */
    ixgbe_setup_rss(adapter);
    
    /* Configure TX rings */
    ixgbe_configure_tx(adapter);
    
    /* Configure RX rings */
    ixgbe_configure_rx(adapter);
    
    /* Enable RX */
    hw->mac.ops.enable_rx(hw);
}
```

### Hardware Initialization

The driver programs the NIC's registers:

```c
static void ixgbe_configure_rx_ring(struct ixgbe_adapter *adapter,
                                   struct ixgbe_ring *ring)
{
    struct ixgbe_hw *hw = &adapter->hw;
    u64 rdba = ring->dma;  /* Ring DMA address */
    u32 rxdctl;
    u8 reg_idx = ring->reg_idx;
    
    /* Disable RX ring while configuring */
    rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
    rxdctl &= ~IXGBE_RXDCTL_ENABLE;
    IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(reg_idx), rxdctl);
    IXGBE_WRITE_FLUSH(hw);
    
    /* Set ring address */
    IXGBE_WRITE_REG(hw, IXGBE_RDBAL(reg_idx), (rdba & 0xffffffff));
    IXGBE_WRITE_REG(hw, IXGBE_RDBAH(reg_idx), (rdba >> 32));
    
    /* Set ring length (in bytes) */
    IXGBE_WRITE_REG(hw, IXGBE_RDLEN(reg_idx),
                    ring->count * sizeof(union ixgbe_adv_rx_desc));
    
    /* Reset head and tail pointers */
    IXGBE_WRITE_REG(hw, IXGBE_RDH(reg_idx), 0);
    IXGBE_WRITE_REG(hw, IXGBE_RDT(reg_idx), 0);
    
    /* Configure descriptor type and buffer sizes */
    rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
    rxdctl |= IXGBE_RXDCTL_RLPML_EN;  /* Large packet support */
    
    /* Enable RX ring */
    rxdctl |= IXGBE_RXDCTL_ENABLE;
    IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(reg_idx), rxdctl);
    
    /* Wait for enable to complete */
    do {
        usleep_range(1000, 2000);
        rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
    } while (!(rxdctl & IXGBE_RXDCTL_ENABLE));
    
    /* Initialize tail pointer (ring is full of buffers) */
    IXGBE_WRITE_REG(hw, IXGBE_RDT(reg_idx), ring->count - 1);
}
```

### Initialization Flow Diagram

```
Module Load (insmod ixgbe.ko)
        ↓
    module_init()
        ↓
pci_register_driver()
        ↓
    ┌───────────────────────────────────┐
    │ PCI subsystem detects device      │
    └──────────────┬────────────────────┘
                   ↓
    ┌───────────────────────────────────┐
    │ ixgbe_probe()                     │
    │  - Enable PCI device              │
    │  - Map MMIO registers             │
    │  - Allocate net_device            │
    │  - Reset hardware                 │
    │  - Read MAC address               │
    │  - Setup queues                   │
    │  - Request MSI-X vectors          │
    │  - register_netdev()              │
    └──────────────┬────────────────────┘
                   ↓
    ┌───────────────────────────────────┐
    │ Device registered as eth0         │
    │ (but not UP yet)                  │
    └───────────────────────────────────┘

User: ip link set eth0 up
        ↓
    ┌───────────────────────────────────┐
    │ ixgbe_open()                      │
    │  - Allocate ring buffers          │
    │  - Setup DMA                      │
    │  - Configure hardware             │
    │  - Request IRQs                   │
    │  - Enable NAPI                    │
    │  - Start TX queues                │
    └──────────────┬────────────────────┘
                   ↓
    ┌───────────────────────────────────┐
    │ Interface is UP and ready         │
    │ Can transmit/receive packets      │
    └───────────────────────────────────┘
```

### Cleanup on Module Unload

```c
static void ixgbe_remove(struct pci_dev *pdev)
{
    struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
    struct net_device *netdev = adapter->netdev;
    
    /* Unregister network device */
    unregister_netdev(netdev);
    
    /* Free IRQs */
    ixgbe_free_irq(adapter);
    
    /* Disable interrupts */
    ixgbe_clear_interrupt_scheme(adapter);
    
    /* Free ring buffers */
    ixgbe_free_all_tx_resources(adapter);
    ixgbe_free_all_rx_resources(adapter);
    
    /* Unmap MMIO */
    iounmap(adapter->hw.hw_addr);
    
    /* Release PCI resources */
    pci_release_mem_regions(pdev);
    
    /* Disable PCI device */
    pci_disable_device(pdev);
    
    /* Free net_device */
    free_netdev(netdev);
}

static void __exit ixgbe_exit_module(void)
{
    pci_unregister_driver(&ixgbe_driver);
}

module_exit(ixgbe_exit_module);
```

The driver initialization demonstrates the complete lifecycle from hardware detection through becoming a functioning network interface, highlighting the interactions between PCI subsystem, DMA, interrupts, and the networking stack.

## Relationship to Other Kernel Subsystems

NIC drivers interact with multiple kernel subsystems. Understanding these relationships provides a complete picture of how network packets flow through the system.

### Interrupts and NAPI

**See [Linux Interrupt Handling](linux_interrupts.md) for detailed coverage of:**

- **Hardware interrupts**: How the NIC raises MSI-X interrupts when packets arrive
- **Interrupt handlers**: The fast path in `ixgbe_msix_clean_rings()` that disables interrupts and schedules softirq
- **Softirqs**: `NET_RX_SOFTIRQ` processing in `net_rx_action()`
- **NAPI polling**: The hybrid interrupt/polling mechanism that balances latency and throughput
- **Interrupt affinity**: Binding interrupts to specific CPUs for cache locality

Key interaction points:
```c
/* NIC raises interrupt */
ixgbe_msix_clean_rings()
    → napi_schedule()           /* Schedule softirq */
        → raise_softirq(NET_RX_SOFTIRQ)
            → net_rx_action()   /* Softirq handler */
                → napi->poll()  /* ixgbe_poll() */
```

The interrupt chapter explains the context switch from hardirq to softirq and the trade-offs between interrupt-driven and polled I/O.

### System Calls and Packet Delivery

**See [syscalls.md](syscalls.md) for detailed coverage of:**

- **`send()`/`sendto()`**: How userspace transmits data
- **`recv()`/`recvfrom()`**: How userspace receives data
- **Socket buffers**: Kernel-side buffers that hold packets for applications
- **Copy operations**: Moving data between kernel space and user space
- **Blocking vs non-blocking I/O**: How processes wait for network data

Key interaction points:
```c
/* Application sends data */
send(sockfd, data, len)
    → sys_sendto()
        → sock_sendmsg()
            → tcp_sendmsg()  /* Protocol layer */
                → ip_queue_xmit()
                    → dev_queue_xmit()
                        → ixgbe_xmit_frame()  /* Driver */

/* Application receives data */
recv(sockfd, buffer, len)
    → sys_recvfrom()
        → sock_recvmsg()
            → tcp_recvmsg()
                → skb_copy_datagram_iter()  /* Copy from skb to user */
```

The syscalls chapter explains how the network stack bridges userspace applications and kernel drivers.

### Context Switches and CPU Scheduling

**See [context_switch.md](context_switch.md) for detailed coverage of:**

- **Interrupt context**: Code running in `ixgbe_msix_clean_rings()` is in interrupt context (cannot sleep)
- **Softirq context**: NAPI polling runs in softirq context (still cannot sleep, but lower priority than hardirq)
- **Process context**: Application `recv()` calls run in process context (can sleep waiting for data)
- **Wake-ups**: How `sk_data_ready()` wakes processes blocked on `recv()`

Key interaction points:
```c
/* Packet arrives, process is blocked in recv() */
ixgbe_poll()
    → ixgbe_clean_rx_irq()
        → netif_receive_skb()
            → tcp_v4_rcv()
                → tcp_data_queue()
                    → sk_data_ready()  /* Wake sleeping process */
                        → wake_up_interruptible()
                            → Context switch to application
```

The context switch chapter explains the CPU state changes between interrupt, softirq, and process contexts.

### Scheduler Interactions

**See [scheduler.md](scheduler.md) for detailed coverage of:**

- **CPU affinity**: Binding NAPI polling and interrupts to specific CPUs
- **Real-time priorities**: Network interrupts can preempt normal processes
- **CPU load balancing**: How RSS distributes work across CPUs
- **ksoftirqd**: Kernel threads that handle softirqs when load is high

Key interaction points:
```c
/* Set interrupt affinity */
irq_set_affinity_hint(msix_vector, &q_vector->affinity_mask);

/* NAPI scheduled on same CPU as interrupt */
napi_schedule()
    → __napi_schedule()
        → __raise_softirq_irqoff(NET_RX_SOFTIRQ)
            /* Runs on same CPU */
```

The scheduler chapter explains how network processing competes with other tasks for CPU time.

### IP Layer and Routing

**See [ip.md](ip.md) for detailed coverage of:**

- **Packet reception path**: After `netif_receive_skb()`, packets enter the IP layer
- **Routing decisions**: Forwarding vs local delivery
- **IP fragmentation**: How large packets are handled
- **Netfilter hooks**: Firewall rules applied to packets

Key interaction points:
```c
/* From driver to IP layer */
napi_gro_receive(skb)
    → netif_receive_skb_internal()
        → __netif_receive_skb_core()
            → deliver_ptype_list_skb()
                → ip_rcv()           /* Enter IP layer */
                    → ip_rcv_finish()
                        → ip_local_deliver() or ip_forward()
```

The IP chapter explains what happens to packets after the driver hands them to the network stack.

### TCP/UDP Processing

**See [udp_tcp.md](udp_tcp.md) for detailed coverage of:**

- **TCP connection management**: How skbs are queued on TCP sockets
- **TCP congestion control**: Backpressure affecting transmission
- **UDP datagram delivery**: Connectionless packet handling
- **Socket lookup**: Finding the destination socket for a packet

Key interaction points:
```c
/* From IP to transport layer */
ip_local_deliver_finish()
    → tcp_v4_rcv() or udp_rcv()
        → __tcp_v4_lookup() or __udp4_lib_lookup()  /* Find socket */
            → tcp_data_queue() or __udp_queue_rcv_skb()
                → sock_queue_rcv_skb()  /* Add to socket queue */
                    → sk_data_ready()   /* Wake application */
```

The TCP/UDP chapter explains protocol-level packet processing after driver delivery.

### XDP (Express Data Path)

**See [xdp.md](xdp.md) for detailed coverage of:**

- **Early packet processing**: XDP programs run in the driver before skb allocation
- **Packet actions**: XDP can drop, pass, redirect, or modify packets
- **Zero-copy**: XDP can process packets without creating skbs
- **High-performance filtering**: Line-rate packet filtering and forwarding

Key interaction points in ixgbe with XDP:
```c
/* In ixgbe_clean_rx_irq(), before building skb */
struct xdp_buff xdp;
xdp.data = page_address(rx_buffer->page) + rx_buffer->page_offset;
xdp.data_end = xdp.data + size;

/* Run XDP program */
if (xdp_prog) {
    act = bpf_prog_run_xdp(xdp_prog, &xdp);
    
    switch (act) {
    case XDP_PASS:
        /* Continue normal processing */
        break;
    case XDP_DROP:
        /* Drop packet, don't allocate skb */
        return true;
    case XDP_TX:
        /* Transmit on same interface */
        ixgbe_xdp_xmit(rx_ring, &xdp);
        return true;
    case XDP_REDIRECT:
        /* Redirect to another interface */
        xdp_do_redirect(netdev, &xdp, xdp_prog);
        return true;
    }
}

/* Only if XDP_PASS: allocate skb and continue normal path */
skb = ixgbe_construct_skb(rx_ring, rx_buffer, &xdp, rx_desc);
```

XDP provides an alternative fast path that bypasses most of the network stack for specialized use cases like DDoS mitigation and high-performance packet forwarding.

### Complete System View

Putting it all together, here's how a packet flows through the entire system:

```
                    Packet Arrival
                          │
                          ▼
    ┌─────────────────────────────────────┐
    │ 1. Hardware (NIC)                   │
    │    - DMA to memory                  │
    │    - Raise MSI-X interrupt          │
    └──────────────┬──────────────────────┘
                   │ [Linux Interrupt Handling]
                   ▼
    ┌─────────────────────────────────────┐
    │ 2. Driver (ixgbe)                   │
    │    - Hardirq handler                │
    │    - Schedule NAPI                  │
    │    - Softirq: poll RX ring          │
    │    - Build skb                      │
    │    - Optional: XDP program          │ [xdp.md]
    │    - napi_gro_receive()             │
    └──────────────┬──────────────────────┘
                   │ [scheduler.md - softirq context]
                   ▼
    ┌─────────────────────────────────────┐
    │ 3. Network Stack                    │
    │    - Protocol handlers              │
    │    - IP: routing decision           │ [ip.md]
    │    - TCP/UDP: socket lookup         │ [udp_tcp.md]
    │    - Queue on socket                │
    └──────────────┬──────────────────────┘
                   │ [context_switch.md - wake up process]
                   ▼
    ┌─────────────────────────────────────┐
    │ 4. Application                      │
    │    - recv() system call             │ [syscalls.md]
    │    - Copy to user space             │
    │    - Process packet data            │
    └─────────────────────────────────────┘
```

This NIC driver chapter provides the foundation for understanding how packets enter and leave the kernel, complementing the other chapters that explain the surrounding subsystems.
