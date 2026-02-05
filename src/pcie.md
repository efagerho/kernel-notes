# PCIe (Peripheral Component Interconnect Express)

## Overview

**PCIe (Peripheral Component Interconnect Express)** is the primary high-speed serial interconnect used in modern computers to connect CPUs with peripheral devices (network cards, GPUs, NVMe SSDs, etc.). Unlike its predecessor PCI, which used a parallel shared bus, PCIe uses point-to-point serial links, providing higher bandwidth, better scalability, and more flexible topology.

This chapter covers the essential aspects of PCIe for understanding device driver development on Linux:

1. **PCIe Architecture**: The hardware topology, addressing mechanisms, and transaction protocols
2. **PCIe Configuration**: How devices are enumerated and configured  
3. **Device Driver Implementation**: How Linux drivers interact with PCIe devices

For information on how PCIe devices perform data transfers, see the [DMA & IOMMU](./dma.md) chapter.

## PCIe Architecture & Fundamentals

### PCIe Topology

PCIe creates a tree-like hierarchy of point-to-point connections, unlike the shared bus architecture of legacy PCI. Understanding this topology is crucial for device driver writers because it affects device discovery, interrupt routing, and DMA address translation.

#### Components of PCIe Topology

```
                   CPU
                    │
            ┌───────┴───────┐
            │  Root Complex │  ← Connects CPU to PCIe hierarchy
            └───────┬───────┘
                    │
         ┌──────────┼───────────┐
         │          │           │
    ┌────┴────┐ ┌───┴───┐  ┌────┴─────┐
    │PCIe Link│ │ PCIe  │  │PCIe Link │
    │         │ │Switch │  │          │
    └────┬────┘ └───┬───┘  └────┬─────┘
         │          │           │
    ┌────┴────┐     │      ┌────┴─────┐
    │Endpoint │     │      │Endpoint  │
    │(NIC)    │     │      │(NVMe SSD)│
    └─────────┘     │      └──────────┘
               ┌────┴────┐
               │More     │
               │Endpoints│
               └─────────┘
```

**Root Complex**:
- The bridge between the CPU/memory subsystem and the PCIe hierarchy
- Generates configuration transactions for device enumeration
- Routes memory and I/O requests between CPU and devices
- Manages interrupt delivery to CPU
- On Intel systems, typically integrated into the chipset (PCH - Platform Controller Hub)

**PCIe Switch**:
- Provides fan-out, allowing multiple devices to connect to a single upstream port
- Performs packet routing based on address or ID
- Each port on a switch is a PCIe-to-PCIe bridge
- Transparent to software - devices behind switches appear directly connected

**PCIe Endpoint**:
- The actual peripheral device (NIC, GPU, NVMe controller, etc.)
- Can be a single function or multi-function device
- Identified by Bus:Device:Function (BDF) address

**PCIe Bridge**:
- Connects PCIe segments (switches are bridges)
- Type 0 configuration header: endpoint
- Type 1 configuration header: bridge (covered in the next section)

### PCIe Lanes and Bandwidth

PCIe connections are made up of **lanes**, where each lane consists of two differential pairs (TX and RX), allowing full-duplex communication. Devices can use 1, 2, 4, 8, 16, or 32 lanes (denoted as x1, x2, x4, x8, x16, x32).

#### PCIe Generations and Raw Bandwidth

Each PCIe generation doubles the signaling rate:

| Generation | Year | Encoding | Transfer Rate | Per-Lane Bandwidth | x16 Bandwidth |
|------------|------|----------|---------------|-------------------|---------------|
| PCIe 1.0   | 2003 | 8b/10b   | 2.5 GT/s      | 250 MB/s          | 4 GB/s        |
| PCIe 2.0   | 2007 | 8b/10b   | 5.0 GT/s      | 500 MB/s          | 8 GB/s        |
| PCIe 3.0   | 2010 | 128b/130b| 8.0 GT/s      | ~1 GB/s           | ~16 GB/s      |
| PCIe 4.0   | 2017 | 128b/130b| 16.0 GT/s     | ~2 GB/s           | ~32 GB/s      |
| PCIe 5.0   | 2019 | 128b/130b| 32.0 GT/s     | ~4 GB/s           | ~64 GB/s      |

**Encoding overhead**:
- **8b/10b encoding** (PCIe 1.0/2.0): 20% overhead - for every 8 bits of data, 2 additional bits are used for encoding, resulting in 80% efficiency
- **128b/130b encoding** (PCIe 3.0+): ~1.5% overhead - only 2 bits per 128 bits of data

**Bandwidth calculation example** (PCIe 3.0 x8):
```
8 GT/s × 8 lanes × (128/130) ≈ 7.877 GB/s per direction (full-duplex)
```

#### Lane Negotiation and Training

When a device is powered on, PCIe performs **link training**:

1. **Detect**: Physical layer detects link partner presence
2. **Polling**: Exchange training sequences to synchronize bit and symbol clocks  
3. **Configuration**: Negotiate lane width, speed, and other parameters
4. **L0 (Active)**: Normal operation state

A device advertised as x16 might negotiate down to x8 or x4 if:
- The slot physically provides fewer lanes
- Signal integrity issues prevent higher lane counts
- BIOS/firmware configuration limits lane allocation

Linux exposes negotiated link parameters via sysfs:
```bash
$ cat /sys/bus/pci/devices/0000:01:00.0/current_link_speed
8.0 GT/s PCIe    # PCIe 3.0

$ cat /sys/bus/pci/devices/0000:01:00.0/current_link_width  
8                # x8 lanes negotiated
```

### PCIe Transaction Layer

PCIe uses **Transaction Layer Packets (TLPs)** to communicate. Understanding TLPs is important because they determine how device drivers interact with hardware and how DMA operates.

#### TLP Types

PCIe defines several transaction types:

**Memory Transactions** (most common for drivers):
- **Memory Read Request (MRd)**: Device or CPU reads from memory
- **Memory Write Request (MWr)**: Device or CPU writes to memory
- **Memory Read Completion (CplD)**: Returns data for a previous memory read
- Used for: DMA transfers, MMIO register access

**I/O Transactions** (legacy, rare on modern systems):
- **I/O Read/Write**: Access I/O port space
- Required for legacy device compatibility

**Configuration Transactions**:
- **Configuration Read/Write (CfgRd/CfgWr)**: Access device configuration space
- Used during device enumeration and initialization
- Only generated by the root complex

**Message Transactions**:
- **Interrupt messages**: MSI/MSI-X delivery
- **Error reporting**: AER (Advanced Error Reporting)
- **Power management**: PM messages
- **Vendor-defined messages**

#### TLP Structure

A TLP consists of:

```
┌─────────────────────────────────────────────────┐
│              TLP Header (3-4 DW)                │ ← Type, address, requester ID
├─────────────────────────────────────────────────┤
│              Data Payload (0-1024 DW)           │ ← Optional, for writes/completions
├─────────────────────────────────────────────────┤
│              Digest (1 DW)                      │ ← Optional ECRC
└─────────────────────────────────────────────────┘
Note: DW = Dword (4 bytes)
```

**TLP Header Format** (Memory Write, 3 DW header):

```
DW 0: [7:0] Format/Type │ [15:8] Attributes │ [25:16] Length │ [31:26] Reserved
      
      Format[2:0]:
        000b = 3 DW header, no data
        010b = 3 DW header, with data
        001b = 4 DW header, no data
        011b = 4 DW header, with data
      
      Type[4:0]:
        00000b = Memory Read
        00001b = Memory Write
        00100b = I/O Read
        01010b = Completion without data
        01011b = Completion with data
      
      Length[9:0]: Payload size in DW (0 = 1024 DW)

DW 1: [15:0] Requester ID │ [23:16] Tag │ [31:24] Last/First DW BE

      Requester ID: Bus:Device:Function of transaction originator
      Tag: Transaction identifier for matching requests/completions
      
DW 2: [31:0] Address (bits [31:2], DW-aligned)

      For 64-bit addressing, uses 4 DW header with address in DW 2-3
```

**Example: Device Performing DMA Write**

When an Intel ixgbe NIC performs DMA to write a received packet to memory at address `0xDEADBEEF000`, it generates a Memory Write TLP:

```
DW 0: Format=010b (3DW+data) │ Type=00001b (MWr) │ Length=0x20 (32 DW = 128 bytes)
DW 1: Requester=0x0100 (Bus 1, Dev 0, Func 0) │ Tag=0x42 │ BE=0xFF
DW 2: Address=0x3DEADBEE (bits [31:2] of 0xDEADBEEF000, lower 2 bits assumed 00)
DW 3-34: Packet data (128 bytes)
DW 35: ECRC (if enabled)
```

The root complex receives this TLP and writes the data to system memory.

### PCIe Flow Control

PCIe implements **credit-based flow control** to prevent buffer overflow. This happens at the link layer, transparent to software, but understanding it helps explain performance characteristics.

#### How Credit-Based Flow Control Works

Each receiver advertises **credits** indicating how much buffer space is available:

```
Device A (Transmitter)          Device B (Receiver)
    │                                  │
    │   Initial Credit: FC=10          │ ← B tells A it has buffer for 10 TLPs
    ├─────────────────────────────────>│
    │                                  │
    │   TLP 1 (consumes 1 credit)      │
    ├─────────────────────────────────>│ FC: 10 → 9
    │   TLP 2 (consumes 1 credit)      │
    ├─────────────────────────────────>│ FC: 9 → 8
    │                                  │
    │   Credit Update: FC += 2         │ ← B processed 2 TLPs, returns credits
    │<─────────────────────────────────┤ FC: 8 → 10
    │                                  │
    │   (Can continue sending)         │
```

Credits are tracked separately for:
- **Posted transactions** (Memory Writes - no completion required)
- **Non-posted transactions** (Memory Reads - completion required)
- **Completions** (Data returned for reads)

And for both:
- **Header credits**: Number of TLP headers
- **Data credits**: Amount of payload data (in units of 16 bytes)

**Why this matters for drivers**:
- Devices can't send TLPs if they lack credits → back pressure
- Deep buffers = more credits = better performance for bursty traffic
- Explains why small random I/O is slower than large sequential I/O

### PCIe Ordering Rules

PCIe enforces specific ordering rules between transactions to maintain consistency while allowing performance optimizations. Drivers must understand these when programming device registers and DMA descriptors.

#### Producer/Consumer Ordering Model

PCIe groups transactions as:
- **Posted**: No completion (e.g., Memory Writes, Messages)
- **Non-posted**: Completion required (e.g., Memory Reads, Config accesses)

**Key ordering rules**:

1. **Writes are NOT ordered with later reads** (relaxed ordering)
   ```c
   /* CPU writes to device MMIO register */
   writel(START_DMA, hw->reg_base + CTRL);
   
   /* Immediately read status register */
   val = readl(hw->reg_base + STATUS);  // May NOT see write yet!
   ```
   
   **Solution**: Flush posted writes before reads:
   ```c
   writel(START_DMA, hw->reg_base + CTRL);
   readl(hw->reg_base + CTRL);  // Flush: forces completion
   val = readl(hw->reg_base + STATUS);  // Now guaranteed to see write
   ```

2. **Writes to the same address ARE ordered**
   ```c
   /* These occur in order */
   writel(0x01, hw->reg);
   writel(0x02, hw->reg);
   writel(0x03, hw->reg);  // Device sees 0x01, then 0x02, then 0x03
   ```

3. **Reads complete in order** (relative to each other)

4. **Reads pull in older writes** (from same requestor)

**Practical example from ixgbe driver**:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static void ixgbe_configure_tx_ring(struct ixgbe_adapter *adapter,
                                    struct ixgbe_ring *ring)
{
    struct ixgbe_hw *hw = &adapter->hw;
    u64 tdba = ring->dma;  /* DMA address of TX descriptor ring */
    u32 txctrl;
    
    /* 1. Write ring base address (low 32 bits) */
    IXGBE_WRITE_REG(hw, IXGBE_TDBAL(ring->reg_idx), (u32)tdba);
    
    /* 2. Write ring base address (high 32 bits) */
    IXGBE_WRITE_REG(hw, IXGBE_TDBAH(ring->reg_idx), (u32)(tdba >> 32));
    
    /* 3. Write ring length */
    IXGBE_WRITE_REG(hw, IXGBE_TDLEN(ring->reg_idx),
                    ring->count * sizeof(union ixgbe_adv_tx_desc));
    
    /* 4. Enable the queue */
    txctrl = IXGBE_READ_REG(hw, IXGBE_DCA_TXCTRL(ring->reg_idx));
    txctrl |= IXGBE_DCA_TXCTRL_TX_ENABLE;
    IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL(ring->reg_idx), txctrl);
    
    /* 
     * 5. CRITICAL: Flush writes before continuing
     * The device must see all the configuration before we start DMA
     */
    IXGBE_WRITE_FLUSH(hw);  // Macro that performs a dummy read
}
```

The flush macro:
```c
#define IXGBE_WRITE_FLUSH(a) IXGBE_READ_REG(a, IXGBE_STATUS)
```

Reading any register forces all prior posted writes to complete before the read returns, ensuring the device has received all configuration before proceeding.

### PCIe Error Handling

PCIe includes sophisticated error detection and reporting mechanisms. While much of this is handled by hardware and platform firmware, drivers need to be aware of error types and recovery mechanisms.

#### Error Types

**Correctable Errors**:
- Detected and corrected by hardware (e.g., bit errors corrected by CRC)
- Logged but don't interrupt normal operation
- Examples: Bad TLP, Bad DLLP (Data Link Layer Packet), Replay Timeout

**Uncorrectable Errors**:
- Cannot be corrected by hardware
- Fatal: require link reset or system reboot
- Non-fatal: recoverable through software
- Examples: Poisoned TLP, Completion Timeout, Malformed TLP

**Advanced Error Reporting (AER)**:

Modern PCIe devices support AER (defined in PCIe capability structure). AER provides:
- Detailed error logging registers
- Error severity classification
- Error masking capabilities
- Error injection for testing

Linux AER driver (`drivers/pci/pcie/aer.c`) handles:
- Error logging to kernel log
- Error recovery coordination
- Notification to device drivers

**Driver considerations**:
```c
/* From include/linux/pci.h */
struct pci_error_handlers {
    /* Error detected */
    pci_ers_result_t (*error_detected)(struct pci_dev *dev,
                                        pci_channel_state_t error);
    
    /* MMIO enabled again after error */
    pci_ers_result_t (*mmio_enabled)(struct pci_dev *dev);
    
    /* Attempt slot reset */
    pci_ers_result_t (*slot_reset)(struct pci_dev *dev);
    
    /* Normal operation resumed */
    void (*resume)(struct pci_dev *dev);
};
```

The ixgbe driver implements error handlers:
```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static const struct pci_error_handlers ixgbe_err_handler = {
    .error_detected = ixgbe_io_error_detected,
    .slot_reset = ixgbe_io_slot_reset,
    .resume = ixgbe_io_resume,
};

static struct pci_driver ixgbe_driver = {
    .name     = ixgbe_driver_name,
    .id_table = ixgbe_pci_tbl,
    .probe    = ixgbe_probe,
    .remove   = ixgbe_remove,
    .err_handler = &ixgbe_err_handler,
};
```

This provides a framework for graceful degradation and recovery when PCIe errors occur, essential for high-reliability systems.

---

This covers the fundamental PCIe architecture concepts needed to understand device driver development. The next sections will build on this foundation to explain how devices are addressed and configured, and how drivers interact with PCIe hardware.

## PCIe Addressing & Configuration Space

Every PCIe device has a **configuration space** - a standardized region of registers used for device identification, resource allocation, and capability discovery. Understanding configuration space is essential for device driver development because drivers must read device information and configure resources during initialization.

### Bus:Device:Function (BDF) Addressing

PCIe uses a hierarchical addressing scheme to identify devices:

```
┌─────────────────────────────────────────────┐
│  Bus Number  │ Device Number │ Function     │
│  (8 bits)    │ (5 bits)      │ (3 bits)     │
│  0-255       │ 0-31          │ 0-7          │
└─────────────────────────────────────────────┘
      ↓              ↓              ↓
   00:1f.0  ← Common notation (hex)
```

**Bus Number** (8 bits, 0-255):
- Each PCIe segment has multiple buses
- Bus 0 is the primary bus attached to the root complex
- Bridges create secondary buses
- Assigned during bus enumeration

**Device Number** (5 bits, 0-31):
- Physical device on a bus
- On PCIe (not legacy PCI), typically only device 0 is used
- Switches and multi-function devices may use multiple device numbers

**Function Number** (3 bits, 0-7):
- Logical function within a device
- Single-function device: function 0 only
- Multi-function device: up to 8 functions (e.g., network card with management controller)

**Complete BDF in Linux**:
```
Domain:Bus:Device.Function
 0000:  01:  00.   0

Domain (16 bits): Segment number, typically 0 on x86-64
```

**Examples from a real system**:
```bash
$ lspci
00:00.0 Host bridge: Intel Corporation Device 9b33
00:02.0 VGA compatible controller: Intel Corporation CometLake-S GT2
00:14.0 USB controller: Intel Corporation Comet Lake USB 3.1 xHCI Host Controller
01:00.0 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection
02:00.0 Non-Volatile memory controller: Samsung Electronics Co Ltd NVMe SSD Controller SM981/PM981/PM983
```

The kernel represents BDF as:
```c
/* From include/linux/pci.h */
struct pci_dev {
    unsigned int devfn;     /* Device (5 bits) and function (3 bits) combined */
    unsigned int bus;       /* Bus number (in struct pci_bus) */
    /* ... many more fields ... */
};

/* Extract device and function */
#define PCI_SLOT(devfn)     (((devfn) >> 3) & 0x1f)  /* Device number */
#define PCI_FUNC(devfn)     ((devfn) & 0x07)         /* Function number */
```

### Configuration Space Structure

PCIe configuration space has evolved over time:

- **PCI Configuration Space**: 256 bytes (original)
- **PCIe Configuration Space**: 4096 bytes (4 KB)

The first 256 bytes maintain PCI compatibility. The remaining 3840 bytes contain PCIe extended capabilities.

```
┌────────────────────────────────────────┐
│ Standard Configuration Header (64B)    │ ← Always present
├────────────────────────────────────────┤
│ Device-Specific Region (192B)          │ ← Device type dependent
├────────────────────────────────────────┤
│ Capability List (variable)             │ ← PCI capabilities
├────────────────────────────────────────┤  Offset 0x100
│ Extended Capabilities (3840B)          │ ← PCIe extended capabilities
└────────────────────────────────────────┘  Offset 0xFFF
```

### Configuration Space Headers

There are two types of configuration headers:

**Type 0 Header** (Endpoints):
```
Offset  Size  Field
------  ----  -----
0x00    2     Vendor ID
0x02    2     Device ID
0x04    2     Command Register
0x06    2     Status Register
0x08    1     Revision ID
0x09    3     Class Code
0x0C    1     Cache Line Size
0x0D    1     Latency Timer
0x0E    1     Header Type (0x00 for Type 0)
0x0F    1     BIST
0x10    4     BAR 0
0x14    4     BAR 1
0x18    4     BAR 2
0x1C    4     BAR 3
0x20    4     BAR 4
0x24    4     BAR 5
0x28    4     Cardbus CIS Pointer
0x2C    2     Subsystem Vendor ID
0x2E    2     Subsystem ID
0x30    4     Expansion ROM Base Address
0x34    1     Capabilities Pointer
0x35    3     Reserved
0x38    4     Reserved
0x3C    1     Interrupt Line
0x3D    1     Interrupt Pin
0x3E    1     Min_Gnt
0x3F    1     Max_Lat
```

**Type 1 Header** (Bridges):
Similar to Type 0, but BAR fields replaced with:
```
0x18    1     Primary Bus Number
0x19    1     Secondary Bus Number
0x1A    1     Subordinate Bus Number
0x1B    1     Secondary Latency Timer
0x1C    2     I/O Base/Limit
0x1E    2     Secondary Status
0x20    2     Memory Base
0x22    2     Memory Limit
0x24    2     Prefetchable Memory Base
0x26    2     Prefetchable Memory Limit
```

### Vendor ID and Device ID

The first fields in configuration space identify the device:

```c
/* Reading vendor/device ID from configuration space */
u16 vendor, device;

pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);  /* Offset 0x00 */
pci_read_config_word(pdev, PCI_DEVICE_ID, &device);  /* Offset 0x02 */
```

**Well-known Vendor IDs**:
- 0x8086: Intel
- 0x10DE: NVIDIA
- 0x1022: AMD
- 0x144D: Samsung
- 0x1AF4: Red Hat (virtio devices)

Drivers match against vendor/device ID:
```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static const struct pci_device_id ixgbe_pci_tbl[] = {
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP), board_82599},
    /* Expands to: .vendor = 0x8086, .device = 0x10FB */
    
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KX4), board_82599},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540T), board_X540},
    {0, }  /* Sentinel */
};

MODULE_DEVICE_TABLE(pci, ixgbe_pci_tbl);
```

### Base Address Registers (BARs)

**BARs** specify memory or I/O regions that the device uses for register access and communication. Endpoints (Type 0 headers) have up to 6 BARs; bridges (Type 1) have 2.

#### BAR Types

BARs can map two types of address spaces:

**Memory-Mapped I/O (MMIO)** - Most common on modern devices:
```
BAR bits [31:0] or [63:0]
Bit 0:     0 (indicates memory space)
Bits 2-1:  Type
           00b = 32-bit address
           10b = 64-bit address
Bit 3:     Prefetchable (1 = yes, 0 = no)
Bits 31-4: Base address (16-byte aligned minimum)
```

**I/O Port Space** - Legacy, rare:
```
BAR bits [31:0]
Bit 0:     1 (indicates I/O space)
Bit 1:     Reserved
Bits 31-2: Base address (4-byte aligned)
```

#### 64-bit BARs

A 64-bit BAR consumes two consecutive BAR slots:
```
BAR 0: [31:0]  Lower 32 bits of address
BAR 1: [31:0]  Upper 32 bits of address
```

Example from ixgbe (82599 NIC):
```bash
$ lspci -s 01:00.0 -v
01:00.0 Ethernet controller: Intel Corporation 82599ES
    ...
    Region 0: Memory at f7e00000 (64-bit, prefetchable) [size=512K]
    Region 3: Memory at f7e80000 (64-bit, prefetchable) [size=16K]
```

BAR 0 uses 64-bit addressing:
- BAR 0 = 0xf7e00000 (lower 32 bits)
- BAR 1 = 0x00000000 (upper 32 bits)
- Full address: 0x00000000f7e00000

#### BAR Sizing and Allocation

The BIOS/UEFI (or OS during hot-plug) determines BAR sizes during enumeration:

1. **Write all 1s** to BAR
2. **Read back** the BAR value
3. **Calculate size**: The read-back value indicates which address bits are hardwired to 0, revealing the region size

```c
/* Pseudocode for BAR sizing */
original = read_config(BAR);
write_config(BAR, 0xFFFFFFFF);
mask = read_config(BAR);
write_config(BAR, original);  /* Restore */

size = ~(mask & ~0xF) + 1;  /* Invert settable bits, add 1 */
```

Example:
- Write: 0xFFFFFFFF
- Read back: 0xFFF80000
- Settable bits: 0xFFF80000 & ~0xF = 0xFFF80000
- Size: ~0xFFF80000 + 1 = 0x00080000 = 512 KB

**Linux BAR management**:
```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    /* ... */
    
    /* Request ownership of device memory regions */
    err = pci_request_mem_regions(pdev, ixgbe_driver_name);
    if (err) {
        dev_err(&pdev->dev, "pci_request_regions failed!\n");
        goto err_pci_reg;
    }
    
    /* Get BAR 0 start address and size */
    hw->hw_addr = ioremap(pci_resource_start(pdev, 0),
                          pci_resource_len(pdev, 0));
    if (!hw->hw_addr) {
        err = -EIO;
        goto err_ioremap;
    }
    
    /* Now hw->hw_addr points to device registers in kernel virtual memory */
}
```

Helper functions:
```c
/* From include/linux/pci.h */
#define pci_resource_start(dev, bar)  /* Physical address of BAR */
#define pci_resource_end(dev, bar)    /* End address of BAR */
#define pci_resource_len(dev, bar)    /* Size of BAR region */
#define pci_resource_flags(dev, bar)  /* Flags (MMIO, I/O, prefetchable) */
```

### Command and Status Registers

The **Command Register** (offset 0x04) controls device behavior:

```
Bit  Field
---  -----
0    I/O Space Enable
1    Memory Space Enable (must be set for MMIO access)
2    Bus Master Enable (must be set for DMA)
3    Special Cycle Enable
4    Memory Write and Invalidate Enable
5    VGA Palette Snoop
6    Parity Error Response
7    Reserved
8    SERR# Enable
9    Fast Back-to-Back Enable
10   Interrupt Disable
```

**Enabling bus mastering** (required for DMA):
```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    /* ... */
    pci_set_master(pdev);  /* Sets bit 2 of Command Register */
}
```

Internally:
```c
/* From drivers/pci/pci.c */
void pci_set_master(struct pci_dev *dev)
{
    u16 cmd;
    
    pci_read_config_word(dev, PCI_COMMAND, &cmd);
    if (!(cmd & PCI_COMMAND_MASTER)) {
        cmd |= PCI_COMMAND_MASTER;
        pci_write_config_word(dev, PCI_COMMAND, cmd);
    }
}
```

The **Status Register** (offset 0x06) reports device state:
```
Bit  Field
---  -----
3    Interrupt Status
4    Capabilities List (1 = has capability list)
5    66 MHz Capable
7    Fast Back-to-Back Capable
8    Master Data Parity Error
11   Signaled Target Abort
12   Received Target Abort
13   Received Master Abort
14   Signaled System Error
15   Detected Parity Error
```

### Configuration Space Access Mechanisms

The CPU accesses configuration space through the root complex using special mechanisms.

#### ECAM (Enhanced Configuration Access Mechanism)

Modern PCIe systems use **ECAM**, which memory-maps the entire configuration space:

```
Base Address + (Bus << 20) + (Device << 15) + (Function << 12) + Offset
```

ECAM maps each device's 4 KB configuration space at a fixed offset from a base address (specified in ACPI MCFG table).

Example: Accessing device 01:00.0 offset 0x40 with ECAM base 0xE0000000:
```
Address = 0xE0000000 + (1 << 20) + (0 << 15) + (0 << 12) + 0x40
        = 0xE0000000 + 0x100000 + 0x40
        = 0xE0100040
```

The kernel abstracts this:
```c
/* From arch/x86/pci/mmconfig-shared.c */
static void __iomem *pci_dev_base(unsigned int seg, unsigned int bus,
                                   unsigned int devfn)
{
    struct pci_mmcfg_region *cfg = pci_mmconfig_lookup(seg, bus);
    
    if (cfg && cfg->virt)
        return cfg->virt + (PCI_MMCFG_BUS_OFFSET(bus) |
                            (devfn << 12));
    return NULL;
}
```

#### Legacy Configuration Mechanism (CF8/CFC)

Older systems use I/O ports 0xCF8 (address) and 0xCFC (data):

```c
/* Write to configuration space using CF8/CFC (legacy) */
static int pci_conf1_write(unsigned int seg, unsigned int bus,
                           unsigned int devfn, int reg, int len, u32 value)
{
    if (seg || (bus > 255) || (devfn > 255) || (reg > 255))
        return -EINVAL;
        
    /* Build address: Enable bit [31], Bus [23:16], DevFn [15:8], Reg [7:2] */
    outl(0x80000000 | (bus << 16) | (devfn << 8) | (reg & ~3), 0xCF8);
    
    /* Write data */
    switch (len) {
    case 1:
        outb(value, 0xCFC + (reg & 3));
        break;
    case 2:
        outw(value, 0xCFC + (reg & 2));
        break;
    case 4:
        outl(value, 0xCFC);
        break;
    }
    
    return 0;
}
```

Linux drivers use generic accessors that work with either mechanism:
```c
int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val);
int pci_read_config_word(struct pci_dev *dev, int where, u16 *val);
int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val);

int pci_write_config_byte(struct pci_dev *dev, int where, u8 val);
int pci_write_config_word(struct pci_dev *dev, int where, u16 val);
int pci_write_config_dword(struct pci_dev *dev, int where, u32 val);
```

### Capability Structures

PCIe devices advertise features through **capability structures** - linked lists of feature descriptors.

#### PCI Capabilities (Legacy, 256-byte space)

The **Capabilities Pointer** (offset 0x34) points to the first capability:

```
Capability Structure:
Offset  Size  Field
------  ----  -----
0x00    1     Capability ID
0x01    1     Next Capability Pointer (0x00 = end of list)
0x02    N     Capability-specific data
```

**Common Capability IDs**:
- 0x01: Power Management
- 0x05: MSI (Message Signaled Interrupts)
- 0x10: PCIe Express Capability
- 0x11: MSI-X

**Walking the capability list**:
```c
/* From drivers/pci/pci.c */
int pci_find_capability(struct pci_dev *dev, int cap)
{
    u16 status;
    u8 pos, id;
    
    /* Check if device has capabilities */
    pci_read_config_word(dev, PCI_STATUS, &status);
    if (!(status & PCI_STATUS_CAP_LIST))
        return 0;
    
    /* Get first capability pointer */
    pci_read_config_byte(dev, PCI_CAPABILITY_LIST, &pos);
    
    /* Walk list */
    while (pos) {
        pci_read_config_byte(dev, pos + PCI_CAP_LIST_ID, &id);
        if (id == cap)
            return pos;  /* Found */
        pci_read_config_byte(dev, pos + PCI_CAP_LIST_NEXT, &pos);
    }
    
    return 0;  /* Not found */
}
```

#### PCIe Extended Capabilities (4 KB space, offset 0x100+)

Extended capabilities start at offset 0x100 and use a different structure:

```
Extended Capability Structure:
Offset  Size  Field
------  ----  -----
0x00    2     Capability ID
0x02    2     Capability Version [3:0] | Next Capability Offset [31:20]
0x04    N     Capability-specific data
```

**Common Extended Capability IDs**:
- 0x0001: Advanced Error Reporting (AER)
- 0x0002: Virtual Channel
- 0x000B: Vendor-Specific Extended Capability
- 0x000D: Access Control Services (ACS)
- 0x0010: SR-IOV (Single Root I/O Virtualization)
- 0x001E: Data Link Feature

**Finding extended capabilities**:
```c
/* From include/linux/pci.h */
int pci_find_ext_capability(struct pci_dev *dev, int cap);
```

### MSI and MSI-X Configuration

**MSI (Message Signaled Interrupts)** and **MSI-X** allow devices to trigger interrupts by writing to memory, rather than using physical interrupt lines. For detailed information on MSI/MSI-X mechanisms, APIC architecture, interrupt delivery, and latency, see [Interrupts](./interrupts_hardware.md). For kernel software handling, see [Linux Interrupt Handling](./linux_interrupts.md). The configuration space aspect is covered here.

#### MSI Capability Structure

```
Offset  Size  Field
------  ----  -----
0x00    1     Capability ID (0x05)
0x01    1     Next Capability Pointer
0x02    2     Message Control Register
0x04    4     Message Address Lower 32 bits
0x08    4     Message Address Upper 32 bits (if 64-bit capable)
0x0C    2     Message Data
0x0E    2     Reserved
0x10    4     Mask Bits (if per-vector masking capable)
0x14    4     Pending Bits
```

**Message Control Register**:
```
Bits     Field
-------  -----
0        MSI Enable
3-1      Multiple Message Capable (device reports max vectors)
6-4      Multiple Message Enable (OS configures active vectors)
7        64-bit Address Capable
8        Per-Vector Masking Capable
```

#### MSI-X Capability Structure

MSI-X provides more interrupt vectors (up to 2048) and uses a separate table structure:

```
Offset  Size  Field
------  ----  -----
0x00    1     Capability ID (0x11)
0x01    1     Next Capability Pointer
0x02    2     Message Control Register
0x04    4     Table Offset and BAR Indicator
0x08    4     Pending Bit Array (PBA) Offset and BAR Indicator
```

**Message Control Register**:
```
Bits     Field
-------  -----
10-0     Table Size (N-1, max 2047 entries)
14       Function Mask (mask all vectors)
15       MSI-X Enable
```

The MSI-X table is stored in device memory (pointed to by BAR):

```c
/* MSI-X Table Entry (16 bytes each) */
struct msix_entry {
    u32 msg_addr_lo;    /* Message address lower 32 bits */
    u32 msg_addr_hi;    /* Message address upper 32 bits */
    u32 msg_data;       /* Message data */
    u32 vector_control; /* Bit 0: Mask bit */
};
```

**Linux MSI-X setup** (from ixgbe):
```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_lib.c */
static int ixgbe_acquire_msix_vectors(struct ixgbe_adapter *adapter)
{
    int vectors, vector_threshold;
    
    /* Calculate desired vectors (typically one per CPU) */
    vectors = min_t(int, num_online_cpus(), adapter->max_q_vectors);
    vector_threshold = MIN_MSIX_COUNT;
    
    /* Try to allocate MSI-X vectors */
    adapter->msix_entries = kcalloc(vectors, sizeof(struct msix_entry),
                                    GFP_KERNEL);
    if (!adapter->msix_entries)
        return -ENOMEM;
    
    for (vector = 0; vector < vectors; vector++)
        adapter->msix_entries[vector].entry = vector;
    
    /* Enable MSI-X */
    vectors = pci_enable_msix_range(adapter->pdev, adapter->msix_entries,
                                     vector_threshold, vectors);
    
    if (vectors < 0) {
        kfree(adapter->msix_entries);
        adapter->msix_entries = NULL;
        return vectors;
    }
    
    adapter->num_q_vectors = vectors;
    return 0;
}
```

The kernel programs the MSI-X table entries with appropriate memory addresses that route interrupts to specific CPUs, abstracting the hardware details from the driver.

---

This section covered PCIe addressing and configuration space in detail. The next section will walk through implementing a complete PCIe device driver, building on these fundamentals.

## Implementing a PCIe Device Driver

This section walks through the complete lifecycle of a PCIe device driver, from module initialization through device removal. We'll use the Intel ixgbe 10-Gigabit Ethernet driver as our primary example, as it's well-structured and demonstrates modern driver techniques.

### Driver Registration

A PCIe driver registers itself with the PCI subsystem using `struct pci_driver`:

```c
/* From include/linux/pci.h */
struct pci_driver {
    const char *name;                      /* Driver name */
    const struct pci_device_id *id_table;  /* Device matching table */
    
    int  (*probe)(struct pci_dev *dev, const struct pci_device_id *id);
    void (*remove)(struct pci_dev *dev);
    
    int  (*suspend)(struct pci_dev *dev, pm_message_t state);
    int  (*resume)(struct pci_dev *dev);
    void (*shutdown)(struct pci_dev *dev);
    
    const struct pci_error_handlers *err_handler;
    const struct attribute_group **groups;
    struct device_driver driver;
    
    /* SR-IOV support */
    int  (*sriov_configure)(struct pci_dev *dev, int num_vfs);
};
```

**Device ID table** specifies which devices the driver supports:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static const struct pci_device_id ixgbe_pci_tbl[] = {
    /* Intel 82599 10-Gigabit adapters */
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP), board_82599},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP_FCOE), board_82599},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KX4), board_82599},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KX4_MEZZ), board_82599},
    
    /* Intel X540 adapters */
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540T), board_X540},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540T1), board_X540},
    
    /* Intel X550 adapters */
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550T), board_x550},
    {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550EM_X_KX4), board_x550em_x},
    
    /* Sentinel - marks end of table */
    {0, }
};

/* Export table for module autoloading */
MODULE_DEVICE_TABLE(pci, ixgbe_pci_tbl);
```

The `PCI_VDEVICE` macro expands to:
```c
#define PCI_VDEVICE(vendor, device) \
    .vendor = PCI_VENDOR_ID_##vendor, \
    .device = device, \
    .subvendor = PCI_ANY_ID, \
    .subdevice = PCI_ANY_ID
```

So `PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP)` expands to:
```c
.vendor = 0x8086,                /* Intel */
.device = 0x10FB,                /* 82599 SFP */
.subvendor = PCI_ANY_ID,         /* Match any */
.subdevice = PCI_ANY_ID,         /* Match any */
.driver_data = board_82599       /* Private data passed to probe() */
```

**Module initialization**:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static struct pci_driver ixgbe_driver = {
    .name        = ixgbe_driver_name,
    .id_table    = ixgbe_pci_tbl,
    .probe       = ixgbe_probe,
    .remove      = ixgbe_remove,
    .suspend     = ixgbe_suspend,
    .resume      = ixgbe_resume,
    .shutdown    = ixgbe_shutdown,
    .sriov_configure = ixgbe_pci_sriov_configure,
    .err_handler = &ixgbe_err_handler,
};

static int __init ixgbe_init_module(void)
{
    int ret;
    
    pr_info("%s - version %s\n", ixgbe_driver_string, ixgbe_driver_version);
    pr_info("%s\n", ixgbe_copyright);
    
    /* Register with PCI subsystem */
    ret = pci_register_driver(&ixgbe_driver);
    if (ret)
        return ret;
    
    return 0;
}

module_init(ixgbe_init_module);

static void __exit ixgbe_exit_module(void)
{
    pci_unregister_driver(&ixgbe_driver);
}

module_exit(ixgbe_exit_module);
```

When `pci_register_driver()` is called:
1. The kernel adds the driver to its internal PCI driver list
2. For each discovered PCI device matching `id_table`, the kernel calls `probe()`
3. For hotplugged devices, `probe()` is called when the device appears

### Device Discovery and Probe

The `probe()` function is the heart of driver initialization. It's called when the kernel finds a matching device.

#### Probe Function Overview

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c (simplified) */
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    struct net_device *netdev;
    struct ixgbe_adapter *adapter;
    struct ixgbe_hw *hw;
    int err, indices;
    
    /* ==================== STEP 1: Enable PCI Device ==================== */
    
    err = pci_enable_device_mem(pdev);
    if (err)
        return err;
    
    /* ==================== STEP 2: Set DMA Addressing ==================== */
    
    /* Try 64-bit DMA first, fall back to 32-bit */
    if (!dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
        /* 64-bit DMA supported */
    } else {
        err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
        if (err) {
            dev_err(&pdev->dev, "No usable DMA configuration\n");
            goto err_dma;
        }
    }
    
    /* ==================== STEP 3: Reserve Memory Regions ==================== */
    
    err = pci_request_mem_regions(pdev, ixgbe_driver_name);
    if (err) {
        dev_err(&pdev->dev, "pci_request_mem_regions failed\n");
        goto err_pci_reg;
    }
    
    /* ==================== STEP 4: Enable Bus Mastering ==================== */
    
    pci_set_master(pdev);
    
    /* Save PCI state for power management */
    pci_save_state(pdev);
    
    /* ==================== STEP 5: Allocate Network Device ==================== */
    
    /* Determine number of queues (typically one per CPU) */
    indices = num_possible_cpus();
    
    /* Allocate net_device with private driver data */
    netdev = alloc_etherdev_mq(sizeof(struct ixgbe_adapter), indices);
    if (!netdev) {
        err = -ENOMEM;
        goto err_alloc_etherdev;
    }
    
    /* Link net_device to PCI device */
    SET_NETDEV_DEV(netdev, &pdev->dev);
    
    /* Get driver's private data area */
    adapter = netdev_priv(netdev);
    adapter->netdev = netdev;
    adapter->pdev = pdev;
    
    /* ==================== STEP 6: Map Device Registers ==================== */
    
    hw = &adapter->hw;
    hw->back = adapter;
    
    /* Map BAR 0 (device registers) into kernel virtual memory */
    hw->hw_addr = ioremap(pci_resource_start(pdev, 0),
                          pci_resource_len(pdev, 0));
    if (!hw->hw_addr) {
        err = -EIO;
        goto err_ioremap;
    }
    
    /* ==================== STEP 7: Initialize Device-Specific Hardware ==================== */
    
    /* Assign hardware-specific function pointers */
    ixgbe_assign_netdev_ops(netdev);
    ixgbe_set_ethtool_ops(netdev);
    
    /* Set watchdog timeout */
    netdev->watchdog_timeo = 5 * HZ;
    
    /* Identify hardware type and capabilities */
    err = ixgbe_sw_init(adapter);
    if (err)
        goto err_sw_init;
    
    /* Reset hardware to known state */
    err = hw->mac.ops.reset_hw(hw);
    if (err) {
        dev_err(&pdev->dev, "HW Init failed: %d\n", err);
        goto err_sw_init;
    }
    
    /* ==================== STEP 8: Read Device Configuration ==================== */
    
    /* Read MAC address from EEPROM/NVM */
    err = hw->mac.ops.get_mac_addr(hw, hw->mac.perm_addr);
    if (err) {
        dev_err(&pdev->dev, "failed to read MAC address\n");
        goto err_sw_init;
    }
    
    /* Set MAC address for net_device */
    memcpy(netdev->dev_addr, hw->mac.perm_addr, netdev->addr_len);
    memcpy(netdev->perm_addr, hw->mac.perm_addr, netdev->addr_len);
    
    /* Validate MAC address */
    if (!is_valid_ether_addr(netdev->dev_addr)) {
        dev_err(&pdev->dev, "invalid MAC address\n");
        err = -EIO;
        goto err_sw_init;
    }
    
    /* ==================== STEP 9: Setup Interrupts ==================== */
    
    /* Allocate MSI-X vectors (or fall back to MSI/legacy) */
    err = ixgbe_init_interrupt_scheme(adapter);
    if (err)
        goto err_sw_init;
    
    /* ==================== STEP 10: Configure Network Device Features ==================== */
    
    /* Enable hardware offloads */
    netdev->features |= NETIF_F_SG;              /* Scatter-gather I/O */
    netdev->features |= NETIF_F_TSO;             /* TCP segmentation offload */
    netdev->features |= NETIF_F_TSO6;            /* TCP segmentation offload (IPv6) */
    netdev->features |= NETIF_F_RXCSUM;          /* RX checksumming */
    netdev->features |= NETIF_F_HW_CSUM;         /* TX checksumming */
    netdev->features |= NETIF_F_RXHASH;          /* Receive hashing */
    netdev->features |= NETIF_F_HW_VLAN_CTAG_RX; /* VLAN RX offload */
    netdev->features |= NETIF_F_HW_VLAN_CTAG_TX; /* VLAN TX offload */
    
    /* Enable features that can be toggled by user */
    netdev->hw_features = netdev->features;
    
    /* ==================== STEP 11: Register Network Device ==================== */
    
    err = register_netdev(netdev);
    if (err)
        goto err_register;
    
    /* Device now appears as ethX in system */
    netdev_info(netdev, "Intel(R) 10 Gigabit Network Connection\n");
    
    /* ==================== STEP 12: Additional Configuration ==================== */
    
    /* Enable wake-on-LAN if supported */
    ixgbe_wol_supported(adapter);
    device_set_wakeup_enable(&pdev->dev, adapter->wol);
    
    /* Create sysfs entries for device management */
    ixgbe_sysfs_init(adapter);
    
    return 0;
    
/* ==================== Error Handling (unwind on failure) ==================== */
err_register:
    ixgbe_clear_interrupt_scheme(adapter);
err_sw_init:
    ixgbe_disable_sriov(adapter);
    iounmap(hw->hw_addr);
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

#### Key Steps Explained

**1. Enable PCI Device**

```c
int pci_enable_device_mem(struct pci_dev *dev);
```

This function:
- Wakes the device from low-power state if needed
- Enables memory space in the Command Register (bit 1)
- Allocates resources if not already done by BIOS

Variant functions:
- `pci_enable_device()`: Enables both memory and I/O space
- `pci_enable_device_io()`: Enables only I/O space

**2. Set DMA Mask**

```c
int dma_set_mask_and_coherent(struct device *dev, u64 dma_mask);
```

Tells the kernel the device's DMA addressing capability:
- `DMA_BIT_MASK(64)`: Device can address full 64-bit address space
- `DMA_BIT_MASK(32)`: Device limited to 32-bit addressing (4 GB)

This affects:
- Whether the kernel can use high memory (>4 GB) for DMA buffers
- Whether IOMMU address translation is needed
- SWIOTLB bounce buffer usage

**Why try 64-bit first?**
- Avoids bounce buffers on systems with >4 GB RAM
- Better performance (no copying to/from low memory)
- Some devices support 64-bit for streaming DMA but only 32-bit for coherent DMA

**3. Request Memory Regions**

```c
int pci_request_mem_regions(struct pci_dev *pdev, const char *name);
```

Marks the device's BARs as in-use by this driver:
- Prevents other drivers from claiming the same resources
- Records ownership for debugging (`/proc/iomem`)
- Must be called before `ioremap()`

Internally, for each BAR:
```c
resource = request_mem_region(pci_resource_start(pdev, bar),
                               pci_resource_len(pdev, bar),
                               driver_name);
```

**4. Enable Bus Mastering**

```c
void pci_set_master(struct pci_dev *dev);
```

Sets bit 2 (Bus Master Enable) in the PCI Command Register, allowing the device to initiate DMA transactions. Without this, the device cannot:
- Perform DMA reads/writes
- Generate memory write TLPs
- Act as a requester on the PCIe bus

**5. Map Device Registers**

```c
void __iomem *ioremap(phys_addr_t phys_addr, unsigned long size);
```

Creates a kernel virtual mapping for device MMIO registers:

```
Physical Address Space:          Kernel Virtual Address Space:
┌─────────────────────┐         ┌─────────────────────┐
│  System RAM         │         │  Direct map         │
│  0x00000000-...     │         │  (RAM)              │
├─────────────────────┤         ├─────────────────────┤
│  PCIe MMIO          │◄────┐   │  vmalloc area       │
│  0xF7E00000-...     │     │   ├─────────────────────┤
│  (BAR 0)            │     │   │  ioremap area       │
└─────────────────────┘     └───┤  0xFFFFC90000000000-│
                                │  (BAR 0 mapped)     │
                                └─────────────────────┘
```

The returned address is used to access device registers:
```c
/* Read register at offset 0x100 */
u32 val = readl(hw->hw_addr + 0x100);

/* Write register at offset 0x200 */
writel(0xDEADBEEF, hw->hw_addr + 0x200);
```

**Important**: Must use special accessor functions (`readl`, `writel`, etc.) not direct pointer dereference, to ensure proper memory ordering and cache behavior.

**6. Hardware Reset and Initialization**

Each device requires hardware-specific initialization:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_common.c */
s32 ixgbe_reset_hw_82599(struct ixgbe_hw *hw)
{
    u32 ctrl, ctrl_ext;
    u32 reset_bit;
    s32 status;
    
    /* Issue global reset to device */
    ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
    ctrl |= IXGBE_CTRL_RST;
    IXGBE_WRITE_REG(hw, IXGBE_CTRL, ctrl);
    IXGBE_WRITE_FLUSH(hw);
    
    /* Wait for reset to complete (hardware clears bit when done) */
    for (i = 0; i < 10; i++) {
        udelay(1);
        ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
        if (!(ctrl & IXGBE_CTRL_RST))
            break;
    }
    
    if (ctrl & IXGBE_CTRL_RST) {
        status = IXGBE_ERR_RESET_FAILED;
        hw_dbg(hw, "Reset polling failed to complete.\n");
    }
    
    /* Additional hardware-specific initialization */
    msleep(50);  /* Allow firmware to complete initialization */
    
    return status;
}
```

### Interrupt Setup

Modern drivers use MSI-X for efficient multi-queue operation. The setup typically follows this pattern:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static int ixgbe_init_interrupt_scheme(struct ixgbe_adapter *adapter)
{
    int err;
    
    /* Allocate queue vectors (interrupt handlers) */
    err = ixgbe_alloc_q_vectors(adapter);
    if (err) {
        dev_err(&adapter->pdev->dev, "Unable to allocate memory for queue vectors\n");
        goto err_alloc_q_vectors;
    }
    
    /* Allocate TX/RX ring structures */
    err = ixgbe_alloc_queues(adapter);
    if (err) {
        dev_err(&adapter->pdev->dev, "Unable to allocate memory for queues\n");
        goto err_alloc_queues;
    }
    
    /* Try MSI-X, fall back to MSI, then legacy */
    err = ixgbe_set_interrupt_capability(adapter);
    if (err) {
        dev_err(&adapter->pdev->dev, "Unable to setup interrupt capabilities\n");
        goto err_set_interrupt;
    }
    
    return 0;
    
err_set_interrupt:
    ixgbe_free_queues(adapter);
err_alloc_queues:
    ixgbe_free_q_vectors(adapter);
err_alloc_q_vectors:
    return err;
}
```

**MSI-X vector allocation**:

```c
static int ixgbe_set_interrupt_capability(struct ixgbe_adapter *adapter)
{
    int vector, v_budget;
    
    /* Calculate desired vectors: one per RX/TX queue pair + 1 for misc */
    v_budget = max_t(int, adapter->num_rx_queues, adapter->num_tx_queues);
    v_budget = min_t(int, v_budget, num_online_cpus());
    v_budget++;  /* Additional vector for link status, etc. */
    
    /* Prepare MSI-X entries */
    adapter->msix_entries = kcalloc(v_budget, sizeof(struct msix_entry),
                                     GFP_KERNEL);
    if (!adapter->msix_entries)
        return -ENOMEM;
    
    for (vector = 0; vector < v_budget; vector++)
        adapter->msix_entries[vector].entry = vector;
    
    /* Try to enable MSI-X */
    vector = pci_enable_msix_range(adapter->pdev,
                                    adapter->msix_entries,
                                    MIN_MSIX_COUNT,
                                    v_budget);
    
    if (vector > 0) {
        adapter->num_q_vectors = vector - 1;  /* Reserve one for misc */
        adapter->flags |= IXGBE_FLAG_MSIX_ENABLED;
        return 0;
    }
    
    /* MSI-X failed, try MSI */
    kfree(adapter->msix_entries);
    adapter->msix_entries = NULL;
    
    if (pci_enable_msi(adapter->pdev) == 0) {
        adapter->flags |= IXGBE_FLAG_MSI_ENABLED;
        return 0;
    }
    
    /* Fall back to legacy INTx interrupts */
    return 0;
}
```

**Request IRQ for each vector**:

```c
static int ixgbe_request_msix_irqs(struct ixgbe_adapter *adapter)
{
    int vector, err;
    
    /* Register IRQ handler for each queue vector */
    for (vector = 0; vector < adapter->num_q_vectors; vector++) {
        struct ixgbe_q_vector *q_vector = adapter->q_vector[vector];
        struct msix_entry *entry = &adapter->msix_entries[vector];
        
        /* Request IRQ */
        err = request_irq(entry->vector,              /* IRQ number from kernel */
                          &ixgbe_msix_clean_rings,    /* Interrupt handler */
                          0,                           /* Flags */
                          q_vector->name,             /* Name for /proc/interrupts */
                          q_vector);                   /* Private data */
        if (err) {
            dev_err(&adapter->pdev->dev,
                   "request_irq failed for MSIX interrupt %d\n", entry->vector);
            goto free_queue_irqs;
        }
        
        /* Set interrupt affinity to specific CPU */
        irq_set_affinity_hint(entry->vector, &q_vector->affinity_mask);
    }
    
    /* Register handler for misc events (link status changes, etc.) */
    err = request_irq(adapter->msix_entries[vector].vector,
                      ixgbe_msix_other, 0, adapter->name, adapter);
    if (err)
        goto free_queue_irqs;
    
    return 0;
    
free_queue_irqs:
    while (vector) {
        vector--;
        free_irq(adapter->msix_entries[vector].vector,
                 adapter->q_vector[vector]);
    }
    pci_disable_msix(adapter->pdev);
    kfree(adapter->msix_entries);
    adapter->msix_entries = NULL;
    return err;
}
```

### Device Removal

The `remove()` function cleans up all resources allocated during `probe()`:

```c
/* From drivers/net/ethernet/intel/ixgbe/ixgbe_main.c */
static void ixgbe_remove(struct pci_dev *pdev)
{
    struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
    struct net_device *netdev;
    
    /* Handle case where device wasn't fully initialized */
    if (!adapter)
        return;
    
    netdev = adapter->netdev;
    
    /* Remove sysfs entries */
    ixgbe_sysfs_exit(adapter);
    
    /* Unregister from networking subsystem */
    unregister_netdev(netdev);
    
    /* Disable SR-IOV if enabled */
    ixgbe_disable_sriov(adapter);
    
    /* Free interrupt resources */
    ixgbe_clear_interrupt_scheme(adapter);
    
    /* Unmap device registers */
    iounmap(adapter->hw.hw_addr);
    
    /* Release PCI regions */
    pci_release_mem_regions(pdev);
    
    /* Free network device structure */
    free_netdev(netdev);
    
    /* Disable PCI device */
    pci_disable_device(pdev);
}
```

**Order matters in cleanup**:
1. Stop device from generating interrupts/DMA
2. Unregister from subsystems (networking, sysfs)
3. Free IRQs
4. Unmap MMIO regions
5. Release PCI resources
6. Free memory structures

**Common mistake**: Freeing memory while device can still DMA to it → memory corruption or crashes.

### Power Management

Drivers should implement suspend/resume for system power management:

```c
static int ixgbe_suspend(struct pci_dev *pdev, pm_message_t state)
{
    struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
    struct net_device *netdev = adapter->netdev;
    int retval = 0;
    
    /* Stop network interface */
    netif_device_detach(netdev);
    
    if (netif_running(netdev)) {
        /* Close device */
        ixgbe_close(netdev);
    }
    
    /* Disable interrupts */
    ixgbe_clear_interrupt_scheme(adapter);
    
    /* Enable wake-on-LAN if configured */
    if (adapter->wol) {
        ixgbe_set_rx_mode(netdev);
        ixgbe_configure_wol(adapter);
    }
    
    /* Save PCI configuration space */
    pci_save_state(pdev);
    
    /* Disable device */
    pci_disable_device(pdev);
    
    /* Set power state */
    pci_set_power_state(pdev, pci_choose_state(pdev, state));
    
    return retval;
}

static int ixgbe_resume(struct pci_dev *pdev)
{
    struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
    struct net_device *netdev = adapter->netdev;
    int err;
    
    /* Restore power state */
    pci_set_power_state(pdev, PCI_D0);
    
    /* Restore PCI configuration space */
    pci_restore_state(pdev);
    
    /* Re-enable device */
    err = pci_enable_device_mem(pdev);
    if (err) {
        dev_err(&pdev->dev, "Cannot enable PCI device from suspend\n");
        return err;
    }
    
    /* Re-enable bus mastering */
    pci_set_master(pdev);
    
    /* Reset hardware */
    ixgbe_reset(adapter);
    
    /* Restore interrupt scheme */
    err = ixgbe_init_interrupt_scheme(adapter);
    if (err) {
        dev_err(&pdev->dev, "Cannot initialize interrupts\n");
        return err;
    }
    
    /* Reopen device if it was running */
    if (netif_running(netdev)) {
        err = ixgbe_open(netdev);
        if (err)
            return err;
    }
    
    /* Reattach network interface */
    netif_device_attach(netdev);
    
    return 0;
}
```

---

This completes the PCIe device driver implementation section. For information on how PCIe devices perform data transfers using DMA and IOMMU, see the [DMA & IOMMU](./dma.md) chapter.
