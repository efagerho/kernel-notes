# Interrupts

## Overview

Interrupts are a fundamental mechanism in the Linux kernel that allow hardware devices and the CPU itself to signal events that require immediate attention. Rather than polling devices constantly, the kernel can respond to events asynchronously as they occur.

Linux uses a **two-level interrupt handling model**:

1. **Hardware Interrupts (Hardirqs)**: The immediate, fast response to hardware signals. On entry, the CPU disables further maskable interrupts on the *local CPU* (and the kernel treats hardirq context as non-preemptible); handlers must do minimal work and return quickly.

2. **Software Interrupts (Softirqs)**: Deferred work that can be processed later in a safer context. These allow the kernel to defer heavy processing out of the time-critical hardirq context.

This split allows the kernel to acknowledge hardware quickly (in the hardirq) while deferring expensive processing (to softirqs), balancing responsiveness with throughput.

**Key principle**: Hardirqs do minimal work and defer everything else to softirqs or other bottom-half mechanisms.

## Hardware Interrupts (Hardirqs)

### What are Hardware Interrupts?

Hardware interrupts are signals sent to the CPU that cause it to suspend its current execution and jump to an interrupt handler. They are the primary way devices communicate with the kernel.

**Types of interrupts**:

1. **External Interrupts (Device IRQs)**:
   - Raised by hardware devices (network cards, disk controllers, timers, etc.)
   - Come through interrupt controller (APIC on modern systems)
   - Asynchronous to CPU execution

2. **Exceptions**:
   - Raised by the CPU itself
   - Examples: page faults, divide by zero, invalid opcodes
   - Synchronous to CPU execution

3. **Non-Maskable Interrupts (NMI)**:
   - Cannot be disabled
   - Used for critical events (hardware errors, watchdog timers)
   - Highest priority

### Interrupt Descriptor Table (IDT)

The **Interrupt Descriptor Table (IDT)** is a data structure that maps interrupt vectors (numbers 0-255) to their handler functions.

**Structure**:

```c
/* From arch/x86/include/asm/desc_defs.h */
struct gate_struct {
    u16 offset_low;      /* Offset bits 0-15 */
    u16 segment;         /* Segment selector */
    u16 ist : 3;         /* Interrupt Stack Table offset */
    u16 zero : 5;
    u16 type : 5;        /* Gate type */
    u16 dpl : 2;         /* Descriptor Privilege Level */
    u16 p : 1;           /* Present */
    u16 offset_middle;   /* Offset bits 16-31 */
    u32 offset_high;     /* Offset bits 32-63 */
    u32 reserved;
} __attribute__((packed));
```

Each IDT entry points to an interrupt handler in kernel code. When an interrupt occurs:

1. CPU looks up the vector in the IDT
2. Loads the handler address from the IDT entry
3. Switches to kernel mode (Ring 0)
4. Jumps to the handler

**IDT Initialization**:

```c
/* From arch/x86/kernel/idt.c */
void __init idt_setup_traps(void)
{
    /* Install exception handlers (vectors 0-31) */
    idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}

void __init idt_setup_apic_and_irq_gates(void)
{
    /* Install IRQ handlers (vectors 32-255) */
    idt_setup_from_table(idt_table, apic_idts, ARRAY_SIZE(apic_idts), true);
}
```

The IDT is loaded into the CPU using the `lidt` instruction during kernel initialization.

### Interrupt Vector Allocation

On AMD64, the CPU provides 256 interrupt vectors (0–255). Linux uses them roughly like this (exact allocation varies by kernel version, configuration, and platform):

- **0–31**: Reserved for CPU-defined exceptions (page fault, divide error, etc.).
- **0x20 (32) and up**: Typically used for external interrupts (device IRQs), but allocated dynamically.
- **High vectors**: Reserved for local-APIC related purposes (IPIs, timers, special vectors). The exact ranges are not ABI-stable.
- **0x80 (128)**: Historically used for `int 0x80` syscalls. On x86-64, the normal system call mechanism is `syscall`, so treat `0x80` as legacy/compat.

**IRQ to Vector Mapping**:

```
IRQ Number → APIC → Interrupt Vector → IDT Entry → Handler

Example:
IRQ 5 (sound card) → APIC remapping → Vector 37 → IDT[37] → sound_interrupt_handler()
```

**APIC (Advanced Programmable Interrupt Controller)**:
- Modern interrupt controller replacing the old 8259 PIC
- Supports per-CPU local APICs
- Allows interrupt routing and prioritization
- Delivers interrupts to specific CPUs

### Hardware Interrupt Flow

When a device raises an interrupt, the following sequence occurs:

```
Device
   │
   │ Assert IRQ line
   ▼
APIC (I/O APIC)
   │
   │ Route to CPU's Local APIC
   ▼
CPU Local APIC
   │
   │ Interrupt vector determined
   ▼
CPU checks interrupts
   │
   │ IF flag = 1 (interrupts enabled)?
   ▼
CPU Interrupt
   │
   ├─ Save current RIP, RSP, RFLAGS
   ├─ Look up vector in IDT
   ├─ Load handler address
   ├─ Switch to kernel stack (if from user mode)
   └─ Jump to interrupt entry point
   │
   ▼
entry_64.S (Assembly)
   │
   ├─ Save all registers (pt_regs)
   ├─ Switch to kernel GS
   ├─ Call interrupt handler
   │
   ▼
common_interrupt / do_IRQ (C)
   │
   ├─ irq_enter() (mark hardirq context)
   ├─ Call device-specific handler
   ├─ irq_exit() (check for softirqs)
   │
   ▼
Interrupt Exit
   │
   ├─ Restore registers
   ├─ Execute IRET instruction
   │
   ▼
Return to interrupted code
```

**Entry through `entry_64.S`**:

The low-level interrupt entry is handled in assembly. The exact symbol names change across kernel versions; the snippet below is pseudocode showing the typical structure:

```asm
/* Conceptual flow; see arch/x86/entry/entry_64.S and arch/x86/include/asm/idtentry.h */
interrupt_entry:
    /* Save registers */
    PUSH_REGS
    
    /* Call C interrupt handler */
    call irqentry_dispatch
    
    /* Restore and return */
    POP_REGS
    iretq
```

The assembly code:
1. Saves all general-purpose registers onto the stack (creating `struct pt_regs`)
2. Switches segment registers (GS) to kernel mode
3. Calls the C interrupt handler
4. Restores registers and returns using `iretq`

### Interrupt Dispatch - The C Handler

Modern kernels dispatch device interrupts through the generic IRQ subsystem (exact entry function names vary). Conceptually, the dispatcher:

```c
/* Conceptual; see arch/x86/kernel/irq.c and kernel/irq/ */
void irq_dispatch(struct pt_regs *regs, unsigned long vector)
{
    struct pt_regs *old_regs = set_irq_regs(regs);
    
    /* Enter interrupt context */
    irq_enter();
    
    /* Find the IRQ number from the vector */
    unsigned int irq = __this_cpu_read(vector_irq[vector]);
    
    if (likely(irq < NR_IRQS)) {
        /* Call the registered handler for this IRQ */
        generic_handle_irq(irq);
    } else {
        /* Spurious interrupt */
        ack_APIC_irq();
    }
    
    /* Exit interrupt context (may invoke softirqs) */
    irq_exit();
    
    set_irq_regs(old_regs);
}
```

The handler:
1. Enters interrupt context with `irq_enter()`
2. Maps the interrupt vector to an IRQ number
3. Calls `generic_handle_irq()` which invokes the device-specific handler
4. Exits interrupt context with `irq_exit()` (critical for softirq processing)

**Finding the Handler**:

```c
/* From kernel/irq/chip.c */
int generic_handle_irq(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);
    
    if (!desc)
        return -EINVAL;
    
    /* Call the action handler(s) for this IRQ */
    generic_handle_irq_desc(desc);
    
    return 0;
}
```

Each IRQ has an `irq_desc` structure that contains:
- The handler function registered by the device driver
- IRQ flags and state
- Statistics counters

### Top Half Handler

The **top half** is the device-specific interrupt handler that runs in hardirq context:

```c
/* Example: Network card interrupt handler */
static irqreturn_t my_network_interrupt(int irq, void *dev_id)
{
    struct net_device *dev = dev_id;
    
    /* Read interrupt status from device */
    u32 status = read_interrupt_status(dev);
    
    /* Acknowledge interrupt at device level */
    write_interrupt_ack(dev, status);
    
    /* Disable device interrupts temporarily */
    disable_device_interrupts(dev);
    
    /* Schedule bottom half (softirq) to process packets */
    napi_schedule(&dev->napi);
    
    return IRQ_HANDLED;
}
```

**Constraints in Hardirq Context**:

1. **Must be fast**: Minimize time with interrupts disabled
2. **Cannot sleep**: No locks that might sleep, no `schedule()`
3. **Cannot access user space**: No `copy_to_user()` or similar
4. **Preemption is disabled**: Cannot be preempted
5. **Other interrupts may be disabled**: On the same CPU

**What to do**:
- Acknowledge the hardware
- Read minimal device state
- Schedule deferred work (softirq, tasklet, workqueue)
- Return quickly

**What NOT to do**:
- Heavy computation
- I/O operations
- Memory allocations (use `GFP_ATOMIC` if necessary)
- Wait for anything

## Interrupt Context Management

### `irq_enter()` - Entering Interrupt Context

Before calling the device handler, the kernel marks that it's in interrupt context:

```c
/* From kernel/softirq.c */
void irq_enter(void)
{
    int cpu = smp_processor_id();
    
    /* Increment preempt count to mark hardirq context */
    __irq_enter();
    
    /* Account for IRQ time */
    account_irq_enter_time(current);
    
    /* Update vtime for current task */
    vtime_account_irq_enter(current);
}

static inline void __irq_enter(void)
{
    preempt_count_add(HARDIRQ_OFFSET);
    trace_hardirq_enter();
}
```

The key operation is incrementing the **preempt count**:

```c
/* Preempt count layout (simplified) */
#define PREEMPT_BITS      8
#define SOFTIRQ_BITS      8
#define HARDIRQ_BITS      4
#define NMI_BITS          1

/*
 * Bits 0-7:   Preemption count (0 means preemptible)
 * Bits 8-15:  Softirq count
 * Bits 16-19: Hardirq count
 * Bit  20:    NMI context
 */
```

Setting the HARDIRQ bits in preempt_count indicates:
- We're in interrupt context (`in_irq()` returns true)
- We're in interrupt context broadly (`in_interrupt()` returns true)
- Preemption is disabled
- Scheduling is not allowed

### `irq_exit()` - Exiting Interrupt Context

This is the **critical function** where softirqs are invoked:

```c
/* From kernel/softirq.c */
void irq_exit(void)
{
    /* Account for IRQ time */
    account_irq_exit_time(current);
    
    /* Decrement hardirq count */
    preempt_count_sub(HARDIRQ_OFFSET);
    
    /* 
     * CRITICAL: Check if we should invoke softirqs
     * This is the PRIMARY execution point for softirqs
     */
    if (!in_interrupt() && local_softirq_pending())
        invoke_softirq();
    
    /* Handle RCU and tick processing */
    tick_irq_exit();
}
```

**Key Logic**:

```c
/* Check if softirqs should run */
if (!in_interrupt() &&           /* Not in nested interrupt */
    local_softirq_pending())     /* Softirqs were raised */
{
    invoke_softirq();            /* Execute them now! */
}
```

This is the main mechanism by which softirqs get executed. When a hardirq handler calls `raise_softirq()`, the softirq is marked as pending. Then, when the interrupt exits via `irq_exit()`, the pending softirqs are executed.

## Software Interrupts (Softirqs)

### What are Softirqs?

**Softirqs** (software interrupts) are a mechanism for deferring work out of hardirq context. They allow interrupt handlers to schedule work that can be done later, outside the time-critical hardirq context.

**Purpose**:
- Defer heavy processing from hardirqs
- Allow interrupts to be re-enabled sooner
- Process batches of work efficiently
- Improve system responsiveness

**Key differences from hardirqs**:

| Aspect | Hardirqs | Softirqs |
|--------|----------|----------|
| Trigger | Hardware signal | Raised by kernel code |
| Context | Hardirq context | Softirq context |
| Interrupts | Often disabled | Enabled |
| Preemption | Disabled | Disabled |
| Priority | Higher | Lower |
| Execution | Immediate | Deferred |

### Softirq Types

The kernel defines a fixed set of softirq types:

```c
/* From include/linux/interrupt.h */
enum
{
    HI_SOFTIRQ=0,        /* High-priority tasklets */
    TIMER_SOFTIRQ,       /* Timer callbacks */
    NET_TX_SOFTIRQ,      /* Network packet transmission */
    NET_RX_SOFTIRQ,      /* Network packet reception */
    BLOCK_SOFTIRQ,       /* Block device operations */
    IRQ_POLL_SOFTIRQ,    /* IRQ polling */
    TASKLET_SOFTIRQ,     /* Regular tasklets */
    SCHED_SOFTIRQ,       /* Scheduler operations */
    HRTIMER_SOFTIRQ,     /* High-resolution timers */
    RCU_SOFTIRQ,         /* RCU callbacks */
    
    NR_SOFTIRQS          /* Total number of softirqs */
};
```

**Common softirqs**:

1. **NET_RX_SOFTIRQ / NET_TX_SOFTIRQ**: 
   - Process received/transmitted network packets
   - Run protocol stack processing
   - Called after network interrupt

2. **BLOCK_SOFTIRQ**:
   - Handle completed block I/O requests
   - Run block layer completion callbacks

3. **TIMER_SOFTIRQ**:
   - Execute expired timer callbacks
   - Process timer wheel

4. **TASKLET_SOFTIRQ**:
   - Run scheduled tasklets
   - Used by many device drivers

5. **SCHED_SOFTIRQ**:
   - Trigger scheduler operations
   - Run load balancing

6. **RCU_SOFTIRQ**:
   - Process RCU callbacks
   - Handle deferred memory reclamation

### Raising Softirqs

Softirqs are scheduled (raised) by calling `raise_softirq()`:

```c
/* From kernel/softirq.c */
void raise_softirq(unsigned int nr)
{
    unsigned long flags;
    
    /* Disable interrupts to protect per-CPU data */
    local_irq_save(flags);
    
    /* Mark this softirq as pending */
    raise_softirq_irqoff(nr);
    
    local_irq_restore(flags);
}

inline void raise_softirq_irqoff(unsigned int nr)
{
    /* Set the bit in the pending bitmask */
    __raise_softirq_irqoff(nr);
    
    /*
     * If we're not already in an interrupt, and not in softirq processing,
     * wake up ksoftirqd to handle it
     */
    if (!in_interrupt())
        wakeup_softirqd();
}
```

**The Pending Bitmask**:

Each CPU has a per-CPU softirq pending bitmask:

```c
/* Per-CPU softirq state */
DEFINE_PER_CPU(u32, softirq_pending);

/* Check if softirqs are pending */
#define local_softirq_pending() \
    this_cpu_read(softirq_pending)

/* Set a softirq as pending */
#define __raise_softirq_irqoff(nr) \
    do { \
        this_cpu_or(softirq_pending, 1UL << (nr)); \
    } while (0)
```

Example:
```
Initial:  softirq_pending = 0b00000000
Raise NET_RX_SOFTIRQ (bit 3): 
After:    softirq_pending = 0b00001000
```

### Softirq Execution Points

This is a critical concept: **When do softirqs actually run?**

Softirqs execute at three main points:

#### 1. During `irq_exit()` - PRIMARY EXECUTION POINT

```c
void irq_exit(void)
{
    /* ... */
    
    /* If softirqs are pending and we're leaving interrupt context */
    if (!in_interrupt() && local_softirq_pending())
        invoke_softirq();  /* <-- Softirqs run HERE */
}
```

This is the **most common** softirq execution point. When returning from a hardware interrupt, if any softirqs were raised during the interrupt, they execute now.

**Example flow**:
```
1. Network card raises interrupt
2. Hardirq handler runs
3. Handler calls napi_schedule() which raises NET_RX_SOFTIRQ
4. Handler returns
5. irq_exit() is called
6. irq_exit() sees NET_RX_SOFTIRQ is pending
7. irq_exit() calls invoke_softirq()
8. NET_RX_SOFTIRQ handler processes packets
9. Return to interrupted context
```

#### 2. In `ksoftirqd` Kernel Threads

Each CPU has a `ksoftirqd/N` kernel thread that processes softirqs when they become too frequent:

```c
/* From kernel/softirq.c */
static int ksoftirqd(void *__bind_cpu)
{
    while (!kthread_should_stop()) {
        /* Sleep until woken */
        schedule();
        
        /* Process pending softirqs */
        while (local_softirq_pending()) {
            __do_softirq();
            cond_resched();  /* Allow other tasks to run */
        }
    }
    
    return 0;
}
```

`ksoftirqd` is woken when:

1. Softirqs are raised outside interrupt context
1. Softirqs are taking too long in `__do_softirq()`
1. System is under heavy softirq load

Softirqs can be raised from many places, not just hardware interrupts. This happens
for instance in the networking code, block layer and in timers. Raising a softirq mostly
means **marking it pending**; execution happens later at well-defined points (e.g. on
interrupt exit via `irq_exit()`, when bottom halves are re-enabled via
`local_bh_enable()`, or in `ksoftirqd`). When softirqs are raised outside interrupt
context, the kernel may wake `ksoftirqd` so the pending work is handled soon without
recursing into softirq processing from arbitrary call sites.

The kernel has an execution time limit for softirqs. If the kernel is not able to
process all raised softirqs before running out of its execution time quota, then it
will wakeup `ksoftirqd` to handle remaining softirqs.

Under high softirq load, the kernel will constantly run out of time to process
softirqs and will transition into a mode where practically all softirqs are handled
by `ksoftirqd`.

#### 3. Explicit `local_bh_enable()` Calls

When kernel code re-enables bottom halves (after disabling them):

```c
void local_bh_enable(void)
{
    /* Decrement softirq disable count */
    if (softirq_count() == SOFTIRQ_OFFSET) {
        /* If softirqs are pending, run them */
        if (local_softirq_pending())
            do_softirq();
    }
    
    preempt_count_sub(SOFTIRQ_OFFSET);
}
```

This allows code that temporarily disabled softirqs to trigger their execution when re-enabling them.

### `__do_softirq()` - The Softirq Executor

This is the main function that executes pending softirqs:

```c
/* From kernel/softirq.c */
asmlinkage __visible void __do_softirq(void)
{
    unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
    unsigned long old_flags = current->flags;
    int max_restart = MAX_SOFTIRQ_RESTART;
    struct softirq_action *h;
    u32 pending;
    
    /* Mark we're in softirq context */
    __local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
    
    /* Get pending softirqs */
    pending = local_softirq_pending();
    
    /* Clear the pending bits we're about to handle */
    set_softirq_pending(0);
    
    /* Re-enable interrupts - key difference from hardirqs */
    local_irq_enable();
    
    h = softirq_vec;
    
restart:
    /* Loop through all softirq types */
    while (pending) {
        if (pending & 1) {
            /* Call the softirq handler */
            h->action(h);
        }
        pending >>= 1;
        h++;
    }
    
    local_irq_disable();
    
    /* Check if new softirqs were raised */
    pending = local_softirq_pending();
    if (pending) {
        if (time_before(jiffies, end) && !need_resched() &&
            --max_restart)
            goto restart;  /* Process more softirqs */
        
        /* Too much work - wake ksoftirqd instead */
        wakeup_softirqd();
    }
    
    /* Leave softirq context */
    __local_bh_enable(SOFTIRQ_OFFSET);
}
```

**Key points**:

1. **Interrupts are re-enabled**: Unlike hardirqs, softirqs run with interrupts enabled, allowing higher-priority hardirqs to preempt them.

2. **Loops through pending softirqs**: Checks each bit in the pending mask and calls registered handlers.

3. **Time limit**: Will only process softirqs for `MAX_SOFTIRQ_TIME` (typically 2ms).

4. **Restart limit**: Will only loop `MAX_SOFTIRQ_RESTART` times (typically 10).

5. **Fallback to ksoftirqd**: If there's too much work, wakes up the `ksoftirqd` thread instead of blocking the current context.

**Handler Registration**:

```c
/* Softirq handler function type */
typedef void (*softirq_action_fn)(struct softirq_action *);

/* Array of softirq handlers */
static struct softirq_action softirq_vec[NR_SOFTIRQS];

/* Register a softirq handler */
void open_softirq(int nr, softirq_action_fn action)
{
    softirq_vec[nr].action = action;
}
```

Example registrations:
```c
/* Network RX softirq */
open_softirq(NET_RX_SOFTIRQ, net_rx_action);

/* Timer softirq */
open_softirq(TIMER_SOFTIRQ, run_timer_softirq);
```

### `ksoftirqd` Threads

Each CPU has a dedicated kernel thread for processing softirqs:

```bash
$ ps aux | grep ksoftirqd
root      12  0.0  0.0      0     0 ?   S   00:00   0:00 [ksoftirqd/0]
root      23  0.0  0.0      0     0 ?   S   00:00   0:00 [ksoftirqd/1]
root      28  0.0  0.0      0     0 ?   S   00:00   0:00 [ksoftirqd/2]
root      33  0.0  0.0      0     0 ?   S   00:00   0:00 [ksoftirqd/3]
```

It's main purpose is to prevent softirq processing from monopolizing
CPU time. The ksoftirqd kernel thread is executed by the scheduler
according to scheduler priorities.

## Execution Context Hierarchy

### Context Types

The kernel operates in different execution contexts, each with different constraints:

```
Priority (Highest to Lowest):
    
    ┌─────────────────────┐
    │   NMI Context       │  Cannot be interrupted
    │   (in_nmi())        │  Most restricted
    └─────────────────────┘
            ↑
    ┌─────────────────────┐
    │  Hardirq Context    │  Interrupts may be disabled
    │  (in_irq())         │  Very restricted
    └─────────────────────┘
            ↑
    ┌─────────────────────┐
    │  Softirq Context    │  Interrupts enabled
    │  (in_softirq())     │  Moderately restricted
    └─────────────────────┘
            ↑
    ┌─────────────────────┐
    │  Process Context    │  Most flexible
    │  (normal code)      │  Can sleep, schedule
    └─────────────────────┘
```

**1. NMI Context** (`in_nmi()` returns true):
- Non-Maskable Interrupt
- Cannot be interrupted by anything
- Must be extremely careful with shared data
- Used for watchdogs, profiling, critical errors

**2. Hardirq Context** (`in_irq()` returns true):
- Running in hardware interrupt handler
- Cannot sleep or schedule
- May have interrupts disabled
- Must be fast

**3. Softirq Context** (`in_softirq()` returns true):
- Running in softirq handler or with bottom halves disabled
- Interrupts are enabled
- Cannot sleep
- More time allowed than hardirq

**4. Process Context**:
- Normal kernel code (system calls, kernel threads)
- Can sleep and be scheduled
- Can access user space
- Most flexible

### Context Checking

The kernel provides macros to check the current context:

```c
/* From include/linux/preempt.h */

/* Are we in interrupt context? (hardirq OR softirq OR nmi) */
#define in_interrupt()  (irq_count())

/* Are we in hardirq context? */
#define in_irq()        (hardirq_count())

/* Are we in softirq context? */
#define in_softirq()    (softirq_count())

/* Are we in NMI context? */
#define in_nmi()        (nmi_count())
```

These use the preempt count:

```c
/*
 * Preempt count bit layout:
 * 
 *  PREEMPT_MASK:  0x000000ff  (preemption disabled count)
 *  SOFTIRQ_MASK:  0x0000ff00  (softirq disabled count)
 *  HARDIRQ_MASK:  0x000f0000  (hardirq count)
 *  NMI_MASK:      0x00100000  (nmi context)
 */

#define PREEMPT_BITS    8
#define SOFTIRQ_BITS    8
#define HARDIRQ_BITS    4
#define NMI_BITS        1

#define hardirq_count() (preempt_count() & HARDIRQ_MASK)
#define softirq_count() (preempt_count() & SOFTIRQ_MASK)
#define irq_count()     (preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK | NMI_MASK))
```

**Why Context Matters**:

Different contexts have different capabilities:

| Operation | Process | Softirq | Hardirq | NMI |
|-----------|---------|---------|---------|-----|
| Sleep | ✓ | ✗ | ✗ | ✗ |
| Schedule | ✓ | ✗ | ✗ | ✗ |
| Mutex lock | ✓ | ✗ | ✗ | ✗ |
| Spinlock | ✓ | ✓ | ✓ | ✓ (carefully) |
| Access user space | ✓ | ✗ | ✗ | ✗ |
| GFP_KERNEL alloc | ✓ | ✗ | ✗ | ✗ |
| GFP_ATOMIC alloc | ✓ | ✓ | ✓ | ✗ |
| Be preempted | ✓ | ✗ | ✗ | ✗ |
| Be interrupted | ✓ | ✓ | sometimes | ✗ |

**Example: Context-Dependent Code**:

```c
void some_kernel_function(void)
{
    if (in_interrupt()) {
        /* In interrupt context - use GFP_ATOMIC */
        data = kmalloc(size, GFP_ATOMIC);
    } else {
        /* In process context - can sleep */
        data = kmalloc(size, GFP_KERNEL);
    }
}
```

## Interrupt Flow Diagram

Here's a comprehensive view of how interrupts and softirqs work together:

```
Device raises IRQ
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                    HARDWARE PATH                            │
├─────────────────────────────────────────────────────────────┤
│ APIC → CPU → Check IF flag → Look up IDT → Jump to handler  │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                  ASSEMBLY ENTRY (entry_64.S)                │
├─────────────────────────────────────────────────────────────┤
│ • Save all registers (pt_regs)                              │
│ • Switch to kernel stack (if from user mode)                │
│ • Switch GS to kernel mode                                  │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                      irq_enter()                            │
├─────────────────────────────────────────────────────────────┤
│ • Increment preempt_count (mark hardirq context)            │
│ • Account IRQ time                                          │
│ • in_irq() now returns TRUE                                 │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│              DEVICE HANDLER (Top Half)                      │
├─────────────────────────────────────────────────────────────┤
│ • Read device status                                        │
│ • Acknowledge interrupt                                     │
│ • Do minimal processing                                     │
│ • raise_softirq(NET_RX_SOFTIRQ)  ← Schedule bottom half     │
│ • Return IRQ_HANDLED                                        │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                     irq_exit()                              │
├─────────────────────────────────────────────────────────────┤
│ • Decrement preempt_count                                   │
│ • Check: !in_interrupt() && local_softirq_pending()?        │
│   ├─ YES → invoke_softirq()                                 │
│   └─ NO  → skip softirqs                                    │
└─────────────────────────────────────────────────────────────┘
    │
    │ Softirqs pending?
    ├─ NO ──────────────────────────┐
    │                               │
    │ YES                           │
    ▼                               │
┌─────────────────────────────────┐ │
│     __do_softirq()              │ │
├─────────────────────────────────┤ │
│ • Clear pending bits            │ │
│ • Re-enable interrupts          │ │
│ • Loop through softirqs:        │ │
│   ├─ NET_RX_SOFTIRQ?            │ │
│   │   └─ net_rx_action()        │ │
│   ├─ TIMER_SOFTIRQ?             │ │
│   │   └─ run_timer_softirq()    │ │
│   └─ ...                        │ │
│ • Check time limit              │ │
│ • Too much work?                │ │
│   └─ Wake ksoftirqd             │ │
└─────────────────────────────────┘ │
    │                               │
    ▼                               │
┌─────────────────────────────────┐ │
│  SOFTIRQ HANDLER                │ │
│  (e.g., net_rx_action)          │ │
├─────────────────────────────────┤ │
│ • Process network packets       │ │
│ • Run protocol stack            │ │
│ • Deliver to sockets            │ │
│ • May raise more softirqs       │ │
└─────────────────────────────────┘ │
    │                               │
    │  Return from __do_softirq()   │
    ▼                               │
┌─────────────────────────────────────────────────────────────┐
│              INTERRUPT RETURN (entry_64.S)                  │
├─────────────────────────────────────────────────────────────┤
│ • Restore all registers                                     │
│ • Check need_resched() if returning to user space           │
│ • Execute IRET instruction                                  │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│              Return to Interrupted Context                  │
└─────────────────────────────────────────────────────────────┘


Alternative Path: ksoftirqd
    
    If __do_softirq() hits limits:
    
    ┌────────────────────────┐
    │  Wake ksoftirqd/N      │
    └────────────────────────┘
              │
              ▼
    ┌────────────────────────┐
    │  ksoftirqd thread      │
    │  (runs when scheduled) │
    ├────────────────────────┤
    │  while (pending) {     │
    │    __do_softirq();     │
    │    cond_resched();     │
    │  }                     │
    └────────────────────────┘
```

### Example: Network Packet Reception

Complete flow from hardware to application:

```
1. Network card DMA writes packet to memory
2. Network card raises IRQ
3. CPU jumps to interrupt handler (entry_64.S)
4. irq_enter() - mark hardirq context
5. Driver interrupt handler runs:
   - Read interrupt status
   - Acknowledge IRQ
   - Disable device interrupts
   - Schedule NAPI poll (raises NET_RX_SOFTIRQ)
   - Return IRQ_HANDLED
6. irq_exit():
   - Sees NET_RX_SOFTIRQ is pending
   - Calls invoke_softirq()
7. __do_softirq() runs:
   - Enables interrupts
   - Calls net_rx_action()
8. net_rx_action():
   - Polls for received packets
   - Processes network protocol stack
   - Delivers data to sockets
   - May take several milliseconds
9. Return from softirq
10. Return from interrupt
11. Resume user space or kernel code
```

## Tasklets

### What are Tasklets?

Tasklets are a simpler interface built on top of the softirq mechanism. They provide an easier way for drivers to defer work than using raw softirqs.

**Key features**:
- Built on TASKLET_SOFTIRQ
- Can be scheduled dynamically
- Guaranteed serialization (same tasklet never runs simultaneously on multiple CPUs)
- Simpler API than softirqs

**Difference from softirqs**:

| Feature | Softirqs | Tasklets |
|---------|----------|----------|
| Number | Fixed (10 types) | Unlimited (dynamic) |
| Concurrency | Can run on multiple CPUs | Serialized per tasklet |
| Registration | Static (compile time) | Dynamic (runtime) |
| Usage | Core kernel subsystems | Device drivers |

### Tasklet API

**Declaring a tasklet**:

```c
/* Define a tasklet */
void my_tasklet_handler(unsigned long data)
{
    struct my_device *dev = (struct my_device *)data;
    
    /* Process deferred work */
    process_device_data(dev);
}

/* Static initialization */
DECLARE_TASKLET(my_tasklet, my_tasklet_handler, (unsigned long)&my_dev);

/* Or dynamic initialization */
struct tasklet_struct my_tasklet;
tasklet_init(&my_tasklet, my_tasklet_handler, (unsigned long)&my_dev);
```

**Scheduling a tasklet**:

```c
/* In interrupt handler */
static irqreturn_t device_interrupt(int irq, void *dev_id)
{
    /* Handle urgent hardware needs */
    ack_device_interrupt(dev_id);
    
    /* Schedule tasklet for deferred processing */
    tasklet_schedule(&my_tasklet);
    
    return IRQ_HANDLED;
}
```

**Tasklet functions**:

```c
/* Schedule tasklet (adds to per-CPU list, raises TASKLET_SOFTIRQ) */
void tasklet_schedule(struct tasklet_struct *t);

/* High-priority tasklet (uses HI_SOFTIRQ instead) */
void tasklet_hi_schedule(struct tasklet_struct *t);

/* Disable tasklet (prevent execution) */
void tasklet_disable(struct tasklet_struct *t);

/* Enable tasklet */
void tasklet_enable(struct tasklet_struct *t);

/* Kill tasklet (remove and prevent future scheduling) */
void tasklet_kill(struct tasklet_struct *t);
```

**How tasklets work**:

1. `tasklet_schedule()` adds tasklet to per-CPU list
2. Raises TASKLET_SOFTIRQ
3. During softirq processing, `tasklet_action()` runs
4. `tasklet_action()` iterates through scheduled tasklets
5. Calls each tasklet's handler function
6. Ensures same tasklet doesn't run on multiple CPUs

```c
/* Simplified tasklet execution (from kernel/softirq.c) */
static void tasklet_action(struct softirq_action *a)
{
    struct tasklet_struct *list;
    
    /* Get this CPU's tasklet list */
    list = this_cpu_read(tasklet_vec.head);
    this_cpu_write(tasklet_vec.head, NULL);
    
    while (list) {
        struct tasklet_struct *t = list;
        list = list->next;
        
        /* Try to lock this tasklet */
        if (!tasklet_trylock(t))
            continue;  /* Already running elsewhere */
        
        /* Call the handler */
        if (tasklet_is_scheduled(t)) {
            t->func(t->data);
        }
        
        tasklet_unlock(t);
    }
}
```

## Work Queues

### Difference from Softirqs

While softirqs and tasklets run in interrupt context (with restrictions), **work queues** run in **process context**, which allows them to sleep.

| Feature | Softirqs/Tasklets | Work Queues |
|---------|-------------------|-------------|
| Context | Softirq (interrupt) | Process |
| Can sleep | ✗ | ✓ |
| Scheduling | ✗ | ✓ |
| Mutexes | ✗ | ✓ |
| User space access | ✗ | ✓ |
| Latency | Lower | Higher |
| Overhead | Lower | Higher |

**When to use work queues**:
- Need to sleep or call blocking functions
- Need to do I/O operations
- Work might take a long time
- Can tolerate higher latency

**When to use softirqs/tasklets**:
- Need low latency
- Work is quick and non-blocking
- Already in interrupt context

### Work Queue API

```c
/* Include header */
#include <linux/workqueue.h>

/* Define work */
void my_work_handler(struct work_struct *work)
{
    struct my_device *dev = container_of(work, struct my_device, work);
    
    /* Can sleep, use mutexes, do I/O, etc. */
    mutex_lock(&dev->lock);
    process_device_data(dev);
    mutex_unlock(&dev->lock);
}

/* Initialize work */
struct my_device {
    struct work_struct work;
    /* ... */
};

INIT_WORK(&dev->work, my_work_handler);

/* Schedule work (in interrupt handler) */
static irqreturn_t device_interrupt(int irq, void *dev_id)
{
    struct my_device *dev = dev_id;
    
    /* Schedule work to run later in process context */
    schedule_work(&dev->work);
    
    return IRQ_HANDLED;
}
```

**Work queue types**:

```c
/* System-wide default work queue */
schedule_work(&work);

/* Schedule delayed work (run after timeout) */
schedule_delayed_work(&delayed_work, msecs_to_jiffies(100));

/* Custom work queue */
struct workqueue_struct *my_wq;
my_wq = create_workqueue("my_work");
queue_work(my_wq, &work);
```

## Timing and Performance

### Interrupt Latency

Interrupt latency is the time from when an interrupt occurs to when its handler starts executing.
Factors affecting latency:

1. **Other interrupts**: Higher-priority interrupts delay lower-priority ones
2. **Interrupt disabled sections**: Code with `local_irq_disable()` delays all interrupts
3. **NMI handling**: NMIs delay regular interrupts
4. **Hardware delays**: APIC routing, bus delays

Typical latencies (on modern hardware):
- Best case: ~1-2 microseconds
- Typical: 5-20 microseconds
- With interrupt disabled: Can be milliseconds

Measuring latency:

```c
/* In interrupt handler */
static irqreturn_t device_interrupt(int irq, void *dev_id)
{
    u64 start_time = local_clock();  /* High-resolution timestamp */
    
    /* Handler code */
    
    u64 duration = local_clock() - start_time;
    if (duration > threshold)
        pr_warn("Interrupt took %llu ns\n", duration);
    
    return IRQ_HANDLED;
}
```

### Softirq Latency

Softirq latency is the time from when a softirq is raised to when it executes.
Factors:

1. **Hardirq execution time**: Softirqs wait for hardirq to complete
2. **Other softirqs**: Multiple softirqs compete
3. **ksoftirqd scheduling**: If fallback to ksoftirqd, subject to scheduler delays

Tuning considerations:

```bash
# Monitor softirq processing
cat /proc/softirqs

# Per-CPU softirq statistics
         CPU0       CPU1       CPU2       CPU3
HI:         5          0          0          0
TIMER:  89123      85234      88567      87890
NET_TX:  1234       1567       1345       1678
NET_RX: 45678      47890      46123      48234
BLOCK:   5432       5678       5234       5890
```

Modern kernels support IRQ threading (`CONFIG_IRQ_FORCED_THREADING`), which moves interrupt handlers to kernel threads:

```bash
# Force all interrupts to threads
echo 1 > /proc/sys/kernel/force_irqthreads
```

This converts:
```
Hardirq → Handler → Done
```

Into:
```
Hardirq → Wake thread → Done
            ↓
      Thread runs handler (can be scheduled)
```

Benefits:
- Better real-time characteristics
- Scheduler can prioritize interrupts
- Better for PREEMPT_RT kernels

Trade-off:
- Higher overhead
- Higher latency
- More context switches

## Criticism and Alternatives to Softirqs

While softirqs have been a core part of Linux interrupt handling since the 2.3 kernel series, they have faced significant criticism over the years from the kernel community, real-time developers, and performance engineers.

### Historical Context

Softirqs were introduced in the late 1990s as part of a redesign of Linux's bottom-half interrupt handling. The original design goals were:

1. **Low overhead**: Minimal per-interrupt cost
2. **High throughput**: Process work efficiently in batches
3. **SMP scalability**: Per-CPU processing without locks
4. **Flexibility**: Generic mechanism for deferred work

At the time, these were appropriate design choices for the hardware and workloads of that era. However, as systems evolved—with more CPU cores, faster networks, real-time requirements, and diverse workloads—the limitations of the softirq design became apparent.

### Main Criticisms

#### 1. Latency Issues and CPU Monopolization

The most serious criticism of the softirq mechanism is that, under heavy load, softirq processing can consume a large fraction of CPU time, leading to high and unpredictable latency and, in extreme cases, significantly delaying user processes.

**The Problem**:

When softirqs execute in `__do_softirq()`, they run in interrupt context with preemption disabled. To prevent unbounded execution, the kernel enforces both a time limit and an iteration limit (`MAX_SOFTIRQ_TIME` and `MAX_SOFTIRQ_RESTART`). However, these limits are checked only after at least one full pass over all pending softirqs, meaning that a single invocation of `__do_softirq()` may still execute a substantial amount of work before yielding.

```c
/* From kernel/softirq.c */
asmlinkage __visible void __do_softirq(void)
{
    unsigned long end = jiffies + MAX_SOFTIRQ_TIME;  /* 2ms typical */
    int max_restart = MAX_SOFTIRQ_RESTART;           /* 10 iterations */
    
    /* ... */
    
restart:
    while (pending) {
        /* Process softirq - could take milliseconds */
        h->action(h);
        pending >>= 1;
        h++;
    }
    
    /* Only check limits AFTER processing all pending softirqs once */
    if (pending && time_before(jiffies, end) && --max_restart)
        goto restart;
}
```

**Real-world impact**:

During high-rate events (e.g., NVMe completing millions of I/O operations per second):

1. Device interrupts occur frequently.
1. Each interrupt raises the relevant softirq (e.g., `BLOCK_SOFTIRQ`).
1. `__do_softirq()` processes a batch of completions, potentially for close to the configured time limit.
1. New completions arrive while softirqs are being processed.
1. The kernel exits __do_softirq() and re-enters it shortly thereafter, or defers remaining work to ksoftirqd.
1. User processes may experience elevated scheduling latency during these periods.

**CPU utilization example**:
```
1. High-frequency events occur (e.g., 100,000 I/O completions/sec)
2. Each interrupt takes ~5μs of hardirq time
3. Each completion triggers softirq work taking ~20μs
4. Total overhead: 2,500,000 μs ≈ 2.5 CPU-seconds per second
5. Result: multiple cores can be heavily occupied by interrupt and softirq handling
```

On modern kernels, this load will typically be split between short bursts in interrupt context and sustained execution in ksoftirqd. While this prevents unbounded execution in interrupt context and preserves preemptive scheduling semantics, it can still result in **entire CPUs spending most of their time executing softirq work**.

This remains a concern for:
- Real-time application developers
- Systems with ultra-high-throughput storage
- Low-latency requirements (audio, industrial control)
- High-frequency trading applications

#### 2. No Priority Mechanism

All softirqs have equal priority, processed in a fixed order (HI, TIMER, NET_TX, NET_RX, etc.). There's no way to prioritize critical softirqs over others.

**Example problem**:

```c
/* Order of processing is hardcoded */
enum {
    HI_SOFTIRQ=0,
    TIMER_SOFTIRQ,
    NET_TX_SOFTIRQ,
    NET_RX_SOFTIRQ,    /* Network always processed before block */
    BLOCK_SOFTIRQ,     /* Block I/O has to wait */
    /* ... */
};
```

If network RX processing takes a long time, block I/O completion handlers (BLOCK_SOFTIRQ) must wait, even if they're more urgent for the system's workload. This led to complaints like:

> "Why does my database's disk I/O completion get delayed by someone else's network traffic?" - Common LKML complaint

#### 3. Limited Softirq Slots

Only 10 softirq types are defined, and adding new ones requires kernel-wide changes. This has led to **overuse of TASKLET_SOFTIRQ**.

```c
enum {
    HI_SOFTIRQ=0,
    TIMER_SOFTIRQ,
    NET_TX_SOFTIRQ,
    NET_RX_SOFTIRQ,
    BLOCK_SOFTIRQ,
    IRQ_POLL_SOFTIRQ,
    TASKLET_SOFTIRQ,      /* Catch-all for many unrelated tasks */
    SCHED_SOFTIRQ,
    HRTIMER_SOFTIRQ,
    RCU_SOFTIRQ,
    NR_SOFTIRQS           /* Only 10! */
};
```

The result: TASKLET_SOFTIRQ becomes a dumping ground for unrelated work, destroying any hope of prioritization or isolation. A slow tasklet from one driver delays tasklets from completely different drivers.

Thomas Gleixner commented in 2020:
> "Tasklets are a historical mistake. They provide the illusion of simplicity while giving up control and debuggability."

#### 4. Non-Preemptible Nature

Softirqs cannot be preempted (except by hardirqs). This is fundamentally incompatible with hard real-time requirements.

**The problem for PREEMPT_RT**:

The Real-Time Linux project (PREEMPT_RT) aims to make Linux fully preemptible for real-time applications. But softirqs are a major obstacle:

```c
void __do_softirq(void)
{
    __local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);  /* Disable preemption */
    
    /* Process softirqs - cannot be preempted */
    while (pending) {
        h->action(h);  /* Could take milliseconds */
        /* No preemption point here */
    }
    
    __local_bh_enable(SOFTIRQ_OFFSET);  /* Re-enable preemption */
}
```

This violates real-time principles where **any** high-priority task should be able to preempt lower-priority work immediately.

#### 5. Debugging Difficulties

When system latency spikes occur, debugging whether softirqs are the cause is difficult:

- Softirqs don't show up clearly in `top` or `ps`
- They're accounted to whatever process was running when interrupted
- `ksoftirqd` time is visible, but inline softirq time is hidden
- Profiling tools often miss softirq overhead

Example confusion:
```bash
# User sees this:
$ top
  PID USER      PR  NI    VIRT    RES  %CPU
  1234 user    20   0   100M    10M  80.0   # Looks like user process
  
# But actually:
# - 60% of that is NET_RX_SOFTIRQ processing
# - Only 20% is actual user code
# - Hidden from standard tools
```

### Specific Problems and Examples

#### Real-Time Latency Issues

Real-time applications require **bounded latency** (typically <5ms, ideally <1ms). Softirqs can violate this constraint even in modern kernels.

**Example scenario**:
```
Audio thread priority: 99 (RT_FIFO)
Softirq priority: N/A (not schedulable)

Timeline:
0.0ms: Audio thread needs to run
0.0ms: Block I/O completion softirq is processing
2.5ms: Softirq still running (processing batch of completions)
3.0ms: Softirq finally yields to ksoftirqd
3.5ms: Scheduler finally runs audio thread
       Result: Audio buffer underrun, audible "pop"
```

This problem remains a concern for:
- Professional audio workstations
- Industrial control systems
- Low-latency trading systems
- Real-time video processing

**Solution**: Use PREEMPT_RT kernels which convert softirqs to threads, or use CPU isolation to dedicate cores to real-time tasks.

#### High-Throughput Storage Workloads

Modern NVMe devices can complete millions of I/O operations per second. Each completion can trigger BLOCK_SOFTIRQ processing:

```c
/* Block I/O completion softirq */
static void blk_done_softirq(struct softirq_action *h)
{
    while (!list_empty(&local_completion_list)) {
        struct request *rq = list_entry(...);
        /* Process completion - may involve callbacks */
        rq->end_io(rq, error);
    }
}
```

With very fast storage (NVMe), BLOCK_SOFTIRQ can consume significant CPU time, delaying other work including user processes. This is an **active area of kernel development** with ongoing discussions about moving more work to workqueues or per-CPU threads.

### Alternatives and Improvements

The kernel community has developed several alternatives and mitigations:

#### 1. IRQ Threading (PREEMPT_RT Approach)

The **most radical alternative**: convert all interrupt handlers to kernel threads.

```c
/* Traditional model */
Interrupt → Hardirq handler → Softirq (non-preemptible)

/* Threaded IRQ model */
Interrupt → Wake thread → Done
              ↓
         Thread handler (schedulable, preemptible)
```

**Advantages**:
- Handlers are fully preemptible
- Priority can be assigned to each IRQ thread
- Better real-time behavior
- Clearer accounting in tools

**Disadvantages**:
- Higher overhead (context switch per interrupt)
- Lower peak throughput
- More complex to tune

**Enabling**:
```bash
# Force all interrupts to use threading
echo 1 > /proc/sys/kernel/force_irqthreads

# Or build with CONFIG_PREEMPT_RT
```

Many distributions now use threaded IRQs for better desktop responsiveness.

#### 2. NAPI for Networking

**NAPI** (New API) largely solved the network receive livelock problem by changing drivers from interrupt-per-packet to **polling under load**:

```c
/* Old model (pre-NAPI) */
Packet arrives → Interrupt → Process one packet → Done
(Could cause livelock under high load)

/* NAPI model (modern) */
Packet arrives → Interrupt → Disable interrupts → Start polling
                             Process many packets in batch
                             When queue empty: Re-enable interrupts
```

This dramatically reduced softirq load from networking. **NAPI is now standard** in all modern network drivers and has effectively solved the receive livelock problem for networking. However, NAPI is **network-specific** and doesn't help other subsystems that can still experience similar issues (storage, serial devices, etc.).

#### 3. XDP and eBPF

**XDP** (eXpress Data Path) processes packets even earlier, before softirqs:

```
Packet → Driver → XDP program (eBPF)
                    ↓
                  Drop/Redirect/Pass
                    ↓ (if Pass)
                  Softirq (NET_RX)
```

XDP can handle millions of packets per second with minimal CPU, often bypassing softirqs entirely. This addresses networking latency but is again network-specific.

#### 4. Workqueues for Deferrable Work

Modern drivers increasingly use **workqueues** instead of tasklets:

```c
/* Old approach: tasklet */
tasklet_schedule(&my_tasklet);  /* Runs in TASKLET_SOFTIRQ */

/* New approach: workqueue */
queue_work(system_wq, &my_work);  /* Runs in process context */
```

**Benefits**:
- Can sleep, use mutexes
- Schedulable (can be preempted)
- Better visibility in tools
- Can be assigned to specific CPUs

**When to use**:
- Work can take >1ms
- Need to sleep or block
- Not extremely latency-sensitive

#### 5. Per-Subsystem Solutions

Rather than using generic softirqs, subsystems increasingly implement their own threading:

**Examples**:
- **Block layer**: `kblockd` workqueue for I/O completion
- **RCU**: Dedicated `rcuc/N` threads per CPU
- **Networking**: Per-device threads for some drivers

This provides better isolation and control than shared softirq mechanism.

### Modern Kernel Solutions

Recent kernels have improved the situation:

#### 1. Better ksoftirqd Behavior

Modern kernels wake `ksoftirqd` more aggressively:

```c
/* Newer behavior */
if (pending) {
    if (time_before(jiffies, end) && !need_resched() && --max_restart)
        goto restart;
    
    wakeup_softirqd();  /* Wake immediately */
}
```

Earlier kernels would continue processing longer before yielding to `ksoftirqd`.

#### 2. CONFIG_PREEMPT_RT

The PREEMPT_RT patchset (partially merged in recent kernels) provides:

- Threaded interrupts by default
- Preemptible softirqs (controversial!)
- Better latency bounds (<100μs typical)

**Trade-off**: Lower peak throughput but bounded latency.

#### 3. CPU Isolation

Users can isolate CPUs for dedicated workloads:

```bash
# Boot parameter: isolate CPUs 2-7 from softirqs
isolcpus=2-7

# All softirqs run on CPUs 0-1
# CPUs 2-7 available for real-time tasks
```

This doesn't fix the softirq mechanism but provides a workaround.

#### 4. Improved Monitoring

Better tools for observing softirq impact:

```bash
# Per-softirq statistics
cat /proc/softirqs

# Latency tracking
trace-cmd record -e irq:softirq_entry -e irq:softirq_exit

# Per-CPU softirq time
mpstat -P ALL 1
```

### Best Practices for Driver Developers

Given the criticism, what should driver developers do?

#### 1. Minimize Softirq Work

Do as little as possible in softirq context:

```c
/* BAD: Heavy processing in tasklet */
void my_tasklet_func(unsigned long data)
{
    process_large_dataset();      /* Takes milliseconds */
    do_complex_computation();     /* Non-preemptible! */
}

/* GOOD: Defer to workqueue */
void my_tasklet_func(unsigned long data)
{
    queue_work(my_wq, &my_work);  /* Quick handoff */
}

void my_work_func(struct work_struct *work)
{
    process_large_dataset();      /* Preemptible */
    do_complex_computation();     /* Can be scheduled */
}
```

#### 2. Consider Workqueues First

Modern advice: **default to workqueues** unless you have specific latency requirements:

```c
/* Use workqueues unless: */
/* 1. Need <1ms latency */
/* 2. Work takes <100μs */
/* 3. Cannot sleep/block */
```

#### 3. Use Threaded IRQs

Request threaded IRQ handlers when possible:

```c
/* Instead of: */
request_irq(irq, my_handler, flags, name, dev);

/* Use: */
request_threaded_irq(irq, my_quick_check, my_thread_handler,
                    flags, name, dev);
```

The `my_thread_handler` runs in process context, fully preemptible.

#### 4. Batch Work

If you must use softirqs, batch work to reduce overhead:

```c
/* BAD: Raise softirq for each item */
for_each_item(item) {
    raise_softirq(MY_SOFTIRQ);
}

/* GOOD: Accumulate, raise once */
list_splice(&items, &pending_list);
raise_softirq(MY_SOFTIRQ);
```

#### 5. Consider NAPI-Style Polling

For high-rate events, implement polling with interrupts as a fallback:

```c
/* Interrupt handler */
static irqreturn_t my_handler(int irq, void *dev)
{
    disable_device_interrupts(dev);
    schedule_poll_work(dev);
    return IRQ_HANDLED;
}

/* Poll work */
static void my_poll_work(struct work_struct *work)
{
    while (device_has_data(dev)) {
        process_data(dev);
        cond_resched();  /* Allow preemption */
    }
    enable_device_interrupts(dev);
}
```

### The Ongoing Debate

The softirq mechanism remains **a practical compromise** in modern kernels:

**Current reality**:
- Softirqs work well for typical server and desktop workloads
- NAPI has solved the networking livelock problem
- Most problematic drivers have moved to threaded IRQs or workqueues
- Real-time users have PREEMPT_RT as an alternative
- The remaining issues are primarily with specialized hardware or real-time requirements

**Arguments for keeping softirqs** (as-is):
- Proven mechanism with 20+ years of optimization
- Excellent throughput for the common case
- Lower overhead than threaded alternatives
- Changing would require massive refactoring of existing drivers

**Arguments for further evolution**:
- Better real-time behavior with more threading
- Clearer performance model for developers
- Better tooling and debuggability
- More flexible resource management

**Modern kernel developer guidance**:
- **New drivers**: Prefer threaded IRQs and workqueues
- **High-throughput paths**: Consider per-subsystem threads (like NAPI)
- **Real-time systems**: Use PREEMPT_RT or CPU isolation
- **Existing softirq code**: Works fine for most cases, no urgent need to rewrite

### Conclusion

Softirqs represent a **classic systems design trade-off** that has evolved over time:
- Originally optimized for **throughput** over latency
- Designed for **common server workloads** 
- Prioritized **simplicity** and low overhead

**Current state (modern kernels)**:
- Most severe issues (network livelock) have been solved through subsystem-specific improvements (NAPI, XDP)
- Remaining issues primarily affect real-time and specialized workloads
- Multiple alternatives exist (threaded IRQs, workqueues, PREEMPT_RT, CPU isolation)
- New code increasingly uses alternatives to softirqs

**When softirqs still work well**:
- General server workloads
- Desktop systems
- Systems with typical I/O rates
- Non-real-time requirements

**When to consider alternatives**:
- Real-time requirements (audio, industrial control, trading)
- Very high-throughput devices (modern NVMe, 100GbE+)
- Need for predictable latency
- Systems requiring fine-grained priority control

Understanding these trade-offs is crucial for:
- Choosing appropriate deferral mechanisms in new code
- Debugging latency issues in production
- Configuring kernels for specific workloads
- Appreciating the evolution of Linux kernel design

The criticism of softirqs has driven significant improvements in Linux interrupt handling. While the core mechanism remains for backward compatibility and proven performance, the ecosystem has evolved to provide better alternatives for cases where softirqs don't fit well.

## Link to Scheduler

Interrupts and the scheduler interact in several ways:

### 1. SCHED_SOFTIRQ

The scheduler uses softirqs for some operations:

```c
/* Trigger scheduler load balancing */
void scheduler_tick(void)
{
    /* ... */
    
    /* Raise softirq to trigger load balancing */
    raise_softirq(SCHED_SOFTIRQ);
}
```

### 2. Preemption and Scheduling

When returning from an interrupt, the kernel checks if rescheduling is needed:

```c
/* Return path from interrupt */
void irq_exit(void)
{
    /* ... process softirqs ... */
    
    /* Check if we need to reschedule */
    if (need_resched() && !in_interrupt())
        invoke_scheduler();
}
```

### 3. Interrupt Accounting

The scheduler tracks time spent in interrupts:

```c
void irq_enter(void)
{
    account_irq_enter_time(current);  /* Account to current task */
}

void irq_exit(void)
{
    account_irq_exit_time(current);
}
```

This ensures that interrupt time is properly accounted and doesn't unfairly count against a process's CPU time.

### 4. Load Balancing

Interrupts can trigger scheduler load balancing:

```c
void scheduler_tick(void)
{
    /* Periodic scheduler tick */
    
    /* Check if load balancing is needed */
    trigger_load_balance(rq);
}

void trigger_load_balance(struct rq *rq)
{
    /* Raise softirq for load balancing */
    raise_softirq(SCHED_SOFTIRQ);
}
```

See the [scheduler chapter](scheduler.md) for more details on how the scheduler interacts with interrupts and the scheduler tick.
