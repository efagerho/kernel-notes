# Linux Interrupt Handling

## Overview

Interrupts are a fundamental mechanism in the Linux kernel that allow hardware devices and the CPU itself to signal events that require immediate attention. Rather than polling devices constantly, the kernel can respond to events asynchronously as they occur.

> **Note**: This chapter focuses on kernel software interrupt handling. For hardware-level details on APIC architecture, MSI/MSI-X mechanisms, interrupt routing, priorities, and latency breakdowns, see [Interrupts](./interrupts_hardware.md).

Linux uses a **two-level interrupt handling model**:

1. **Hardware Interrupts (Hardirqs)**: The immediate, fast response to hardware signals. On entry, the CPU disables further maskable interrupts on the *local CPU* (and the kernel treats hardirq context as non-preemptible); handlers must do minimal work and return quickly.

2. **Software Interrupts (Softirqs)**: Deferred work that can be processed later in a safer context. These allow the kernel to defer heavy processing out of the time-critical hardirq context.

This split allows the kernel to acknowledge hardware quickly (in the hardirq) while deferring expensive processing (to softirqs), balancing responsiveness with throughput.

**Terminology**: Hardirq handlers are often called the **"top half"** (or "top-level"), while softirqs and other deferred work mechanisms are called the **"bottom half"** (or "bottom-level"). This terminology reflects the two-level structure where the top half runs first in time-critical interrupt context, and the bottom half runs later in a less restrictive context.

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

Linux dynamically allocates interrupt vectors (0-255) to device IRQs. While vectors 0-31 are reserved for CPU exceptions and high vectors for system IPIs, the kernel manages the remaining range for device interrupts.

> **Hardware Details**: For the specific hardware vector ranges, priority classes, and APIC routing mechanisms, see [Interrupts (Hardware)](./interrupts_hardware.md#vector-assignment).

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

> For detailed APIC architecture, Local APIC registers, I/O APIC structure, x2APIC features, and interrupt routing mechanisms, see [Interrupts (Hardware)](./interrupts_hardware.md).

### Hardware Interrupt Flow

When an interrupt is delivered to the CPU, the following sequence occurs:

> **Hardware Path**: For the complete delivery flow from device to CPU (including PCIe TLP generation, I/O APIC routing, and LAPIC delivery), see [Interrupts (Hardware)](./interrupts_hardware.md#complete-delivery-flow).

```
CPU Interrupt (Vector N)
   │
   ├─ Save current RIP, RSP, RFLAGS
   ├─ Look up vector N in IDT
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

## Threaded Interrupts

### Introduction and Motivation

**Threaded interrupts** (also called **IRQ threading**) are a mechanism that allows interrupt handlers to execute in process context as kernel threads, rather than in hardirq context. This fundamental shift enables interrupt handlers to use operations that are prohibited in hardirq context, such as sleeping, taking mutexes, and performing lengthy operations.

**The traditional problem**:

In the traditional interrupt model, all device-specific work happens in hardirq context, which is extremely restrictive:

```c
/* Traditional handler - runs in hardirq context */
static irqreturn_t my_handler(int irq, void *dev_id)
{
    /* Can't sleep! */
    /* Can't take mutexes! */
    /* Can't do I/O! */
    /* Must be FAST! */
    
    read_device_status();
    schedule_tasklet();  // Defer work
    return IRQ_HANDLED;
}
```

**The threaded solution**:

With threaded interrupts, heavy work runs in a dedicated kernel thread that can be scheduled, preempted, and uses normal process context operations:

```c
/* Primary handler - runs in hardirq context (quick check) */
static irqreturn_t my_primary_handler(int irq, void *dev_id)
{
    if (!is_my_interrupt(dev_id))
        return IRQ_NONE;
    
    ack_device();
    return IRQ_WAKE_THREAD;  // Wake the thread
}

/* Thread handler - runs in process context (can do anything) */
static irqreturn_t my_thread_handler(int irq, void *dev_id)
{
    /* Can sleep! */
    /* Can take mutexes! */
    /* Can do I/O! */
    /* Can take as long as needed! */
    
    mutex_lock(&dev->lock);
    process_device_data(dev);
    mutex_unlock(&dev->lock);
    
    return IRQ_HANDLED;
}
```

**Why threaded interrupts were introduced**:

1. **Real-time requirements**: Real-time systems need bounded, predictable latency. Non-preemptible hardirq handlers can cause unbounded delays. Threaded handlers can be preempted by higher-priority tasks.

2. **Driver simplification**: Many devices require complex processing (I2C transactions, SPI transfers, etc.) that's awkward to split into hardirq and softirq/tasklet parts. Threading allows natural, straightforward code.

3. **Better resource management**: Threaded handlers can be assigned priorities and CPU affinity, allowing fine-grained control over interrupt processing.

4. **PREEMPT_RT**: The real-time Linux project (PREEMPT_RT) requires that nearly everything be preemptible. Threaded interrupts are essential for this.

**Use cases**:

- **Real-time systems**: Audio processing, industrial control, robotics
- **Slow devices**: I2C/SMBus, SPI, UART where operations involve waiting
- **Complex processing**: Network drivers with extensive protocol processing
- **PREEMPT_RT kernels**: All interrupts are automatically threaded
- **Desktop responsiveness**: Many distributions enable forced threading for better interactivity

### API and Usage

The kernel provides the `request_threaded_irq()` function for registering threaded interrupt handlers:

```c
/* From include/linux/interrupt.h */
int request_threaded_irq(unsigned int irq,
                        irq_handler_t handler,
                        irq_handler_t thread_fn,
                        unsigned long flags,
                        const char *name,
                        void *dev);
```

**Parameters**:

- `irq`: The interrupt number to register
- `handler`: Primary handler (optional, runs in hardirq context)
- `thread_fn`: Thread handler (runs in process context)
- `flags`: IRQ flags (including `IRQF_ONESHOT`)
- `name`: Name for the interrupt (appears in `/proc/interrupts` and thread name)
- `dev`: Device-specific pointer passed to both handlers

**Primary handler** (`handler`):

- Runs in hardirq context (fast, non-preemptible)
- Should quickly check if this is the device's interrupt
- Can be `NULL` if no quick check is needed
- Return values:
  - `IRQ_NONE`: Not our interrupt (shared IRQ line)
  - `IRQ_HANDLED`: Handled, but don't wake thread
  - `IRQ_WAKE_THREAD`: Handled, wake the thread handler

**Thread handler** (`thread_fn`):

- Runs in process context (can sleep, take mutexes, etc.)
- Called when primary handler returns `IRQ_WAKE_THREAD`
- Runs in a dedicated kernel thread (`irq/<n>-<name>`)
- Fully preemptible and schedulable
- Return values:
  - `IRQ_HANDLED`: Successfully processed
  - `IRQ_NONE`: Not handled (shouldn't normally happen)

**The `IRQF_ONESHOT` flag**:

This flag is **critical** for level-triggered interrupts with threaded handlers:

```c
request_threaded_irq(irq, primary, thread,
                    IRQF_ONESHOT,  // Keep IRQ masked until thread completes
                    "my_device", dev);
```

**Why `IRQF_ONESHOT` is needed**:

```
Without IRQF_ONESHOT (BAD for level-triggered):
1. Device asserts IRQ line (level high)
2. Primary handler runs, returns IRQ_WAKE_THREAD
3. IRQ is re-enabled
4. Device STILL asserting → immediate re-interrupt!
5. Infinite interrupt storm before thread can run

With IRQF_ONESHOT (CORRECT):
1. Device asserts IRQ line
2. Primary handler runs, returns IRQ_WAKE_THREAD
3. IRQ stays MASKED
4. Thread handler runs and clears device status
5. Thread completes, IRQ is unmasked
6. No spurious re-interrupts
```

For edge-triggered interrupts, `IRQF_ONESHOT` is not strictly necessary but is still commonly used.

### Complete Driver Example

Here's a realistic example of a threaded interrupt handler:

```c
/* Example: I2C device with interrupt */
struct my_i2c_device {
    struct i2c_client *client;
    int irq;
    struct mutex lock;
    wait_queue_head_t wait;
    u8 buffer[256];
};

/* Primary handler - runs in hardirq context */
static irqreturn_t my_i2c_irq_primary(int irq, void *dev_id)
{
    struct my_i2c_device *dev = dev_id;
    struct i2c_client *client = dev->client;
    u8 status;
    
    /* Quick read of interrupt status register */
    status = i2c_smbus_read_byte_data(client, REG_INT_STATUS);
    
    if (!(status & INT_DATA_READY))
        return IRQ_NONE;  /* Not our interrupt */
    
    /* Acknowledge interrupt at device */
    i2c_smbus_write_byte_data(client, REG_INT_STATUS, status);
    
    /* Wake the thread to do the real work */
    return IRQ_WAKE_THREAD;
}

/* Thread handler - runs in process context */
static irqreturn_t my_i2c_irq_thread(int irq, void *dev_id)
{
    struct my_i2c_device *dev = dev_id;
    struct i2c_client *client = dev->client;
    int ret, i;
    
    /*
     * Can take mutex - would deadlock in hardirq context!
     * Can sleep - would panic in hardirq context!
     * Can do slow I2C transactions - would block hardirqs!
     */
    mutex_lock(&dev->lock);
    
    /* Read data from device (involves I2C transactions, can take ms) */
    for (i = 0; i < sizeof(dev->buffer); i++) {
        ret = i2c_smbus_read_byte_data(client, REG_DATA);
        if (ret < 0) {
            dev_err(&client->dev, "Failed to read data: %d\n", ret);
            break;
        }
        dev->buffer[i] = ret;
    }
    
    mutex_unlock(&dev->lock);
    
    /* Wake up any waiting readers */
    wake_up_interruptible(&dev->wait);
    
    return IRQ_HANDLED;
}

/* Probe function - device initialization */
static int my_i2c_probe(struct i2c_client *client)
{
    struct my_i2c_device *dev;
    int ret;
    
    dev = devm_kzalloc(&client->dev, sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;
    
    dev->client = client;
    dev->irq = client->irq;
    mutex_init(&dev->lock);
    init_waitqueue_head(&dev->wait);
    
    /* Register threaded IRQ handler */
    ret = request_threaded_irq(dev->irq,
                              my_i2c_irq_primary,    /* Primary (hardirq) */
                              my_i2c_irq_thread,     /* Thread (process) */
                              IRQF_ONESHOT |         /* Keep masked until thread done */
                              IRQF_TRIGGER_FALLING,  /* Falling edge */
                              "my_i2c_device",       /* Name */
                              dev);                  /* Device data */
    if (ret) {
        dev_err(&client->dev, "Failed to request IRQ: %d\n", ret);
        return ret;
    }
    
    i2c_set_clientdata(client, dev);
    return 0;
}

static void my_i2c_remove(struct i2c_client *client)
{
    struct my_i2c_device *dev = i2c_get_clientdata(client);
    
    free_irq(dev->irq, dev);
}
```

**Alternative: Thread-only handler**:

If no quick check is needed, pass `NULL` for the primary handler:

```c
/* Only thread handler, no primary */
ret = request_threaded_irq(irq,
                          NULL,              /* No primary handler */
                          my_thread_only,    /* Only thread handler */
                          IRQF_ONESHOT,
                          "my_device",
                          dev);
```

In this case, the kernel provides a minimal primary handler that just returns `IRQ_WAKE_THREAD`.

### Kernel Implementation Details

#### Thread Creation

When you call `request_threaded_irq()`, the kernel creates a dedicated kernel thread for the interrupt handler. Here's how it works:

```c
/* Simplified from kernel/irq/manage.c */
int request_threaded_irq(unsigned int irq, irq_handler_t handler,
                        irq_handler_t thread_fn, unsigned long irqflags,
                        const char *devname, void *dev_id)
{
    struct irqaction *action;
    struct irq_desc *desc;
    int retval;
    
    /* Allocate irqaction structure */
    action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
    if (!action)
        return -ENOMEM;
    
    action->handler = handler;       /* Primary handler */
    action->thread_fn = thread_fn;   /* Thread handler */
    action->flags = irqflags;
    action->name = devname;
    action->dev_id = dev_id;
    
    /* Get IRQ descriptor */
    desc = irq_to_desc(irq);
    if (!desc) {
        kfree(action);
        return -EINVAL;
    }
    
    /* Setup the IRQ and create thread if needed */
    retval = __setup_irq(irq, desc, action);
    if (retval)
        kfree(action);
    
    return retval;
}
```

The `__setup_irq()` function creates the kernel thread:

```c
/* Simplified from kernel/irq/manage.c */
static int __setup_irq(unsigned int irq, struct irq_desc *desc,
                      struct irqaction *new)
{
    struct task_struct *t;
    
    /* If there's a thread function, create the kernel thread */
    if (new->thread_fn) {
        /* Create kernel thread for this IRQ */
        t = kthread_create(irq_thread, new, "irq/%d-%s",
                          irq, new->name);
        if (IS_ERR(t))
            return PTR_ERR(t);
        
        /* Set scheduling policy and priority */
        sched_set_fifo(t);  /* SCHED_FIFO, high priority */
        
        /* Store thread pointer */
        new->thread = t;
        
        /* Setup completion for thread synchronization */
        init_completion(&new->thread_completion);
        wake_up_process(t);
    }
    
    /* Add action to the IRQ descriptor's action list */
    /* ... */
    
    return 0;
}
```

**Thread naming convention**:

Threads are named `irq/<irq_number>-<device_name>`:

```bash
$ ps -eLo pid,tid,comm | grep 'irq/'
    3    3 irq/9-acpi
   12   12 irq/16-i801_smb
  240  240 irq/129-eth0
  241  241 irq/130-eth0-TxRx-0
  242  242 irq/131-eth0-TxRx-1
```

#### The IRQ Thread Function

Each IRQ thread runs the `irq_thread()` function in a loop:

```c
/* Simplified from kernel/irq/manage.c */
static int irq_thread(void *data)
{
    struct irqaction *action = data;
    struct irq_desc *desc = irq_to_desc(action->irq);
    irqreturn_t ret;
    
    /* Thread loop */
    while (!kthread_should_stop()) {
        /* Sleep until woken by primary handler */
        wait_for_completion(&action->thread_completion);
        
        /* Check if we should stop */
        if (kthread_should_stop())
            break;
        
        /* Call the thread handler */
        ret = irq_thread_fn(desc, action);
        
        /* If IRQF_ONESHOT, unmask the interrupt now */
        if (action->flags & IRQF_ONESHOT) {
            /* Unmask interrupt at chip level */
            desc->irq_data.chip->irq_unmask(&desc->irq_data);
        }
        
        /* Mark completion done for next iteration */
        reinit_completion(&action->thread_completion);
    }
    
    return 0;
}

/* Call the actual thread handler function */
static irqreturn_t irq_thread_fn(struct irq_desc *desc,
                                struct irqaction *action)
{
    irqreturn_t ret;
    
    /* Mark that we're in IRQ thread context */
    local_bh_disable();
    
    /* Call the driver's thread handler */
    ret = action->thread_fn(action->irq, action->dev_id);
    
    local_bh_enable();
    
    return ret;
}
```

**Key points**:

1. The thread sleeps on a completion variable
2. When the primary handler returns `IRQ_WAKE_THREAD`, it wakes the thread
3. Thread calls the driver's `thread_fn`
4. If `IRQF_ONESHOT` is set, interrupt is unmasked after thread completes
5. Thread goes back to sleep, waiting for next interrupt

#### Interrupt Handling Flow

When a threaded interrupt occurs, the primary handler runs in hardirq context to acknowledge the device (and mask it if `IRQF_ONESHOT`), then wakes the kernel thread. The thread runs later in process context to perform the actual work.

> **Visual Flow**: For a detailed comparison of the traditional vs. threaded interrupt flow, see [Comparison: Traditional vs. Threaded vs. Forced Threading](#comparison-traditional-vs-threaded-vs-forced-threading).

**Detailed code path**:

```c
/* Hardware interrupt occurs → entry_64.S → common_interrupt → ... */

/* From kernel/irq/handle.c */
irqreturn_t __handle_irq_event_percpu(struct irq_desc *desc)
{
    irqreturn_t retval = IRQ_NONE;
    struct irqaction *action;
    
    for_each_action_of_desc(desc, action) {
        irqreturn_t res;
        
        /* Call primary handler */
        res = action->handler(desc->irq_data.irq, action->dev_id);
        
        /* Check return value */
        switch (res) {
        case IRQ_WAKE_THREAD:
            /* Mask if ONESHOT */
            if (action->flags & IRQF_ONESHOT) {
                desc->irq_data.chip->irq_mask(&desc->irq_data);
                desc->threads_oneshot |= action->thread_mask;
            }
            
            /* Wake the thread */
            __irq_wake_thread(desc, action);
            
            fallthrough;
        case IRQ_HANDLED:
            retval |= res;
            break;
        default:
            break;
        }
    }
    
    return retval;
}

/* Wake the IRQ thread */
static void __irq_wake_thread(struct irq_desc *desc,
                             struct irqaction *action)
{
    /*
     * Wake the handler thread. The completion is used to
     * synchronize between the primary handler and the thread.
     */
    complete(&action->thread_completion);
}
```

The scheduler then runs the IRQ thread when appropriate based on its priority and the system load.

### Process Visibility

Threaded interrupts create visible kernel threads that appear in process listings:

```bash
$ ps -eLo pid,tid,class,rtprio,pri,comm | grep 'irq/'
  PID   TID CLS RTPRIO PRI COMMAND
    3     3  FF     50  90 irq/9-acpi
   12    12  FF     50  90 irq/16-i801_smb
  240   240  FF     50  90 irq/129-eth0
  241   241  FF     50  90 irq/130-eth0-TxRx-0
  242   242  FF     50  90 irq/131-eth0-TxRx-1
  243   243  FF     50  90 irq/132-eth0-TxRx-2
  244   244  FF     50  90 irq/133-eth0-TxRx-3
```

**Understanding the output**:

- `PID/TID`: Process/Thread ID
- `CLS`: Scheduling class
  - `FF` = SCHED_FIFO (real-time, first-in-first-out)
  - `TS` = SCHED_NORMAL (regular time-sharing)
- `RTPRIO`: Real-time priority (0-99, higher = more priority)
- `PRI`: Kernel's internal priority value
- `COMMAND`: Thread name (`irq/<num>-<name>`)

**IRQ thread properties**:

1. **Real-time scheduling**: By default, IRQ threads use `SCHED_FIFO` with priority 50
2. **High priority**: Preempt regular processes but not higher-priority RT tasks
3. **Per-IRQ threads**: One thread per interrupt line (or per MSI-X vector)
4. **Visible in tools**: Show up in `ps`, `top`, `htop`, `perf`, etc.

> For details on MSI-X hardware capabilities, vector allocation, and per-queue interrupt mechanisms, see [Interrupts (Hardware)](./interrupts_hardware.md).

**Managing IRQ threads**:

You can adjust IRQ thread priority and affinity:

```bash
# Set IRQ thread priority
$ chrt -f -p 60 $(pgrep -f 'irq/129-eth0')

# Set IRQ thread CPU affinity
$ taskset -cp 2,3 $(pgrep -f 'irq/129-eth0')

# Check current settings
$ chrt -p $(pgrep -f 'irq/129-eth0')
pid 240's current scheduling policy: SCHED_FIFO
pid 240's current scheduling priority: 50

$ taskset -cp $(pgrep -f 'irq/129-eth0')
pid 240's current affinity list: 0-7
```

**Monitoring IRQ threads**:

```bash
# See IRQ thread CPU usage
$ top -H -p $(pgrep -f 'irq/' | tr '\n' ',' | sed 's/,$//')

# Trace IRQ thread activity
$ perf record -e 'irq:*' -g -p $(pgrep -f 'irq/129-eth0')

# See IRQ thread wakeups
$ trace-cmd record -e sched:sched_wakeup -f comm~'irq/*'
```

**Comparison with `/proc/interrupts`**:

```bash
$ cat /proc/interrupts
           CPU0       CPU1       CPU2       CPU3
  9:          0          0          0          0   IO-APIC   9-fasteoi   acpi
 16:        156        234        198        211   IO-APIC  16-fasteoi   i801_smbus
129:      45234      48967      46123      47890   PCI-MSI 524288-edge      eth0
130:      12456      11234      12789      13456   PCI-MSI 524289-edge      eth0-TxRx-0
```

The interrupt numbers match the IRQ thread names (`irq/129-eth0`, etc.).

### Forced Threading

The kernel provides mechanisms to force ALL interrupts to use threading, even if drivers didn't explicitly request it.

#### CONFIG_IRQ_FORCED_THREADING

At compile time, enable this kernel configuration option:

```kconfig
CONFIG_IRQ_FORCED_THREADING=y
```

This adds support for forced threading but doesn't automatically enable it. You must still use the boot parameter or runtime control.

#### Boot Parameter

Force threading at boot time:

```bash
# Add to kernel command line
threadirqs

# Example in GRUB:
linux /vmlinuz-5.15.0 root=/dev/sda1 threadirqs
```

This makes ALL interrupts use threading, regardless of how drivers registered them.

#### Runtime Control

Enable/disable forced threading at runtime:

```bash
# Enable forced threading
$ echo 1 > /proc/sys/kernel/force_irqthreads

# Disable forced threading (only affects new IRQ registrations)
$ echo 0 > /proc/sys/kernel/force_irqthreads

# Check current setting
$ cat /proc/sys/kernel/force_irqthreads
0
```

**Important**: Changing this at runtime only affects IRQs registered AFTER the change. Existing IRQs keep their current threading mode.

#### How Forced Threading Works

When forced threading is enabled:

```c
/* Simplified from kernel/irq/manage.c */
static int __setup_irq(unsigned int irq, struct irq_desc *desc,
                      struct irqaction *new)
{
    /* Check if threading should be forced */
    if (force_irqthreads) {
        /* If driver didn't provide thread_fn, create a wrapper */
        if (!new->thread_fn) {
            /* Use primary handler as thread handler */
            new->thread_fn = new->handler;
            
            /* Replace primary with generic stub */
            new->handler = irq_default_primary_handler;
        }
        
        /* Force ONESHOT flag */
        new->flags |= IRQF_ONESHOT;
    }
    
    /* ... rest of setup, including thread creation ... */
}

/* Generic primary handler for forced threading */
static irqreturn_t irq_default_primary_handler(int irq, void *dev_id)
{
    /* Just wake the thread */
    return IRQ_WAKE_THREAD;
}
```

**Effect**:

```c
/* Original driver code: */
request_irq(irq, my_handler, flags, "my_device", dev);

/* With forced threading, kernel transforms it to: */
request_threaded_irq(irq,
                    irq_default_primary_handler,  /* Stub */
                    my_handler,                    /* Moves to thread */
                    flags | IRQF_ONESHOT,
                    "my_device",
                    dev);
```

All processing moves to the thread, with only a minimal stub in hardirq context.

#### PREEMPT_RT Behavior

On **PREEMPT_RT kernels**, forced threading is automatic and mandatory:

```c
/* From kernel/irq/manage.c with CONFIG_PREEMPT_RT */
#ifdef CONFIG_PREEMPT_RT
static const bool force_irqthreads = true;
#else
static bool force_irqthreads;
#endif
```

**PREEMPT_RT requirements**:

1. Nearly everything must be preemptible for hard real-time guarantees
2. All interrupts are threaded (except a few critical ones like timer, IPI)
3. IRQ threads can be prioritized above application threads
4. Bounded worst-case latency (<100μs typical)

**Checking if running PREEMPT_RT**:

```bash
$ uname -a | grep PREEMPT_RT
Linux hostname 5.15.0-rt48 #1 SMP PREEMPT_RT Mon Jan 1 12:00:00 UTC 2024 x86_64

$ cat /sys/kernel/realtime
1
```

### Performance Considerations

#### Advantages of Threaded Interrupts

1. **Fully Preemptible Handlers**: Interrupt work can be preempted by higher-priority real-time tasks, ensuring bounded latency.
2. **Priority-Based Scheduling**: IRQ threads can be assigned priorities (using `chrt`) relative to application threads.
3. **Better Real-Time Latency**: Worst-case latency is significantly reduced (e.g., from milliseconds to microseconds) as hardirq sections are minimized.
4. **Clearer Accounting**: IRQ threads appear as distinct processes in `top` and `ps`, making CPU usage visible.
5. **Simplified Locking**: Handlers run in process context, allowing them to sleep, take mutexes, and perform I/O without complex workarounds.

#### Disadvantages of Threaded Interrupts

1. **Context Switch Overhead**: Waking and switching to a thread costs ~2000-5000 cycles, compared to ~100-200 cycles for a hardirq.
2. **Higher Latency**: The handler does not run immediately; it must be scheduled. This adds 5-50 μs of latency depending on load.
3. **Tuning Complexity**: Requires managing thread priorities and affinity to avoid priority inversion or starvation.
4. **Reduced Peak Throughput**: The higher per-interrupt overhead consumes more CPU cycles, potentially limiting maximum packet/IO rates.
5. **Scheduler Dependency**: Handler execution is subject to scheduler decisions and lock contention, unlike hardirqs which run immediately.

#### When to Use Threaded Interrupts

**Use threaded interrupts when**:

1. **Real-time requirements**: Need bounded latency for RT tasks
2. **Slow devices**: I2C, SPI, UART where transactions take milliseconds
3. **Complex processing**: Handler needs to take locks, do I/O, sleep
4. **Low-frequency interrupts**: < 10,000 interrupts/second
5. **PREEMPT_RT kernel**: Required for RT guarantees
6. **Driver simplification**: Threading makes code more straightforward

**DON'T use threaded interrupts when**:

1. **High-frequency interrupts**: > 100,000 interrupts/second
2. **Minimal processing**: Handler only reads a register and sets a flag
3. **Latency-critical acknowledgment**: Device requires immediate ACK
4. **Maximum throughput needed**: Every cycle counts
5. **Simple hardirq handlers**: Already fast enough without threading

**Hybrid approach (best of both)**:

Many drivers use a hybrid model:

```c
/* Fast path in primary handler */
static irqreturn_t my_primary(int irq, void *dev_id)
{
    u32 status = readl(dev->regs + STATUS);
    
    if (status & FAST_PATH_BIT) {
        /* Handle fast path immediately */
        handle_fast_path(dev);
        return IRQ_HANDLED;  /* Don't wake thread */
    }
    
    /* Slow path needs thread */
    return IRQ_WAKE_THREAD;
}

static irqreturn_t my_thread(int irq, void *dev_id)
{
    /* Handle slow path in thread */
    handle_slow_path(dev);
    return IRQ_HANDLED;
}
```

**Result**: Fast path has low latency, slow path gets flexibility.

#### Performance Benchmarks

**Synthetic microbenchmark** (null interrupt handler):

```
Hardware: Intel Core i7-9700K @ 3.6GHz
Kernel: 5.15.0

Test: Trigger interrupt, measure handler completion time

Traditional (hardirq):
    Min: 0.8 μs
    Avg: 1.2 μs
    Max: 2.5 μs
    Throughput: ~800k interrupts/sec @ 50% CPU

Threaded IRQ:
    Min: 4.2 μs
    Avg: 8.5 μs
    Max: 45 μs (scheduler delays)
    Throughput: ~115k interrupts/sec @ 50% CPU
```

**Real-world workload** (network driver, 10GbE):

```
Test: Network throughput and latency

Traditional (NAPI + softirq):
    Throughput: 9.8 Gbps
    P50 latency: 45 μs
    P99 latency: 450 μs
    CPU usage: 35%

Threaded IRQ (forced):
    Throughput: 8.9 Gbps (-9%)
    P50 latency: 52 μs
    P99 latency: 95 μs (better!)
    CPU usage: 42% (+20% overhead)
```

**Key insight**: Threaded IRQs reduce peak throughput but improve worst-case latency.

**Audio workload** (real-time audio processing):

```
Test: Jack audio server, 64-sample buffer @ 48kHz (1.3ms deadline)

Without IRQ threading:
    Xruns (buffer underruns): 12 per hour
    Worst-case latency: 2.8ms (deadline miss)

With IRQ threading + PREEMPT_RT:
    Xruns: 0 per hour
    Worst-case latency: 0.9ms (well under deadline)
```

**Result**: Threaded IRQs enable reliable real-time audio.

### Comparison: Traditional vs. Threaded vs. Forced Threading

Here's a visual comparison of the three interrupt handling models:

#### Traditional Interrupt Model

```
Device raises interrupt
    ↓
Hardware interrupt path
    ↓
┌──────────────────────────────┐
│   Hardirq Handler            │ ← Non-preemptible
│   - Read device status       │   ~100-200 cycles
│   - Acknowledge interrupt    │
│   - Schedule softirq         │
└──────────────────────────────┘
    ↓
Return from interrupt
    ↓
┌──────────────────────────────┐
│   Softirq Processing         │ ← Non-preemptible
│   - Process device data      │   Can take ms
│   - Run protocol stack       │   (or defer to ksoftirqd)
└──────────────────────────────┘
    ↓
Work complete

Characteristics:
✓ Fast (~1μs handler latency)
✓ High throughput
✗ Non-preemptible (unbounded latency for other tasks)
✗ Can't sleep or use mutexes
```

#### Threaded Interrupt Model (Explicit)

```
Device raises interrupt
    ↓
Hardware interrupt path
    ↓
┌──────────────────────────────┐
│   Primary Handler            │ ← Non-preemptible
│   - Quick status check       │   ~100 cycles
│   - Acknowledge if needed    │
│   - Return IRQ_WAKE_THREAD   │
└──────────────────────────────┘
    ↓
If IRQF_ONESHOT: Mask interrupt
    ↓
Wake IRQ thread
    ↓
Return from interrupt (fast!)
    ↓
┌──────────────────────────────┐
│   IRQ Thread (Process        │ ← PREEMPTIBLE!
│   Context)                   │   Runs when scheduled
│   - Process device data      │   Priority: SCHED_FIFO 50
│   - Can sleep, use mutexes   │
│   - Can do I/O               │
└──────────────────────────────┘
    ↓
If IRQF_ONESHOT: Unmask interrupt
    ↓
Work complete

Characteristics:
✓ Preemptible (bounded latency for RT tasks)
✓ Can sleep, use mutexes, do I/O
✓ Clear accounting in tools
✗ Slower (~5-10μs handler latency)
✗ Context switch overhead
```

#### Forced Threading Model

```
Device raises interrupt
    ↓
Hardware interrupt path
    ↓
┌──────────────────────────────┐
│   Generic Stub Handler       │ ← Minimal work
│   - Just return              │   ~50 cycles
│     IRQ_WAKE_THREAD          │
└──────────────────────────────┘
    ↓
Mask interrupt (IRQF_ONESHOT automatic)
    ↓
Wake IRQ thread
    ↓
Return from interrupt (very fast!)
    ↓
┌──────────────────────────────┐
│   IRQ Thread (Process        │ ← Everything here
│   Context)                   │   Fully preemptible
│   - ALL interrupt work       │   Priority: SCHED_FIFO 50
│   - Read device status       │
│   - Process data             │
│   - Everything from original │
│     handler                  │
└──────────────────────────────┘
    ↓
Unmask interrupt
    ↓
Work complete

Characteristics:
✓ Maximum preemptibility
✓ Minimal hardirq time
✓ Uniform model for all IRQs
✗ Highest overhead
✗ May break drivers that assume hardirq context
```

### Interaction with Other Mechanisms

#### Threaded IRQs and Softirqs

Threaded IRQs and softirqs are alternative bottom-half mechanisms:

```
Traditional:  Hardirq → Softirq → Work
Threaded:     Hardirq → IRQ Thread → Work
```

Many drivers use both:

```c
static irqreturn_t my_primary(int irq, void *dev_id)
{
    /* Quick check */
    if (simple_condition) {
        raise_softirq(NET_RX_SOFTIRQ);  /* Use softirq for simple case */
        return IRQ_HANDLED;
    }
    
    return IRQ_WAKE_THREAD;  /* Use thread for complex case */
}
```

#### Threaded IRQs and NAPI

Network drivers often combine threaded IRQs with NAPI:

```c
/* Primary handler disables interrupts, schedules NAPI */
static irqreturn_t eth_primary(int irq, void *dev_id)
{
    struct net_device *ndev = dev_id;
    
    /* Disable device interrupts */
    eth_disable_interrupts(ndev);
    
    /* Schedule NAPI polling */
    napi_schedule(&ndev->napi);
    
    return IRQ_HANDLED;  /* No thread needed */
}

/* NAPI poll runs in softirq context */
static int eth_poll(struct napi_struct *napi, int budget)
{
    /* Process packets... */
}
```

Some drivers use threads for control path, NAPI for data path.

#### Threaded IRQs and Workqueues

Workqueues vs. IRQ threads:

```c
/* IRQ thread: For interrupt-driven work */
request_threaded_irq(irq, primary, thread, flags, name, dev);
/* Thread wakes immediately when interrupt occurs */

/* Workqueue: For deferred work not tied to interrupts */
schedule_work(&work);
/* Work runs when workqueue thread schedules it */
```

**When to use each**:
- **IRQ thread**: Work must happen in response to interrupt
- **Workqueue**: Periodic work, deferred non-critical work

Some drivers use both:

```c
static irqreturn_t my_thread(int irq, void *dev_id)
{
    /* Handle interrupt */
    process_interrupt_data(dev);
    
    /* Schedule additional work for later */
    schedule_delayed_work(&dev->cleanup_work, HZ);
    
    return IRQ_HANDLED;
}
```

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

> **Hardware Latency**: For detailed hardware breakdowns (PCIe, APIC, MSI-X timing), see [Interrupts (Hardware)](./interrupts_hardware.md#performance-summary).

**Software Factors**:
1. **Interrupt Disabled Sections**: Code running with `local_irq_disable()` blocks delivery.
2. **Other Interrupts**: Higher-priority handlers pre-empt or delay lower-priority ones.
3. **Context Switch Overhead**: Saving registers and switching stacks.

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

Modern kernels support IRQ threading (`CONFIG_IRQ_FORCED_THREADING`), which moves interrupt handlers to kernel threads. See the [Threaded Interrupts](#threaded-interrupts) section for comprehensive coverage of how this works.

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

The kernel community has developed several alternatives and mitigations to address softirq limitations:

#### 1. IRQ Threading & PREEMPT_RT
Converting interrupt handlers to kernel threads allows them to be preempted and prioritized. This is the default in **PREEMPT_RT** kernels and available in standard kernels via `threadirqs`.
> See [Threaded Interrupts](#threaded-interrupts) for details.

#### 2. NAPI & Networking
NAPI (New API) switches from interrupt-driven to polling mode under load, preventing interrupt storms and reducing softirq pressure.
> See [NICs](./nics.md) for NAPI architecture and configuration.

#### 3. Workqueues
For work that is not strictly latency-critical or needs to sleep, **workqueues** are preferred over tasklets/softirqs.
> See [Work Queues](#work-queues).

#### 4. CPU Isolation
Isolating CPUs (`isolcpus`) allows dedicating cores to real-time tasks, keeping them free from softirq interference.
> See [Interrupts (Hardware)](./interrupts_hardware.md#cpu-isolation) for configuration.

#### 5. Per-Subsystem Threading
Subsystems like the Block layer (`kblockd`) and RCU (`rcuc/N`) use dedicated per-CPU threads instead of the shared softirq mechanism to improve isolation.

### Best Practices for Driver Developers

1. **Prefer Workqueues**: Default to workqueues unless latency requirements (<1ms) strictly demand softirqs.
2. **Use Threaded IRQs**: Request `request_threaded_irq()` to move work to preemptible process context.
3. **Minimize Softirq Work**: Keep softirq handlers fast; offload heavy computation to process context.
4. **Batch Operations**: Accumulate work and raise softirq once rather than for every item.
5. **Implement Polling**: For high-rate events, use NAPI-style polling to avoid interrupt storms.

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
