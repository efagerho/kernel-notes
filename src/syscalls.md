# System Calls

## Overview

This chapter explains how system calls work on AMD64. We aim to answer the following
questions:

1. Where is the kernel code loaded and how does the CPU find it?
1. What instructions execute in userspace before a syscall?
1. How is CPU state saved/restored, i.e. the calling convention?

## Code Organization

On AMD64 Linux, both user and kernel code exist in the same virtual address space, but
hardware protections prevent user code from accessing kernel memory.

### Virtual to Physical Address Translation

On AMD64, a 64-bit virtual address is structured as follows (for 4-level paging):

```
Bits:  63-48  47-39   38-30   29-21   20-12   11-0
      ┌──────┬───────┬───────┬───────┬───────┬──────┐
      │ Sign │ PML4  │ PDPT  │  PD   │  PT   │Offset│
      │ Ext  │ Index │ Index │ Index │ Index │      │
      └──────┴───────┴───────┴───────┴───────┴──────┘
       16 bits 9 bits  9 bits  9 bits  9 bits 12 bits
```

- **Bits 63-48**: Sign extension (canonical address - must be all 0s or all 1s)
- **Bits 47-39**: PML4 (Page Map Level 4) index - 9 bits = 512 entries
- **Bits 38-30**: PDPT (Page Directory Pointer Table) index - 9 bits = 512 entries
- **Bits 29-21**: PD (Page Directory) index - 9 bits = 512 entries
- **Bits 20-12**: PT (Page Table) index - 9 bits = 512 entries
- **Bits 11-0**: Page offset - 12 bits = 4096 bytes (4 KB page)

The CR3 register holds the physical address of the top-level page table (PML4). When huge pages
are enabled, the offset field covers the PT index or also the PD index.

### Virtual Address Space Layout

On AMD64, the virtual address space is divided between user and kernel space:

```
0xFFFFFFFFFFFFFFFF  ┌─────────────────────┐
                    │                     │
                    │   Kernel Space      │  Ring 0 only
                    │   (Upper half)      │
0xFFFF800000000000  ├─────────────────────┤  ← Canonical address boundary
                    │                     │
                    │  Non-canonical      │  (causes #GP fault)
                    │      (hole)         │
                    │                     │
0x00007FFFFFFFFFFF  ├─────────────────────┤
                    │                     │
                    │   User Space        │  Ring 3 accessible
                    │   (Lower half)      │
                    │                     │
0x0000000000000000  └─────────────────────┘
```

Key characteristics:
- **User space**: `0x0000000000000000` to `0x00007FFFFFFFFFFF` (lower 128 TB)
- **Kernel space**: `0xFFFF800000000000` to `0xFFFFFFFFFFFFFFFF` (upper 128 TB)
- **Non-canonical hole**: Middle addresses are invalid and cause faults

This is the **canonical address** requirement: addresses must have bits 48-63 all zeros
(user space) or all ones (kernel space).

### How Page Tables Enforce Protection

Each entry in the page tables is 64 bits and contains:

```
Bits:  63    62-52   51-12      11-0
      ┌────┬───────┬──────────┬───────┐
      │ XD │Ignored│   PFN    │ Flags │
      └────┴───────┴──────────┴───────┘
```

The Flags field contain permissions bits that control access:

| Bit | Name | Meaning |
|-----|------|---------|
| **P** | Present | Page is in memory (vs. swapped out) |
| **R/W** | Read/Write | 0 = read-only, 1 = read-write |
| **U/S** | User/Supervisor | 0 = kernel only (Ring 0-2), 1 = user accessible (Ring 3) |
| **XD** | Execute Disable | 1 = no-execute (NX bit) |

For kernel pages:
- **U/S bit = 0** (Supervisor): Only accessible when CPL = 0 (kernel mode)
- User mode (CPL = 3) attempts to access these pages trigger a **#PF (Page Fault)** exception

For user pages:
- **U/S bit = 1** (User): Accessible in both kernel and user mode
- This allows the kernel to safely copy data to/from user space

### Userspace Memory Layout

A program is loaded into userspace as follows:

```
0x00007FFFFFFFFFFF  ┌─────────────────────┐
                    │   [stack]           │  ← RSP starts here
                    │       ↓             │     (grows down)
                    ├─────────────────────┤
                    │   (unmapped)        │
                    ├─────────────────────┤
                    │   libc.so           │  ← Shared libraries
                    │   ld-linux.so       │
                    ├─────────────────────┤
                    │   (unmapped)        │
                    ├─────────────────────┤
                    │   [heap]            │  ← malloc() uses this
                    │       ↑             │     (grows up)
                    ├─────────────────────┤
                    │   [bss]             │  ← Uninitialized data
                    ├─────────────────────┤
                    │   [data]            │  ← Initialized data
                    ├─────────────────────┤
                    │   [text]            │  ← Program code
0x0000000000400000  └─────────────────────┘
```

The address at which the program code is loaded can be at some address
`0x0000000000400000 + random_offset` if Address Space Layout Randomization (ASLR)
is enabled.

### Kernel Memory Layout

The **kernel is mapped into every process's address space**, in the upper half (kernel space).
This mapping is done for efficiency. It means system calls don't require switching page tables.

Unfortunately, earlier Intel CPUs did not check the U/S bit in the page tables during
speculative execution. This is what caused the Meltdown vulnerability on older Intel CPUs
allowing userspace to read kernel memory.

On such older CPUs most of kernel memory is not mapped into the address space of the program,
so a page table switch needs to happen when executing syscalls. This feature is called
KPTI (Kernel Page Table Isolation).

The kernel's virtual memory layout (approximate, varies by kernel version):

```
0xFFFFFFFFFFFFFFFF  ┌─────────────────────┐
                    │   (reserved)        │
                    ├─────────────────────┤
                    │   vmalloc/ioremap   │  ← Kernel dynamic memory
                    ├─────────────────────┤
                    │   (gap)             │
                    ├─────────────────────┤
                    │   vmemmap           │  ← Page structs
                    ├─────────────────────┤
                    │   (gap)             │
                    ├─────────────────────┤
                    │   Direct mapping    │  ← All physical RAM
                    │   of physical mem   │     mapped here
                    ├─────────────────────┤
                    │   (gap)             │
                    ├─────────────────────┤
                    │   Kernel text/data  │  ← Kernel code (.text)
                    │   __START_KERNEL    │     and data (.data, .bss)
0xFFFF800000000000  └─────────────────────┘
```

**Important**: Even though kernel memory is mapped into every process's virtual address space,
user code **cannot access it** due to page table permission bits.

## Segment Registers and System Calls

Understanding segment registers is crucial to comprehending how system calls work at the hardware level on AMD64. While segmentation is largely legacy on x86-64, segment registers still play a critical role in privilege level management.

### Segment Registers on AMD64

AMD64 has six segment registers, though their usage differs significantly from 32-bit x86:

| Register | Name | Purpose on AMD64 |
|----------|------|------------------|
| **CS** | Code Segment | Determines privilege level (CPL) and execution mode |
| **SS** | Stack Segment | Determines stack privilege level |
| **DS** | Data Segment | General data (largely unused, base=0) |
| **ES** | Extra Segment | General data (largely unused, base=0) |
| **FS** | F Segment | Used for thread-local storage (TLS) in user-space |
| **GS** | G Segment | Used for per-CPU data in kernel, TLS in user-space |

Segment registers are 16-bits wide and contain indices into the Global/Local Descriptor
Table. The register contain a value as follows:

```
15                3  2  1 0
+------------------+--+----+
|   Index          |TI|RPL |
+------------------+--+----+
```

- **Bits 15-3**: Entry number in GDT/LDT
- **Bit 2**: 0 = GDT, 1 = LDT
- **Bit 1-0**: Requested privilege level

Only specific instructions are allowed to change their value.
When the CPU encounters a virtual address it performs the following checks in the
translation steps:

```
Instruction
  ↓
Segment checks        (CS/DS/SS/FS/GS)
  ↓
Linear address
  ↓
Paging checks         (CR3 → page tables)
  ↓
Physical address
  ↓
Cache / memory access
```

Each step can page fault separately.

When an instruction is fetched from the address of the instruction pointer,
the CS segment register is used to lookup an entry from the GDT, which is then
used to validate the memory access. Instructions like `push/pop/call/ret`
will validate stack access using the SS segment register. Most memory read/write
instructions use the DS segment register. 

The FS segment register is used on Linux to implement Thread-Local Storage. On x86-64, we
can perform instructions like

```
mov rax, [fs:0x30]
```

The virtual address used by the CPU will then be `FS.base + 0x30`, where `FS.base`
is a value stored in the `IA32_FS_BASE` MSR. Every time execution is switched to
another thread, the `IA32_FS_BASE` value is updated.

The GS segment register provides similar functionality. Linux uses GS in kernel
mode to implement per-CPU storage. On privilege transitions, the kernel uses the
`swapgs` instruction to switch between the user GS base and the kernel per-CPU GS base.

### The CPL and Privilege Rings

The **Current Privilege Level (CPL)** is stored in the lower 2 bits of the CS (Code Segment) register:

- **Ring 0** (CPL=0): Kernel mode - full access to all hardware and memory
- **Ring 1** (CPL=1): Unused on most systems
- **Ring 2** (CPL=2): Unused on most systems  
- **Ring 3** (CPL=3): User mode - restricted access

When a system call occurs:
1. CS must transition from Ring 3 (user) to Ring 0 (kernel)
2. SS must also transition to match the new privilege level

### The syscall Instruction

The `syscall` instruction performs these segment register operations:

1. **Loads kernel's CS from IA32_STAR MSR**:
   - Sets CS to the kernel code segment (Ring 0)
   - This changes CPL from 3 to 0
1. **Calculates and loads kernel's SS**:
   - Sets SS to kernel stack segment (Ring 0)
   - SS selector is derived from the value in IA32_STAR MSR (CS + 8)

The **IA32_STAR** (Syscall Target Address Register) MSR contains:
- Bits 63:48 - User CS selector (+16 for SS) for `sysret`
- Bits 47:32 - Kernel CS selector (+8 for SS) for `syscall`
- Bits 31:0 - Not used by `syscall`/`sysret`

When `sysret` returns to user mode, it reverses this process:
1. Restores user's CS from IA32_STAR (setting CPL back to 3)
2. Restores user's SS
3. Restores RIP from RCX (the saved return address)
4. Restores RFLAGS from R11

### Model-Specific Registers (MSRs)

The `syscall` instruction relies on three MSRs that must be initialized during kernel boot:

| MSR | Name | Purpose |
|-----|------|---------|
| **IA32_LSTAR** | Long Mode System Target Address Register | Contains the kernel's RIP (entry point address) |
| **IA32_STAR** | Syscall Target Address Register | Contains CS/SS segment selectors for kernel and user |
| **IA32_FMASK** | Syscall Flag Mask | Specifies which RFLAGS bits to clear on entry |

These MSRs are set once at boot and define how system calls will work for that CPU core. On Linux, you can see these being set in `arch/x86/kernel/cpu/common.c` in the `syscall_init()` function.

### Example: The Complete Picture

When a user program executes `syscall`:

```
Before syscall:
- RIP = 0x0000000000401234  (user code address)
- CS = 0x33                 (user code segment, Ring 3)
- SS = 0x2b                 (user stack segment, Ring 3)
- RSP = 0x00007fff12340000  (user stack)
- CPL = 3                   (user mode)

During syscall:
- RCX ← RIP                 (save return address)
- R11 ← RFLAGS              (save flags)
- RIP ← IA32_LSTAR          (load kernel entry point)
- CS ← IA32_STAR[47:32]     (load kernel CS, Ring 0)
- SS ← IA32_STAR[47:32]+8   (load kernel SS, Ring 0)
- RFLAGS ← RFLAGS & ~IA32_FMASK (mask certain flags)
- CPL = 0                   (kernel mode)

Kernel mode:
- RIP = 0xffffffff81a00000  (kernel entry point)
- CS = 0x10                 (kernel code segment, Ring 0)
- SS = 0x18                 (kernel stack segment, Ring 0)
- RSP = 0xffffc90000123f80  (kernel stack, switched by kernel code)
- CPL = 0                   (kernel mode)
```

Note that while the CPU switches CS and SS automatically, the kernel entry code is responsible for switching RSP to the kernel stack. The CPU doesn't automatically change RSP because it needs to remain accessible to save the user's stack pointer.

## AMD64 System Call ABI

The AMD64 (x86-64) architecture defines a specific Application Binary Interface (ABI)
for making system calls. The system call calling convention is similar to the calling
convention for functions with some differences documented at the end of this chapter.

As mentioned above, the `syscall` instruction is used to transition from user mode to
kernel mode. This instruction:

1. Saves the return address (RIP) to RCX
2. Saves RFLAGS to R11
3. Loads the kernel's RIP from the IA32_LSTAR MSR (Model-Specific Register)
4. Loads the kernel's CS from IA32_STAR MSR
5. Masks RFLAGS using IA32_FMASK MSR
6. Transitions to Ring 0

The corresponding `sysret` instruction returns from kernel mode back to user mode.

### Register Conventions

The AMD64 Linux system call ABI uses the following register conventions:

| Register | Purpose |
|----------|---------|
| **RAX** | System call number (input), return value (output) |
| **RDI** | 1st argument |
| **RSI** | 2nd argument |
| **RDX** | 3rd argument |
| **R10** | 4th argument |
| **R8** | 5th argument |
| **R9** | 6th argument |

As we saw above, the `syscall` instruction clobbers registers `RCX` and `R11`.
Contrary to the userspace calling convention, the 4th argument uses `R10` instead
of `RCX`.

### Example: Making a System Call

Here's a simple example of making the `write` system call (syscall number 1) to write
"Hello, World!\n" to stdout (file descriptor 1):

```asm
section .data
    msg db "Hello, World!", 0x0a    ; message with newline
    len equ $ - msg                 ; length of message

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; fd = 1 (stdout)
    mov rsi, msg        ; buffer = msg
    mov rdx, len        ; count = len
    syscall             ; invoke system call
    
    ; exit(0)
    mov rax, 60         ; syscall number for exit
    xor rdi, rdi        ; status = 0
    syscall             ; invoke system call
```

Note that `rsi` just contains the virtual address of the buffer. The kernel
can directly read the data from this address due to the shared virtual memory
mapping.

### System Call Numbers

Each system call is identified by a unique number. On AMD64 Linux, these numbers are
defined in the kernel and typically found in:
- Kernel headers: `arch/x86/entry/syscalls/syscall_64.tbl`
- User-space headers: `/usr/include/asm/unistd_64.h`

Some common system call numbers on AMD64:

| Number | System Call | Description |
|--------|-------------|-------------|
| 0 | read | Read from file descriptor |
| 1 | write | Write to file descriptor |
| 2 | open | Open file |
| 3 | close | Close file descriptor |
| 9 | mmap | Map memory |
| 57 | fork | Create child process |
| 59 | execve | Execute program |
| 60 | exit | Terminate process |

This table is compiled into a C array:
```c
const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
    [0] = sys_read,
    [1] = sys_write,
    [2] = sys_open,
    [3] = sys_close,
    // ... and so on
};
```

and defined in `arch/x86/entry/syscall/syscall_64.c`.

### Differences from Function Calling Convention

The AMD64 System V ABI (used for regular function calls) differs from the syscall ABI:

**System V ABI** (functions):
- Arguments: RDI, RSI, RDX, RCX, R8, R9, then stack
- Return value: RAX
- Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
- Callee-saved: RBX, RSP, RBP, R12-R15

**Syscall ABI** (system calls):
- Arguments: RDI, RSI, RDX, **R10**, R8, R9 (no stack arguments)
- Return value: RAX
- Only RCX and R11 are clobbered
- All other registers preserved

## The System Call Entry Point

The IA32_LSTAR MSR is initialized during kernel boot to point to the system call entry
function. This happens once per CPU core in `syscall_init()`:

```c
// Simplified from arch/x86/kernel/cpu/common.c
void syscall_init(void)
{
    // Set the system call entry point
    wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
    
    // Set segment selectors
    wrmsrl(MSR_STAR, ((u64)__USER32_CS)<<48  | ((u64)__KERNEL_CS)<<32);
    
    // Set RFLAGS mask
    wrmsrl(MSR_SYSCALL_MASK, X86_EFLAGS_TF|X86_EFLAGS_IF|...);
}
```

The system call entry point `entry_SYSCALL_64` is defined in the Linux kernel at:
- **File**: `arch/x86/entry/entry_64.S`
- **Type**: Assembly code (it must be assembly to handle low-level register operations)

This is one of the most critical pieces of code in the kernel, as it's the gateway
between user and kernel space.

#### What the Entry Point Does

The `entry_SYSCALL_64` function performs several essential tasks:

**1. Save User State**
```asm
ENTRY(entry_SYSCALL_64)
    /* Save user stack pointer */
    movq    %rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
    
    /* Switch to kernel stack */
    movq    PER_CPU_VAR(cpu_current_top_of_stack), %rsp
```

The first critical operation is switching from the user stack to the kernel stack. The
user's RSP is saved in a per-CPU variable, and RSP is loaded with the kernel stack address.
This is necessary because:

- The user stack is not trusted
- The kernel needs its own stack to prevent stack overflow attacks
- Different privilege levels require different stacks

**2. Save Registers on Kernel Stack**
```asm
    /* Save registers to pt_regs structure */
    pushq   $__USER_DS          /* SS */
    pushq   PER_CPU_VAR(rsp_scratch)  /* Saved user RSP */
    pushq   %r11                /* RFLAGS (saved by syscall instruction) */
    pushq   $__USER_CS          /* CS */
    pushq   %rcx                /* RIP (saved by syscall instruction) */
    pushq   %rax                /* System call number */
    pushq   %rdi                /* 1st arg */
    pushq   %rsi                /* 2nd arg */
    pushq   %rdx                /* 3rd arg */
    pushq   %r10                /* 4th arg */
    pushq   %r8                 /* 5th arg */
    pushq   %r9                 /* 6th arg */
```
All relevant registers are pushed onto the kernel stack, creating a `struct pt_regs` that captures the complete CPU state at the moment of the system call.

**3. Handle KPTI (if enabled)**
```asm
    /* Switch to kernel page tables if KPTI is enabled */
    SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
```
If Kernel Page Table Isolation is enabled, the page tables must be switched to give the kernel access to its full memory mapping.

**4. Validate System Call Number**
```asm
    /* Check if syscall number is valid */
    cmpq    $__NR_syscall_max, %rax
    ja      1f                  /* Jump if above maximum */
```
The system call number in RAX is checked against the maximum valid system call number. Invalid numbers are rejected.

**5. Call the System Call Handler**
```asm
    /* Look up system call in table and call it */
    movq    sys_call_table(, %rax, 8), %rax
    call    *%rax
```
The system call number is used as an index into the `sys_call_table` array. Each entry in this table is a function pointer to the actual system call implementation (e.g., `sys_read`, `sys_write`, etc.). The handler is then called with the arguments already in the correct registers.

**6. Return Path**
```asm
    /* Store return value */
    movq    %rax, RAX(%rsp)
    
    /* Check for signals, ptrace, etc. */
    testl   $_TIF_ALLWORK_MASK, CURRENT_THREAD_INFO($ti_flags)
    jnz     syscall_return_work
    
    /* Restore user state and return */
    USERGS_SYSRET64
```
After the system call handler completes:
- The return value (in RAX) is stored in the saved register structure
- The kernel checks if there are pending signals or other work to do
- If no work is pending, it restores the user state and returns to user mode using `sysret`

## System Call Return Path: `syscall_return_work`

Before returning to user space, the kernel must check for pending work that needs to be handled.
work is done by the `syscall_return_work` function. Such work includes:

1. **Pending Signals**: If a signal was sent to the process while it was in the kernel, it needs to be delivered
2. **Thread Flags**: Various thread-specific flags may require action (tracing, single-step, etc.)
3. **Scheduling**: The process may need to be rescheduled if its timeslice expired
4. **Audit/Seccomp**: Security auditing or seccomp filters may need to run
5. **Ptrace**: If the process is being debugged, the tracer may need to be notified

### The Thread Info Flags

The kernel maintains per-thread flags in `struct thread_info`. These flags indicate pending work:

```c
// From arch/x86/include/asm/thread_info.h
#define TIF_SIGPENDING          2   /* signal pending */
#define TIF_NEED_RESCHED        3   /* rescheduling necessary */
#define TIF_SINGLESTEP          4   /* debugger single step */
#define TIF_SYSCALL_TRACE       8   /* syscall trace active */
#define TIF_SYSCALL_AUDIT       9   /* syscall auditing active */
#define TIF_SECCOMP            10   /* seccomp syscall filtering active */
#define TIF_USER_RETURN_NOTIFY 11   /* notify kernel before returning to user */
// ... and more

// Mask of all flags that require work on syscall return
#define _TIF_ALLWORK_MASK                                       \
    (_TIF_SIGPENDING | _TIF_NEED_RESCHED |                      \
     _TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT |                  \
     _TIF_SINGLESTEP | _TIF_SECCOMP | ...)
```

### The Check in Assembly

In the fast path (step 6 of entry point), the kernel checks these flags:

```asm
syscall_return:
    /* Store return value */
    movq    %rax, RAX(%rsp)
    
    /* Load thread flags */
    movq    CURRENT_THREAD_INFO($ti_flags), %r11
    
    /* Test if any work flags are set */
    testl   $_TIF_ALLWORK_MASK, %r11d
    jnz     syscall_return_work      /* Jump if work needed */
    
    /* Fast path: no work, return immediately */
    USERGS_SYSRET64
```

If any of the work flags are set, execution jumps to `syscall_return_work` instead of returning immediately.

### What `syscall_return_work` Does

The `syscall_return_work` function (also in `arch/x86/entry/entry_64.S`) handles the slow path:

```asm
syscall_return_work:
    /* Re-enable interrupts (they were disabled) */
    ENABLE_INTERRUPTS
    
    /* Save registers and call C function */
    movq    %rsp, %rdi              /* pt_regs pointer */
    call    syscall_return_slowpath  /* C function */
    
    /* After handling, return to user mode */
    jmp     syscall_return
```

This assembly stub re-enables interrupts and calls into C code for the actual work handling.

### The C Implementation: `syscall_return_slowpath`

The actual work is done in C code (from `arch/x86/entry/common.c`):

```c
__visible void syscall_return_slowpath(struct pt_regs *regs)
{
    struct thread_info *ti = current_thread_info();
    unsigned long work = READ_ONCE(ti->flags);
    
    /* Handle syscall auditing */
    if (work & _TIF_SYSCALL_AUDIT)
        audit_syscall_exit(regs);
    
    /* Handle ptrace/seccomp */
    if (work & (_TIF_SYSCALL_TRACE | _TIF_SECCOMP))
        syscall_trace_leave(regs);
    
    /* Enter the work loop */
    syscall_exit_work(regs, work);
}
```

The core work loop (`syscall_exit_work`) handles each flag:

```c
static void syscall_exit_work(struct pt_regs *regs, unsigned long work)
{
    while (work) {
        /* Handle pending signals */
        if (work & _TIF_SIGPENDING) {
            do_signal(regs);
            work &= ~_TIF_SIGPENDING;
        }
        
        /* Handle rescheduling */
        if (work & _TIF_NEED_RESCHED) {
            schedule();
            work &= ~_TIF_NEED_RESCHED;
        }
        
        /* Handle single-step for debuggers */
        if (work & _TIF_SINGLESTEP) {
            send_sigtrap(regs);
            work &= ~_TIF_SINGLESTEP;
        }
        
        /* Handle user return notifiers */
        if (work & _TIF_USER_RETURN_NOTIFY) {
            fire_user_return_notifiers();
            work &= ~_TIF_USER_RETURN_NOTIFY;
        }
        
        /* Re-check flags (new work may have arrived) */
        work = READ_ONCE(current_thread_info()->flags) & _TIF_ALLWORK_MASK;
    }
}
```

### Signal Delivery Example

One of the most important tasks is delivering pending signals. Here's how it works:

1. **Signal arrives during syscall**: Another process calls `kill()` to send a signal to our process while it's executing a system call
2. **Kernel sets flag**: The signal handling code sets `TIF_SIGPENDING` in the thread's flags
3. **Syscall completes**: The system call handler finishes and returns
4. **Check detects work**: The `testl $_TIF_ALLWORK_MASK` check finds `TIF_SIGPENDING` is set
5. **Slow path taken**: Execution jumps to `syscall_return_work`
6. **Signal delivered**: `do_signal()` is called, which:
   - Sets up a signal handler frame on the user stack
   - Modifies the saved RIP to point to the signal handler
   - When `sysret` executes, control goes to the signal handler instead of the normal return address
7. **Handler executes**: The user-space signal handler runs
8. **Return**: A special system call (`rt_sigreturn`) restores the original context and the process continues

### Performance Implications

The fast path (no work) is extremely quick:
- One memory read (thread flags)
- One test instruction
- One conditional jump (not taken)
- Then immediate return to user space

The slow path adds overhead:
- Re-enabling interrupts
- Calling C functions
- Potentially handling multiple types of work
- Loop until all work is done

This is why the kernel tries to minimize work on the return path. For example, signal delivery is deferred until syscall return rather than handled immediately when the signal arrives.

### Relation to Other Exit Paths

Other kernel-to-user transitions use similar patterns:

- **Interrupt return** (`ret_from_intr`): Checks same flags before returning
- **Exception return** (`ret_from_exception`): Also checks for pending work
- **Fork return** (`ret_from_fork`): Child process checks work before first user instruction

All paths converge on checking `_TIF_ALLWORK_MASK` and calling similar work handling code. This ensures that no matter how the kernel was entered, all pending work is handled before returning to user mode.
