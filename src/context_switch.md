# Context Switches on AMD64

## Overview

A **context switch** on AMD64 is the process by which the Linux kernel stops executing
one task (`struct task_struct`) on a CPU and resumes execution of another.

Two important clarifications:

1. **A privilege transition is NOT a context switch**: When a user program executes
   `syscall` or triggers an interrupt, the CPU switches from Ring 3 to Ring 0 and
   loads the kernel stack, but it's still the *same task* running. See
   [syscalls.md](syscalls.md) and [Linux Interrupt Handling](linux_interrupts.md) for details on how
   these transitions work.

2. **A context switch requires scheduler involvement**: It only happens when
   `schedule()` (or related functions like `preempt_schedule()`) runs and selects a
   *different* task to execute.

## When do context switches happen on AMD64?

Understanding when context switches occur requires separating **triggers** (events that
request rescheduling) from **execution points** (where `schedule()` actually runs).

### Triggers: what sets TIF_NEED_RESCHED

These events signal that the kernel should switch tasks:

- **Current task blocks**: It goes to sleep waiting for I/O, a lock, or some event,
  and explicitly calls `schedule()` (e.g., from `wait_event()`, `futex()`, `mutex_lock()`).

- **Higher-priority task becomes runnable**: A wakeup, priority change, or scheduling
  class rule decides the current task should yield. The kernel sets the
  `TIF_NEED_RESCHED` thread flag.

- **Timer tick accounting**: The scheduler tick (see [Linux Interrupt Handling](linux_interrupts.md))
  updates vruntime/timeslice accounting and may decide the current task has run long
  enough, setting `TIF_NEED_RESCHED`.

### When the switch actually happens

The actual context switch occurs when the kernel reaches a **safe point** where it can
call `schedule()` and the scheduler returns a different task:

- **Explicit blocking**: Task sets its state (e.g., `TASK_INTERRUPTIBLE`) and calls
  `schedule()` directly.

- **Kernel preemption points**: When preemption is re-enabled (or at explicit
  preemption checks), the kernel notices `TIF_NEED_RESCHED` and calls into the
  scheduler.

- **Return-to-user / return-from-interrupt paths**: Before restoring user state, the
  kernel checks `TIF_NEED_RESCHED`. If set, it calls `schedule()` before executing
  `sysret`/`iretq`. This is described in detail in [syscalls.md](syscalls.md) and
  [Linux Interrupt Handling](linux_interrupts.md).

**Important**: A user thread executing in Ring 3 can only be preempted when a timer
interrupt fires and the return path checks `TIF_NEED_RESCHED`. If no interrupts occur,
and the task doesn't call into the kernel, the task continues running even if
`TIF_NEED_RESCHED` is set.

Linux exposes per-task counters in `/proc/[pid]/status`:

- **voluntary_ctxt_switches**: task blocked/yielded
- **nonvoluntary_ctxt_switches**: task was preempted

For the exact assembly code that checks `TIF_NEED_RESCHED` on return paths, see the
Relationship to Interrupts and Syscalls section below.

## Why are context switches expensive on AMD64?

Even with efficient switching code, context switches impose significant overhead:

### Cache disruption

Modern AMD64 CPUs have multi-level caches (L1/L2/L3). When a context switch occurs:

- The incoming task's working set is likely not in L1/L2 (cold cache)
- Memory accesses incur higher latency until caches warm up
- Branch predictor state is lost (different code paths)

Typical L1 hit: ~4 cycles, L3 hit: ~40 cycles, DRAM access: ~200+ cycles

### TLB disruption and CR3 switching

The **TLB (Translation Lookaside Buffer)** caches recent virtual→physical address
translations. Each TLB entry is tied to a specific page table context.

On AMD64, **CR3** holds the physical address of the current process's top-level page
table (PML4). When switching processes, the kernel loads a new CR3:

```c
write_cr3(__sme_pa(next_mm->pgd) | next_mm->context.asid);
```

#### Without PCID (legacy behavior)

Loading CR3 triggers the CPU to **flush all non-global TLB entries**:

- All user-space translations are invalidated
- The next task starts with a "cold" TLB
- Every memory access requires a page table walk until the TLB repopulates

A page table walk on AMD64 (4-level paging) requires 4 memory accesses (PML4 → PDPT →
PD → PT → final translation), adding ~100-200 cycles per miss.

#### With PCID (Process Context ID)

PCID is x86-64's implementation of address space tagging, allowing the TLB to cache
entries for multiple address spaces simultaneously. With PCID enabled, switching CR3
can preserve TLB entries, dramatically reducing context switch overhead. See the
dedicated PCID section below for full technical details including CR3 bit layout and
allocation strategies.

#### Global pages (G bit)

AMD64 page table entries have a Global flag. Translations marked Global persist across
CR3 changes, which Linux uses for kernel mappings. See the CR3 section below for more
details on global pages and their interaction with PCID.

#### KPTI impact

With KPTI (Kernel Page Table Isolation) enabled for Meltdown mitigation, additional CR3
switches occur on syscall/interrupt entry and exit. See the CR3 section below and
[syscalls.md](syscalls.md) for details on KPTI's dual CR3 strategy.

### XSAVE state overhead

Modern AMD64 CPUs have extensive SIMD/FPU state:

- x87 FPU: 512 bytes
- SSE (XMM0-XMM15): 256 bytes
- AVX (YMM high halves): 256 bytes
- AVX-512 (ZMM16-ZMM31, opmask, etc.): 1664+ bytes

With AVX-512, the complete XSAVE area can exceed 2560 bytes. Saving/restoring this state
on every context switch is expensive, so Linux uses optimizations:

- `XSAVEOPT`: only saves modified components
- `XSAVES`: uses supervisor-mode save area (more compact)
- Eager vs lazy strategies (modern kernels prefer eager)

## CR3 and address space switching on AMD64

### CR3 structure and page table hierarchy

On AMD64 with 4-level paging, CR3 points to the physical address of the **PML4 (Page Map
Level 4)**. For virtual address layout details, see [syscalls.md](syscalls.md).
AMD64 page table entries have a Global flag (bit 8). When CR4.PGE (Page Global Enable)
is set, translations marked Global are NOT flushed on CR3 changes.

Linux marks kernel mappings (kernel text, data, per-CPU areas) as Global, so these
translations persist across process context switches. This is crucial because:
- Kernel code/data is mapped in all address spaces
- Avoids TLB misses when entering/exiting kernel mode
- Works in conjunction with PCID (global pages exempt from PCID tagging)

With KPTI, the behavior is more nuanced: user-mode page tables have minimal global
entries (only entry stubs), while kernel-mode page tables have full kernel mappings
marked global. In other words, in this case each process has two CR3 values, which
are swapped on entering/leaving the kernel.

Loading CR3 is done with the `MOV CR3, reg` instruction:

```c
static inline void native_write_cr3(unsigned long val)
{
    asm volatile("mov %0, %%cr3" : : "r" (val) : "memory");
}
```

The value written to CR3 determines:
1. Which page table hierarchy to use (physical PML4 address)
2. Which PCID namespace to activate (if PCID enabled)
3. Whether to flush TLB entries (bit 63 control)

## PCID: Process Context IDs on x86-64

PCID (Process Context ID) is the x86-64 implementation of address space tagging for TLB
entries. It was introduced to reduce TLB flush overhead.

### PCID mechanics

- **12-bit identifier** (0-4095 possible PCIDs), stored in CR3 bits 11:0
- Becomes part of TLB lookup: `(PCID, virtual_address) → physical_address`
- Linux manages PCID allocation per-mm, stored in `mm->context.asid`

See the CR3 structure section above for the complete CR3 bit layout including PCID
placement and the no-flush control bit.

### PCID enablement

PCID is enabled via CR4.PCIDE (bit 17):

```c
/* From arch/x86/include/asm/tlbflush.h */
static inline void cr4_set_bits_and_update_boot(unsigned long mask)
{
    write_cr4(read_cr4() | mask);
}

/* Enable PCID if CPU supports it */
if (cpu_has(c, X86_FEATURE_PCID))
    cr4_set_bits_and_update_boot(X86_CR4_PCIDE);
```

Once enabled, ALL CR3 loads must include a PCID (bits 11:0 must be valid).

### CR3 bit 63: no-flush control

When loading CR3 with PCID enabled, bit 63 controls TLB behavior:

- **Bit 63 = 0**: Flush all TLB entries for the old PCID (traditional behavior)
- **Bit 63 = 1**: Preserve TLB entries (no flush)

```c
/* From arch/x86/mm/tlb.c */
#define CR3_NO_FLUSH_BIT (1UL << 63)

unsigned long new_cr3 = __sme_pa(next_mm->pgd) | next_mm->context.asid;

if (should_preserve_tlb_entries(prev_mm, next_mm))
    new_cr3 |= CR3_NO_FLUSH_BIT;

write_cr3(new_cr3);
```

This allows the kernel to switch address spaces WITHOUT flushing the TLB, dramatically
improving performance when:
- The incoming task ran recently (its TLB entries still cached)
- The system has low TLB pressure (entries haven't been evicted)

### PCID allocation example

```c
/* Simplified from arch/x86/mm/tlb.c */
static void choose_new_asid(struct mm_struct *mm)
{
    u16 asid = this_cpu_read(cpu_tlbstate.next_asid);
    
    if (asid > MAX_ASID_AVAILABLE) {
        /*
         * Exhausted all PCIDs for this CPU. Flush TLB and restart.
         * This happens infrequently (every ~4000 context switches).
         */
        flush_tlb_all();
        asid = 1;  /* PCID 0 reserved */
    }
    
    mm->context.asid = asid;
    this_cpu_write(cpu_tlbstate.next_asid, asid + 1);
}
```

### Performance impact

Measured context switch latency on modern Intel CPUs:

- Without PCID: ~4-6 µs (TLB flush + repopulate overhead)
- With PCID: ~1-2 µs (TLB entries preserved)

The benefit is most pronounced for workloads with frequent context switches and good
temporal locality (tasks switching back and forth).

## switch_mm() on AMD64

The memory context switch is handled by `switch_mm_irqs_off()` (called from
`context_switch()` in `kernel/sched/core.c`). Its job is to load the correct CR3 for
the incoming task.

### Implementation structure

```c
/* From arch/x86/mm/tlb.c */
void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
                       struct task_struct *tsk)
{
    struct mm_struct *real_prev = this_cpu_read(cpu_tlbstate.loaded_mm);
    
    /*
     * Fast path: switching between threads in same process.
     * CR3 already points to correct page tables.
     */
    if (likely(real_prev == next))
        return;
    
    /*
     * Kernel thread: next->mm == NULL.
     * Don't load a new CR3; just borrow the previous active_mm.
     * This is "lazy TLB" mode.
     */
    if (unlikely(!next)) {
        /* Kernel thread continues using previous address space */
        tsk->active_mm = real_prev;
        return;
    }
    
    /*
     * Normal process switch: load new CR3.
     */
    load_new_mm_cr3(next);
    
    /*
     * Switch the active_mm and update per-CPU tracking.
     */
    this_cpu_write(cpu_tlbstate.loaded_mm, next);
    tsk->active_mm = next;
    
    /*
     * Handle any deferred TLB invalidations for this mm.
     * This flushes ranges that were modified while this mm wasn't active.
     */
    if (unlikely(next->tlb_gen > this_cpu_read(cpu_tlbstate.tlb_gen)))
        flush_tlb_mm_range(next, ...);
}
```

### Handling SME (Secure Memory Encryption)

On AMD CPUs with SME enabled, physical addresses must include encryption bits:

```c
/* From arch/x86/include/asm/mem_encrypt.h */
#define __sme_pa(x) (__pa(x) | sme_me_mask)
```

The `sme_me_mask` contains the C-bit (encryption bit) position for AMD's SME feature.

### Lazy TLB for kernel threads

Kernel threads (e.g., `kworker`, `kswapd`) have `mm == NULL`. When switching to a
kernel thread, the kernel avoids loading a new CR3:

```c
if (!next_mm) {
    /* Keep CR3 unchanged; borrow previous mm */
    tsk->active_mm = prev_mm;
    return;  /* No CR3 load */
}
```

This optimization is called "lazy TLB." See the Kernel Threads section below for a
detailed explanation of why this works and its performance benefits.

### TLB invalidation batching

Linux batches TLB invalidations using generation counters:

```c
/* From include/linux/mm_types.h */
struct mm_struct {
    atomic64_t tlb_gen;  /* TLB generation number */
    ...
};

/* Per-CPU state tracks last seen generation */
struct tlb_state {
    u64 tlb_gen;  /* Last TLB gen we processed */
    ...
};
```

When unmapping pages in an mm that's not currently active on this CPU, the kernel
increments `mm->tlb_gen` instead of sending an IPI. On next context switch to that mm,
`switch_mm_irqs_off()` detects the mismatch and flushes affected ranges.

## Register context switching: switch_to() on AMD64

Switching the address space (CR3) is only half the work. The kernel must also switch
CPU register state and the kernel stack pointer (RSP).

### The switch_to() macro

Defined in `arch/x86/include/asm/switch_to.h`:

```c
#define switch_to(prev, next, last)                                    \
do {                                                                   \
    prepare_switch_to(prev, next);                                    \
                                                                       \
    /* The actual low-level register/stack switch */                  \
    ((last) = __switch_to_asm((prev), (next)));                       \
                                                                       \
    finish_switch_to(last);                                           \
} while (0)
```

The `last` parameter is subtle: after `__switch_to_asm()` returns, we're running on
the *next* task's stack, so `prev` may have been rescheduled by another CPU. `last`
tells us which task we actually switched away from.

Note that `switch_to()` runs very quickly as it only saves/restores registers.
Exposing it to userspace would make it possible to implement cooperative multitasking
mechanisms on top of it. This is for instance what Google's fibers implementation did.

### Which registers need saving?

On AMD64, the System V ABI defines calling conventions:

**Callee-saved registers** (preserved across function calls):
- RBX, RBP, R12, R13, R14, R15
- RSP (stack pointer)

**Caller-saved registers** (not preserved):
- RAX, RCX, RDX, RSI, RDI, R8-R11

Since `schedule()` is a normal C function call, only callee-saved registers need
explicit saving in `switch_to`. All caller-saved registers were already saved by the
compiler-generated prologue of functions that called `schedule()`.

### __switch_to_asm(): the assembly trampoline

```asm
/* From arch/x86/entry/entry_64.S */
SYM_FUNC_START(__switch_to_asm)
    /*
     * Save callee-saved registers on prev's kernel stack.
     * Layout matches struct inactive_task_frame.
     */
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* Save prev's RSP into prev->thread.sp */
    movq    %rsp, TASK_thread_sp(%rdi)

    /* Load next's RSP from next->thread.sp */
    movq    TASK_thread_sp(%rsi), %rsp

    /* Restore callee-saved registers from next's kernel stack */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp

    /* 
     * Call __switch_to() (C function) to handle:
     * - FPU state
     * - Segment registers (FS base)
     * - Per-CPU current task pointer
     */
    jmp     __switch_to
SYM_FUNC_END(__switch_to_asm)
```

The crucial operation: **switching RSP** from prev's kernel stack to next's kernel stack.
After `movq TASK_thread_sp(%rsi), %rsp`, all subsequent memory references (pushes,
pops, function calls) use next's stack.

### Stack layout during switch

Before `__switch_to_asm()`:
```
prev's kernel stack (RSP):
    [... prev's stack frames ...]
    [return address to __schedule()]
```

After saving registers and switching RSP:
```
prev's kernel stack:
    [saved R15]
    [saved R14]
    [saved R13]
    [saved R12]
    [saved RBX]
    [saved RBP]
    [return address to __schedule()]  ← prev->thread.sp points here

next's kernel stack (new RSP):
    [saved R15]  ← being popped
    [saved R14]
    [saved R13]
    [saved R12]
    [saved RBX]
    [saved RBP]
    [return address to some previous __schedule() call]
```

When `__switch_to_asm()` returns (via `jmp __switch_to` → `ret`), it returns to
wherever next was previously blocked, continuing next's execution.

### __switch_to(): high-level register handling

```c
/* From arch/x86/kernel/process_64.c */
__visible __notrace_funcgraph struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
    struct thread_struct *prev = &prev_p->thread;
    struct thread_struct *next = &next_p->thread;
    
    /* Update per-CPU current task pointer */
    this_cpu_write(current_task, next_p);
    
    /* Switch FS base (see Segment Registers section) */
    if (unlikely(prev->fsbase != next->fsbase)) {
        if (cpu_feature_enabled(X86_FEATURE_FSGSBASE))
            wrfsbase(next->fsbase);
        else
            wrmsrl(MSR_FS_BASE, next->fsbase);
    }
    
    /* Switch FPU/XSAVE state */
    switch_fpu_prepare(prev_p, cpu);
    switch_fpu_finish(next_p);
    
    return prev_p;  /* Return "last" for switch_to() macro */
}
```

### RIP (instruction pointer) handling

RIP doesn't need explicit saving because it's preserved implicitly:

1. When `schedule()` is called, the return address is pushed onto the stack by `call`
2. This return address remains on prev's stack when RSP is switched
3. When next is later scheduled back in, RSP points to its saved return address
4. The `ret` at the end of `__switch_to()` pops and jumps to that address

So RIP "switching" happens naturally through normal function return mechanics.

## Segment registers on AMD64

While segmentation is mostly legacy on x86-64, segment registers still serve important
purposes for context switching.

### FS base: per-thread storage

The FS segment base register (`FS.base`, stored in MSR `IA32_FS_BASE` or accessed via
`RDFSBASE`/`WRFSBASE`) provides per-thread storage for user-space:

```c
/* User-space TLS access */
mov %fs:0x10, %rax  /* Read thread-local variable at offset 0x10 */
```

Each thread has its own FS base value, so context switches must update it:

```c
/* From arch/x86/kernel/process_64.c */
void x86_fsbase_write_task(struct task_struct *task, unsigned long fsbase)
{
    task->thread.fsbase = fsbase;
    
    if (task == current) {
        /* Update CPU's FS base immediately */
        if (cpu_feature_enabled(X86_FEATURE_FSGSBASE))
            wrfsbase(fsbase);
        else
            wrmsrl(MSR_FS_BASE, fsbase);
    }
}
```

On context switch in `__switch_to()`:

```c
if (prev->fsbase != next->fsbase) {
    if (cpu_feature_enabled(X86_FEATURE_FSGSBASE))
        wrfsbase(next->fsbase);  /* Fast: single instruction */
    else
        wrmsrl(MSR_FS_BASE, next->fsbase);  /* Slower: MSR write */
}
```

### GS base: per-CPU kernel data

The GS segment base is used differently in kernel vs user mode:

- **Kernel mode**: `GS.base` points to per-CPU data area
- **User mode**: `GS.base` can be used for TLS (like FS)

The `swapgs` instruction exchanges `GS.base` with `IA32_KERNEL_GS_BASE` MSR:

```asm
/* On syscall entry (from arch/x86/entry/entry_64.S) */
swapgs  /* Swap user GS.base with kernel per-CPU pointer */
```

Crucially, `GS.base` does NOT change on context switch (within kernel mode). It always
points to the same per-CPU area. What changes is the `current` task pointer stored
*within* that per-CPU area:

```c
/* From arch/x86/kernel/process_64.c */
this_cpu_write(current_task, next_p);
```

See the Per-CPU Data and GS section below for details on how per-CPU variables are
accessed and why this design enables fast `current` access without reloading GS.

### WRFSBASE/WRGSBASE instructions

Modern x86-64 CPUs support direct FS/GS base manipulation via instructions (instead of
slow MSR writes):

```asm
rdfsbase %rax     /* Read FS.base into RAX */
wrfsbase %rax     /* Write RAX to FS.base */
rdgsbase %rax     /* Read GS.base into RAX */
wrgsbase %rax     /* Write RAX to GS.base */
```

These are much faster than `rdmsr`/`wrmsr` (~20 cycles vs ~200 cycles), so Linux prefers
them when available:

```c
if (cpu_feature_enabled(X86_FEATURE_FSGSBASE)) {
    wrfsbase(next->fsbase);  /* Fast path */
} else {
    wrmsrl(MSR_FS_BASE, next->fsbase);  /* Legacy fallback */
}
```

## Per-CPU data and GS on AMD64

Linux relies heavily on per-CPU variables for lock-free access to CPU-local state.

### Per-CPU area layout

Each CPU has a dedicated memory area for per-CPU variables:

```c
/* From include/linux/percpu-defs.h */
DECLARE_PER_CPU(struct task_struct *, current_task);
DECLARE_PER_CPU(unsigned long, kernel_stack);
DECLARE_PER_CPU(struct tlb_state, cpu_tlbstate);
/* ... many more ... */
```

On AMD64, `GS.base` points to the start of the current CPU's per-CPU area:

```
CPU 0's GS.base → [per-CPU area for CPU 0]
                  - current_task
                  - kernel_stack
                  - cpu_tlbstate
                  - ...

CPU 1's GS.base → [per-CPU area for CPU 1]
                  - current_task
                  - kernel_stack
                  - cpu_tlbstate
                  - ...
```

### Accessing per-CPU variables

```c
/* From arch/x86/include/asm/percpu.h */
#define this_cpu_read(var)   percpu_from_op("mov", var)
#define this_cpu_write(var, val)   percpu_from_op("mov", var, val)

#define percpu_from_op(op, var, ...)                \
({                                                   \
    typeof(var) pfo_ret__;                          \
    asm(op " %%gs:%P1, %0"                          \
        : "=r" (pfo_ret__)                           \
        : "m" (var));                                \
    pfo_ret__;                                       \
})
```

This generates a single instruction:

```asm
mov %gs:offset_of_var, %rax
```

### Why GS doesn't change on context switch

Key insight: **GS.base is per-CPU, not per-task**.

- All tasks running on CPU 0 use the same GS.base (CPU 0's per-CPU area)
- On context switch, only the `current_task` pointer within that area changes

```c
/* In __switch_to() */
this_cpu_write(current_task, next_p);

/* Expands to: */
mov %rsi, %gs:current_task_offset  /* Update pointer at fixed offset */
```

So `get_current()` reads the updated pointer:

```c
struct task_struct *t = this_cpu_read(current_task);
/* Reads from %gs:current_task_offset, which now points to next_p */
```

### swapgs on kernel entry/exit

When transitioning between user and kernel mode, `swapgs` exchanges the two GS base
values:

```asm
/* User mode: GS.base = user TLS pointer */
syscall  /* Enter kernel */

/* Kernel entry code: */
swapgs   /* Now GS.base = kernel per-CPU area */
         /* IA32_KERNEL_GS_BASE = user TLS pointer (saved) */

/* ... kernel code uses %gs: for per-CPU access ... */

/* Before returning to user: */
swapgs   /* Restore user GS.base */
sysretq  /* Return to user mode */
```

See [syscalls.md](syscalls.md) and [Linux Interrupt Handling](linux_interrupts.md) for complete details.

## FPU/SSE/AVX state on AMD64: XSAVE

Modern x86-64 CPUs have extensive floating-point and vector state that must be preserved
across context switches.

### Extended state components

- **x87 FPU**: 8 x 80-bit floating-point registers (ST0-ST7), control/status words
- **SSE**: 16 x 128-bit XMM registers (XMM0-XMM15)
- **AVX**: 16 x 128-bit YMM high halves (extending XMM to 256-bit)
- **AVX-512**: 16 x 256-bit ZMM high halves (extending YMM to 512-bit)
- **AVX-512**: 16 additional ZMM registers (ZMM16-ZMM31)
- **AVX-512**: 8 x 64-bit opmask registers (k0-k7)
- **MPX**: Memory Protection Extensions bounds registers (if enabled)

Total size can exceed 2560 bytes with all features enabled.

### XSAVE/XRSTOR instructions

XSAVE saves extended state to memory:

```asm
/* Save all enabled state components */
xsave64 [%rdi]  /* RDI points to save area */

/* What gets saved is controlled by XCR0 (Extended Control Register 0) */
/* and the requested feature mask in EDX:EAX */
```

XRSTOR restores state:

```asm
xrstor64 [%rsi]  /* RSI points to save area */
```

### XSAVE area layout

```c
/* From arch/x86/include/asm/fpu/types.h */
struct xregs_state {
    struct fxregs_state  i387;     /* x87/SSE state (512 bytes) */
    struct xstate_header header;   /* XSAVE header (64 bytes) */
    struct ymmh_struct   ymmh;     /* AVX YMM high halves (256 bytes) */
    /* Extended components follow based on CPUID */
};
```

The header includes a bitmask indicating which components are in their init state (can
skip saving/restoring).

### XSAVEOPT optimization

`XSAVEOPT` only saves components that have been modified since last `XRSTOR`:

```asm
xsaveopt64 [%rdi]  /* Only saves dirty components */
```

This reduces memory bandwidth if, e.g., a task only used SSE but not AVX.

### XSAVES: supervisor mode save

`XSAVES` provides a more compact save format and can save supervisor-mode state:

```asm
xsaves64 [%rdi]  /* Compact format, supervisor state */
xrstors64 [%rsi] /* Restore from compact format */
```

Modern kernels prefer XSAVES when available.

### Legacy lazy FPU switching (historical)

Older kernels used lazy FPU switching to avoid saving/restoring FPU state on every
context switch:

1. On context switch, set `CR0.TS` (Task Switched) bit
2. First FPU/SSE instruction triggers `#NM` (Device Not Available) exception
3. Exception handler:
   - Saves prev task's FPU state (if dirty)
   - Restores current task's FPU state
   - Clears `CR0.TS`
4. Task continues with FPU access

This avoided overhead for tasks that don't use FPU/SSE.

### Modern eager switching

Current kernels use eager FPU switching: always save/restore on context switch. Why?

1. **Security**: Lazy switching leaked FPU state across tasks (Meltdown-style attacks)
2. **Prevalence**: Almost all tasks use SSE (even for `memcpy`), so lazy rarely helped
3. **XSAVEOPT**: Hardware optimization makes eager switching cheap

```c
/* From arch/x86/kernel/fpu/core.c */
void switch_fpu_prepare(struct task_struct *prev, int cpu)
{
    /* Save prev's FPU state if it was active */
    if (prev->thread.fpu.initialized) {
        if (cpu_feature_enabled(X86_FEATURE_XSAVES))
            xsaves(&prev->thread.fpu.state.xsave, -1);
        else
            xsaveopt(&prev->thread.fpu.state.xsave, -1);
    }
}

void switch_fpu_finish(struct task_struct *next)
{
    /* Restore next's FPU state */
    if (next->thread.fpu.initialized) {
        if (cpu_feature_enabled(X86_FEATURE_XSAVES))
            xrstors(&next->thread.fpu.state.xsave, -1);
        else
            xrstor(&next->thread.fpu.state.xsave, -1);
    }
}
```

### Handling kernel FPU usage

Normally, the kernel doesn't use FPU/SSE. But some code paths need it (crypto, RAID XOR):

```c
kernel_fpu_begin();
/* Can use XMM registers for vectorized operations */
kernel_fpu_end();
```

This saves/restores FPU state around the kernel usage, ensuring user state is preserved.

## The complete AMD64 context switch walkthrough

Let's trace a concrete example: switching from Task A (PID 1234) to Task B (PID 5678)
on CPU 0.

### Initial state (Task A running)

```
CPU 0 registers:
  RIP = 0xffffffff81234567  (in schedule())
  RSP = 0xffffc90000123f80  (Task A's kernel stack)
  CR3 = 0x0000000012345000 | PCID=7
  GS.base = 0xffff888100000000  (CPU 0's per-CPU area)
  FS.base = 0x00007f8a9b400000  (Task A's TLS)

Task A state:
  task_struct at 0xffff888012340000
  thread.sp = <not yet saved>
  thread.fsbase = 0x00007f8a9b400000
  mm->pgd = 0xffff888012345000 (virtual)
  mm->context.asid = 7

Task B state:
  task_struct at 0xffff888056780000
  thread.sp = 0xffffc90000456f40  (saved RSP from last time)
  thread.fsbase = 0x00007f3c2d800000
  mm->pgd = 0xffff888067890000 (virtual)
  mm->context.asid = 12
```

### Step 1: schedule() calls context_switch()

```c
/* From kernel/sched/core.c */
static void context_switch(struct rq *rq,
                          struct task_struct *prev,
                          struct task_struct *next)
{
    prepare_task_switch(rq, prev, next);
    
    /* Switch memory context */
    switch_mm_irqs_off(prev->mm, next->mm, next);
    
    /* Switch register context */
    switch_to(prev, next, prev);
    
    finish_task_switch(prev);
}
```

### Step 2: switch_mm_irqs_off() loads new CR3

```c
/* In arch/x86/mm/tlb.c */
void switch_mm_irqs_off(struct mm_struct *prev_mm,
                       struct mm_struct *next_mm,
                       struct task_struct *next)
{
    /* prev_mm != next_mm, not a kernel thread */
    
    /* Build new CR3 value */
    unsigned long new_cr3 = __sme_pa(next_mm->pgd) | next_mm->context.asid;
    new_cr3 |= CR3_NO_FLUSH_BIT;  /* Preserve TLB entries */
    
    /* Load new CR3 */
    write_cr3(new_cr3);  /* MOV 0x0000000067890000|12|(1<<63), %CR3 */
    
    /* Update tracking */
    this_cpu_write(cpu_tlbstate.loaded_mm, next_mm);
    next->active_mm = next_mm;
}
```

**State after CR3 switch**:
```
CR3 = 0x8000000067890000 | PCID=12  (bit 63 set = no flush)
Task B's page tables now active
TLB entries for both PCID=7 and PCID=12 remain cached
```

### Step 3: switch_to() macro invokes __switch_to_asm()

```asm
/* In arch/x86/entry/entry_64.S */
__switch_to_asm:
    /* Save Task A's callee-saved registers */
    pushq   %rbp        /* RSP: 0xffffc90000123f78 */
    pushq   %rbx        /* RSP: 0xffffc90000123f70 */
    pushq   %r12        /* RSP: 0xffffc90000123f68 */
    pushq   %r13        /* RSP: 0xffffc90000123f60 */
    pushq   %r14        /* RSP: 0xffffc90000123f58 */
    pushq   %r15        /* RSP: 0xffffc90000123f50 */
    
    /* Save Task A's RSP */
    movq    %rsp, TASK_thread_sp(%rdi)  /* task_A->thread.sp = 0xffffc90000123f50 */
    
    /* Load Task B's RSP */
    movq    TASK_thread_sp(%rsi), %rsp  /* RSP = 0xffffc90000456f40 */
    
    /* Restore Task B's callee-saved registers */
    popq    %r15        /* RSP: 0xffffc90000456f48 */
    popq    %r14        /* RSP: 0xffffc90000456f50 */
    popq    %r13        /* RSP: 0xffffc90000456f58 */
    popq    %r12        /* RSP: 0xffffc90000456f60 */
    popq    %rbx        /* RSP: 0xffffc90000456f68 */
    popq    %rbp        /* RSP: 0xffffc90000456f70 */
    
    /* Jump to __switch_to() */
    jmp     __switch_to
```

**State after RSP switch**:
```
Now executing on Task B's kernel stack
RSP = 0xffffc90000456f70
Next RET will pop return address from Task B's stack
  (some previous call to schedule() from Task B's context)
```

### Step 4: __switch_to() handles remaining state

```c
/* In arch/x86/kernel/process_64.c */
struct task_struct *__switch_to(struct task_struct *prev_p,
                                struct task_struct *next_p)
{
    /* Update per-CPU current pointer */
    this_cpu_write(current_task, next_p);
    /* %gs:current_task_offset = 0xffff888056780000 (Task B) */
    
    /* Switch FS base to Task B's TLS */
    if (prev_p->thread.fsbase != next_p->thread.fsbase) {
        wrfsbase(next_p->thread.fsbase);
        /* FS.base = 0x00007f3c2d800000 */
    }
    
    /* Switch FPU state */
    switch_fpu_prepare(prev_p, 0);  /* Save Task A's XMM/YMM/ZMM */
    switch_fpu_finish(next_p);       /* Restore Task B's XSAVE area */
    
    return prev_p;
}
```

### Step 5: Return from schedule() in Task B's context

```c
/* __switch_to() returns to __switch_to_asm */
/* __switch_to_asm does RET, popping return address from Task B's stack */
/* Control returns to wherever Task B previously called schedule() */

/* Now executing Task B's code */
```

**Final state**:
```
CPU 0 registers:
  RIP = 0xffffffff81234abc  (in Task B's context, wherever it blocked)
  RSP = 0xffffc90000456f78  (Task B's kernel stack)
  CR3 = 0x8000000067890000 | PCID=12
  GS.base = 0xffff888100000000  (unchanged, still CPU 0's per-CPU area)
  FS.base = 0x00007f3c2d800000  (Task B's TLS)

Per-CPU state:
  current_task = 0xffff888056780000  (Task B)
  cpu_tlbstate.loaded_mm = Task B's mm

Task A state (saved):
  thread.sp = 0xffffc90000123f50
  thread.fsbase = 0x00007f8a9b400000
  FPU state saved in task_struct

Task B state (active):
  thread.sp = <will be saved on next switch>
  Executing in kernel or about to return to user mode
```

### Timeline summary

```
Time  CPU State
----  --------------------
T0    Task A running, CR3=...12345|7, RSP=...123f80
T1    schedule() called by Task A
T2    pick_next_task() selects Task B
T3    switch_mm() loads CR3=...67890|12 (bit 63=1, TLB preserved)
T4    __switch_to_asm() saves RBX-R15, switches RSP to Task B's stack
T5    __switch_to() updates current, FS.base, FPU state
T6    Returns into Task B's previous schedule() call site
T7    Task B resumes execution
```

Total context switch time: ~1-2 µs (with PCID), ~4-6 µs (without PCID)

## Kernel threads on AMD64

Kernel threads are tasks that run only in kernel mode and have no user address space.
Examples: `kworker`, `kswapd`, `ksoftirqd`, `migration` threads.

### Characteristics

- `task->mm == NULL` (no user address space)
- `task->active_mm` points to borrowed address space
- Never return to Ring 3 (no user mode)
- Have kernel stack but no user stack

### Lazy TLB: avoiding CR3 loads

When switching to a kernel thread, Linux avoids loading a new CR3:

```c
/* In switch_mm_irqs_off() */
if (unlikely(!next_mm)) {
    /* Kernel thread: borrow previous mm, keep current CR3 */
    tsk->active_mm = real_prev;
    enter_lazy_tlb(real_prev, tsk);
    return;  /* No CR3 write */
}
```

The kernel can do this because:
- Kernel threads only access kernel memory (upper half of virtual address space)
- Kernel mappings are identical across all processes
- The "borrowed" address space provides valid kernel mappings

### Why this matters

Kernel threads frequently run for short periods (handling softirqs, writeback, etc.).
Without lazy TLB, every switch to/from a kernel thread would require two CR3 writes:

```
User Task A → Kernel Thread → User Task B
Without lazy TLB: 2 CR3 writes
With lazy TLB:    1 CR3 write (only when switching to Task B)
```

On a busy system, this saves thousands of CR3 writes per second.

### active_mm tracking

```c
struct task_struct {
    struct mm_struct *mm;         /* Real mm (NULL for kthreads) */
    struct mm_struct *active_mm;  /* What's in CR3 right now */
};
```

For user tasks: `mm == active_mm`  
For kernel threads: `mm == NULL`, `active_mm` is borrowed

### Example: kworker execution

```
Timeline:
T0: User Task A running, CR3 points to Task A's page tables
T1: Interrupt occurs, wakes kworker
T2: Return from interrupt checks TIF_NEED_RESCHED
T3: schedule() picks kworker
T4: switch_mm() sees kworker->mm == NULL, keeps CR3 unchanged
T5: kworker executes (using Task A's page tables for kernel access)
T6: kworker blocks, schedule() picks Task B
T7: switch_mm() loads Task B's CR3
```

Only one CR3 write despite two context switches.

## Performance characteristics on AMD64

Context switch performance varies significantly based on CPU features and workload.

### Cycle counts (approximate, modern Intel/AMD CPUs)

| Operation | Cycles (approx) |
|-----------|-----------------|
| schedule() overhead | 500-1000 |
| CR3 write (no PCID, flush) | 2000-4000 |
| CR3 write (PCID, no flush) | 200-400 |
| XSAVE (AVX-512) | 500-1000 |
| XRSTOR (AVX-512) | 500-1000 |
| TLB miss + page walk | 100-200 each |
| Cache line miss L3 | 40-80 |
| FS base write (WRFSBASE) | 20-30 |
| FS base write (MSR) | 150-200 |
| **Total (with PCID)** | **2000-4000 cycles** |
| **Total (without PCID)** | **5000-10000 cycles** |

At 3 GHz: 2000 cycles ≈ 0.67 µs, 5000 cycles ≈ 1.67 µs

### PCID impact

As explained in the PCID section above, PCID dramatically reduces TLB flush overhead.
Measured context switch latency (microbenchmark):

```
Without PCID:
  Min: 3.2 µs
  Avg: 4.8 µs
  Max: 12.1 µs (cold TLB)

With PCID:
  Min: 0.9 µs
  Avg: 1.4 µs
  Max: 3.2 µs
```

PCID provides 3-4x improvement by eliminating TLB flush overhead.

### Cache effects

After a context switch, the incoming task typically sees:

- **L1 cache**: ~10% hit rate initially (mostly kernel code)
- **L2 cache**: ~30% hit rate
- **L3 cache**: ~50% hit rate (shared across cores, may have data)

Cache warm-up time: 100-500 µs depending on working set size.

### Branch predictor effects

Modern CPUs have large branch predictors (~16K entries). On context switch:
- Branch prediction tables remain, but are now predicting wrong context
- Misprediction rate spikes for first ~1000 branches
- Recovery time: 50-200 µs

### Why frequent switching hurts

Consider a workload with 1000 context switches per second:

```
Without PCID:
  1000 switches × 5 µs = 5ms CPU time
  TLB misses: ~1000 × 50 = 50,000 extra page walks
  Cache misses: High for ~500ms total

With PCID:
  1000 switches × 1.5 µs = 1.5ms CPU time
  TLB misses: Minimal if working sets fit
  Cache misses: Still significant

Either way, frequent switching reduces effective CPU throughput by 10-30%.
```

### Hyperthreading (SMT) considerations

Intel's Hyperthreading presents two logical CPUs per physical core, sharing execution
units but with separate register files and per-thread state.

Hardware context switch (between SMT siblings):
- Registers already separate
- TLB/cache tagged with thread ID
- Switch cost: ~1000 cycles (very fast)

This is why high-frequency, low-latency applications sometimes use SMT siblings for
different tasks rather than kernel-level context switching.

## AMD64 stack layout during context switch

Understanding the kernel stack layout is crucial for debugging context switches.

### Kernel stack structure

Each task has a kernel stack (typically 16KB on x86-64):

```
High address (top of stack)
┌─────────────────────────────────────┐
│         thread_info                 │  Optional: may be at bottom or separate
├─────────────────────────────────────┤
│         (stack grows down)          │
│                                     │
│                                     │
├─────────────────────────────────────┤  ← RSP when task is running
│      [current stack frames]         │
├─────────────────────────────────────┤
│      struct pt_regs (if from        │  Saved by interrupt/syscall entry
│      interrupt/syscall)             │
├─────────────────────────────────────┤
│      [more stack frames]            │
├─────────────────────────────────────┤
│      inactive_task_frame            │  ← task->thread.sp when context switched
│      - saved R15                    │
│      - saved R14                    │
│      - saved R13                    │
│      - saved R12                    │
│      - saved RBX                    │
│      - saved RBP                    │
│      - return address               │
├─────────────────────────────────────┤
│      [unused stack space]           │
Low address (bottom of stack)
└─────────────────────────────────────┘
```

### pt_regs structure

When entering kernel from user mode (via `syscall` or interrupt), the entry code saves
all registers into `struct pt_regs`:

```c
/* From arch/x86/include/asm/ptrace.h */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    /* Above registers saved by C code */
    
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    /* Above registers saved by entry stub */
    
    unsigned long orig_rax;  /* Original RAX (syscall number) */
    
    unsigned long rip;       /* Saved by CPU on interrupt/syscall */
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;       /* User RSP */
    unsigned long ss;
};
```

Size: 168 bytes

### inactive_task_frame

When a task is context-switched out, its RSP points to this structure:

```c
/* From arch/x86/include/asm/switch_to.h */
struct inactive_task_frame {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long ret_addr;  /* Return address into __schedule() */
};
```

This matches what `__switch_to_asm()` pushes onto the stack.

### Example stack snapshot

Task blocked in `schedule()` after coming from user mode via timer interrupt:

```
Address           Content
───────────────────────────────────────────
0xffffc90000124000  (top of 16KB stack)
...
0xffffc90000123e00  struct pt_regs
                    - r15 = 0x0000000000000000
                    - r14 = 0x0000000000000000
                    - ...
                    - rip = 0x00000000004012ab (user RIP)
                    - rsp = 0x00007ffd1234abcd (user RSP)
0xffffc90000123d00  [stack frames: schedule() called from here]
...
0xffffc90000123f50  inactive_task_frame ← task->thread.sp
                    - r15 = 0xffff888012345678
                    - r14 = 0xffff888056789abc
                    - r13 = 0x0000000000000000
                    - r12 = 0xffff888012340000
                    - rbx = 0xffff888100000000
                    - rbp = 0xffffc90000123f80
                    - ret_addr = 0xffffffff81234567 (__schedule+0x123)
0xffffc90000120000  (bottom of stack)
```

When this task is scheduled back in:
1. `__switch_to_asm()` loads RSP = 0xffffc90000123f50
2. Pops R15-RBP from inactive_task_frame
3. Returns to `ret_addr` (0xffffffff81234567)
4. Continues execution in `__schedule()`
5. Eventually returns through call chain
6. Restores `pt_regs` and returns to user mode

## Debugging context switches on AMD64

### Using ftrace

Enable context switch tracing:

```bash
cd /sys/kernel/debug/tracing
echo 1 > events/sched/sched_switch/enable
cat trace
```

Output:
```
# tracer: nop
#
#           TASK-PID   CPU#  TIMESTAMP  FUNCTION
#              | |       |       |         |
     kworker/0:1-12    [000] 1234.567890: sched_switch: prev_comm=kworker/0:1 prev_pid=12 prev_prio=120 prev_state=S ==> next_comm=bash next_pid=1234 next_prio=120
            bash-1234  [000] 1234.578901: sched_switch: prev_comm=bash prev_pid=1234 prev_prio=120 prev_state=R ==> next_comm=migration/0 next_pid=10 next_prio=0
```

Shows exactly which task switched to which, with timestamps.

### Reading /proc/[pid]/status

```bash
$ cat /proc/1234/status | grep ctxt
voluntary_ctxt_switches:	12847
nonvoluntary_ctxt_switches:	432
```

High nonvoluntary count indicates the task is being preempted frequently (CPU contention).

### Using perf

Record context switches:

```bash
perf record -e sched:sched_switch -a sleep 10
perf script
```

Measure context switch latency:

```bash
perf stat -e context-switches,cpu-cycles,instructions ./workload
```

### Stack unwinding across context switches

When debugging with `gdb` or reading kernel crash dumps, understanding stack layout lets
you trace execution across switches:

```
(gdb) info threads
  Id   Target Id         Frame 
  1    Thread 1234       0xffffffff81234567 in schedule () at kernel/sched/core.c:3456
  
(gdb) bt
#0  0xffffffff81234567 in schedule () at kernel/sched/core.c:3456
#1  0xffffffff81345678 in schedule_timeout () at kernel/time/timer.c:1234
#2  0xffffffff81456789 in wait_for_completion () at kernel/sched/completion.c:89
#3  0xffffffff81567890 in flush_work () at kernel/workqueue.c:2345

(gdb) x/16gx $rsp
0xffffc90000123f50: 0xffff888012345678  0xffff888056789abc  ← saved R15, R14
0xffffc90000123f60: 0x0000000000000000  0xffff888012340000  ← saved R13, R12
0xffffc90000123f70: 0xffff888100000000  0xffffc90000123f80  ← saved RBX, RBP
0xffffc90000123f80: 0xffffffff81234567                      ← return address
```

### Understanding register dumps

When kernel panics, register dumps show state at panic time:

```
RIP: 0010:some_function+0x42/0x100
RSP: 0018:ffffc90000123f80 EFLAGS: 00010246
RAX: 0000000000000000 RBX: ffff888012340000 RCX: 0000000000000001
RDX: 0000000000000002 RSI: 0000000000000003 RDI: 0000000000000004
RBP: ffffc90000123fa0 R08: 0000000000000005 R09: 0000000000000006
R10: 0000000000000007 R11: 0000000000000008 R12: ffff888056780000
R13: 0000000000000000 R14: ffff888012345678 R15: ffff888098765432
```

- RSP points to current stack location
- RBX, RBP, R12-R15 are preserved across calls (likely meaningful)
- RAX-R11 are scratch registers (may be garbage)

## Relationship to interrupts and syscalls

Context switches don't happen in isolation—they're deeply integrated with interrupt and
system call handling.

### Context switch after timer interrupt

The timer interrupt can trigger a context switch via the return path (see
[Linux Interrupt Handling](linux_interrupts.md) for full details):

```
Timer IRQ → scheduler_tick() sets TIF_NEED_RESCHED → irq_exit() checks flag
→ schedule() → context_switch() → switch_mm() + switch_to() → Resume new task
```

Key point: The context switch doesn't happen *during* the interrupt handler, but in the
return path after the handler completes.

### Context switch after syscall

The syscall return path can trigger a context switch (see [syscalls.md](syscalls.md)
for full details):

```
syscall entry → sys_*() handler → syscall_return_slowpath checks TIF_NEED_RESCHED
→ schedule() → context_switch() → switch_mm() + switch_to()
→ Resume new task (eventually returns to *its* user mode)
```

Again, the context switch happens in the return path, not during the syscall itself.

### Example flow: task blocks in syscall

```c
/* User calls read() */
syscall  /* Enter kernel */
  ↓
sys_read()
  ↓
vfs_read()
  ↓
/* File not ready, must wait */
wait_event_interruptible(...)
  ↓
prepare_to_wait()  /* Sets task state to TASK_INTERRUPTIBLE */
  ↓
schedule()  ← Explicit call, voluntary context switch
  ↓
__schedule()
  ↓
context_switch(prev=current_task, next=picked_task)
  ↓
switch_mm_irqs_off(): Load next's CR3
  ↓
switch_to(): Switch RSP, FS.base, FPU state
  ↓
/* Now executing on next task's stack */
/* Eventually next task returns to user mode via sysret */
```

The blocking task set its state to `TASK_INTERRUPTIBLE` before calling `schedule()`,
so `__schedule()` dequeued it from the runqueue. It will remain blocked until something
wakes it up (e.g., data becomes available).

## Code references (Linux source tree)

Key files for understanding AMD64 context switching:

### Core scheduler code

- **kernel/sched/core.c**
  - `schedule()`: Main entry point
  - `__schedule()`: Core scheduler logic
  - `context_switch()`: Orchestrates mm and register switching
  - `pick_next_task()`: Selects next task from scheduling classes

### x86-64 specific code

- **arch/x86/kernel/process_64.c**
  - `__switch_to()`: High-level register switching (FS base, FPU)
  - Task creation/destruction helpers

- **arch/x86/entry/entry_64.S**
  - `__switch_to_asm()`: Low-level register save/restore in assembly
  - `entry_SYSCALL_64`: Syscall entry with TIF_NEED_RESCHED checks
  - `ret_from_intr`: Interrupt return with scheduling checks

- **arch/x86/mm/tlb.c**
  - `switch_mm_irqs_off()`: Memory context switching
  - `load_new_mm_cr3()`: CR3 loading logic
  - PCID management (ASID allocation, invalidation)
  - TLB shootdown IPI handlers

- **arch/x86/kernel/fpu/core.c**
  - `switch_fpu_prepare()`: Save outgoing task's FPU state
  - `switch_fpu_finish()`: Restore incoming task's FPU state
  - XSAVE/XRSTOR wrappers

- **arch/x86/include/asm/switch_to.h**
  - `switch_to()` macro definition
  - Per-architecture hooks

- **arch/x86/include/asm/tlbflush.h**
  - CR3 manipulation helpers
  - TLB flush interfaces
  - PCID bit definitions

### Useful for reference

- **Intel® 64 and IA-32 Architectures Software Developer's Manual**
  - Volume 3A: System Programming Guide, Part 1
  - Chapter 4: Paging
  - Chapter 13: System Programming for Instruction Set Extensions (XSAVE)

- **AMD64 Architecture Programmer's Manual**
  - Volume 2: System Programming
  - Chapter 5: Page Translation and Protection

### Tracing and debugging

```bash
# Enable all scheduler tracepoints
cd /sys/kernel/debug/tracing
echo 1 > events/sched/enable

# Trace context switches
echo 1 > events/sched/sched_switch/enable
cat trace_pipe

# Measure switch latency with perf
perf stat -e context-switches,cpu-cycles ./workload

# Record stack traces at context switches
perf record -e sched:sched_switch -g -a sleep 10
perf report
```
