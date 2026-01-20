# Scheduler

## Overview

The Linux kernel scheduler is responsible for deciding which process runs on which CPU and for how long. The scheduler is designed with a modular architecture that allows multiple scheduling policies (or "scheduling classes") to coexist. This chapter explains how the scheduler works, starting with the fundamental API that any scheduling class must implement.

## Scheduler API: The `sched_class` Interface

The Linux scheduler uses a plugin-like architecture where different scheduling policies are implemented as separate "scheduling classes." Each scheduling class implements a common interface defined by `struct sched_class`.

### The `sched_class` Structure

The core scheduler interface is defined in `kernel/sched/sched.h`:

```c
struct sched_class {
    /* Hierarchy of scheduling classes */
    const struct sched_class *next;
    
    /* Core scheduling operations */
    void (*enqueue_task)(struct rq *rq, struct task_struct *p, int flags);
    void (*dequeue_task)(struct rq *rq, struct task_struct *p, int flags);
    void (*yield_task)(struct rq *rq);
    
    /* Task selection */
    struct task_struct *(*pick_next_task)(struct rq *rq);
    void (*put_prev_task)(struct rq *rq, struct task_struct *p);
    void (*set_next_task)(struct rq *rq, struct task_struct *p, bool first);
    
    /* Load balancing */
    int (*balance)(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
    int (*select_task_rq)(struct task_struct *p, int task_cpu, int flags);
    void (*migrate_task_rq)(struct task_struct *p, int new_cpu);
    
    /* Task state changes */
    void (*task_woken)(struct rq *rq, struct task_struct *p);
    void (*switched_from)(struct rq *rq, struct task_struct *p);
    void (*switched_to)(struct rq *rq, struct task_struct *p);
    void (*prio_changed)(struct rq *rq, struct task_struct *p, int oldprio);
    
    /* Preemption */
    void (*check_preempt_curr)(struct rq *rq, struct task_struct *p, int flags);
    
    /* Tick and time accounting */
    void (*task_tick)(struct rq *rq, struct task_struct *p, int queued);
    void (*task_fork)(struct task_struct *p);
    void (*task_dead)(struct task_struct *p);
    
    /* Policy operations */
    void (*update_curr)(struct rq *rq);
};
```

This structure is the contract that every scheduling class must implement.
As can be seen from the structure, the scheduler classes are organized into
a linked list structure:

```
                        GLOBAL SCHEDULER CLASS CHAIN
                        (linked list in priority order)
                        
    sched_class_highest ───-───┐
                               │
                               ▼
                    ┌─────────────────────────┐
                    │   stop_sched_class      │  Priority 1 (Highest)
                    │   .next ──────────┐     │
                    │   .enqueue_task   │     │  For critical per-CPU tasks
                    │   .pick_next_task │     │
                    │   .task_tick      │     │
                    │   ...             │     │
                    └───────────────────┼─────┘
                                        │
                                        ▼
                    ┌─────────────────────────┐
                    │   dl_sched_class        │  Priority 2
                    │   .next ──────────┐     │
                    │   .enqueue_task   │     │  SCHED_DEADLINE
                    │   .pick_next_task │     │  (if CONFIG_SCHED_DEADLINE)
                    │   .task_tick      │     │  (deadline scheduling)
                    │   ...             │     │
                    └───────────────────┼─────┘
                                        │
                                        ▼
                    ┌─────────────────────────┐
                    │   rt_sched_class        │  Priority 3
                    │   .next ──────────┐     │
                    │   .enqueue_task   │     │  SCHED_FIFO, SCHED_RR
                    │   .pick_next_task │     │  (if CONFIG_RT_SCHED)
                    │   .task_tick      │     │  (real-time priorities 1-99)
                    │   ...             │     │
                    └───────────────────┼─────┘
                                        │
                                        ▼
                    ┌─────────────────────────┐
                    │   fair_sched_class      │  Priority 4
                    │   .next ──────────┐     │
                    │   .enqueue_task   │     │  SCHED_NORMAL, SCHED_BATCH
                    │   .pick_next_task │     │  (CFS: Completely Fair Scheduler)
                    │   .task_tick      │     │
                    │   ...             │     │
                    └───────────────────┼─────┘
                                        │
                                        ▼
                    ┌─────────────────────────┐
                    │   ext_sched_class       │  Priority 5
                    │   .next ──────────┐     │
                    │   .enqueue_task   │     │  SCHED_EXT (if CONFIG_SCHED_CLASS_EXT)
                    │   .pick_next_task │     │  BPF-programmable scheduler
                    │   .task_tick      │     │
                    │   ...             │     │
                    └───────────────────┼─────┘
                                        │
                                        ▼
                    ┌─────────────────────────┐
                    │   idle_sched_class      │  Priority 6 (Lowest)
                    │   .next = NULL          │
                    │   .enqueue_task         │  The idle thread
                    │   .pick_next_task       │  (runs when nothing else can)
                    │   .task_tick            │
                    │   ...                   │
                    └─────────────────────────┘
```

The set of scheduler classes is hard coded at compile time. Each `struct sched_class`
is a global object in the kernel image and the .next pointers are set via static
initializers.

### Per-CPU Runqueue Structure

Each CPU has its own runqueue (`struct rq`) that contains separate sub-runqueues for each scheduling class:

```
                        CPU 0                               CPU 1
                    
            ┌──────────────────────┐               ┌──────────────────────┐
            │   struct rq          │               │   struct rq          │
            ├──────────────────────┤               ├──────────────────────┤
            │  curr (current task) │               │  curr (current task) │
            │  idle (idle thread)  │               │  idle (idle thread)  │
            │  nr_running = 5      │               │  nr_running = 3      │
            ├──────────────────────┤               ├──────────────────────┤
            │                      │               │                      │
            │  ┌────────────────┐  │               │  ┌────────────────┐  │
            │  │  stop          │  │               │  │  stop          │  │
            │  │  (empty)       │  │               │  │  (empty)       │  │
            │  └────────────────┘  │               │  └────────────────┘  │
            │                      │               │                      │
            │  ┌────────────────┐  │               │  ┌────────────────┐  │
            │  │  dl            │  │               │  │  dl            │  │
            │  │  nr_running: 0 │  │               │  │  nr_running: 1 │  │
            │  │  (empty)       │  │               │  │  [task_A]      │  │
            │  └────────────────┘  │               │  └────────────────┘  │
            │                      │               │                      │
            │  ┌────────────────┐  │               │  ┌────────────────┐  │
            │  │  rt            │  │               │  │  rt            │  │
            │  │  nr_running: 1 │  │               │  │  nr_running: 0 │  │
            │  │  [task_B]      │  │               │  │  (empty)       │  │
            │  └────────────────┘  │               │  └────────────────┘  │
            │                      │               │                      │
            │  ┌────────────────┐  │               │  ┌────────────────┐  │
            │  │  cfs           │  │               │  │  cfs           │  │
            │  │  nr_running: 4 │  │               │  │  nr_running: 2 │  │
            │  │  RB-Tree:      │  │               │  │  RB-Tree:      │  │
            │  │   ├─[task_C]   │  │               │  │   ├─[task_X]   │  │
            │  │   ├─[task_D]   │  │               │  │   └─[task_Y]   │  │
            │  │   ├─[task_E]   │  │               │  └────────────────┘  │
            │  │   └─[task_F]   │  │               │                      │
            │  └────────────────┘  │               │  ┌────────────────┐  │
            │                      │               │  │  idle          │  │
            │  ┌────────────────┐  │               │  │  [swapper/1]   │  │
            │  │  idle          │  │               │  └────────────────┘  │
            │  │  [swapper/0]   │  │               │                      │
            │  └────────────────┘  │               └──────────────────────┘
            │                      │
            └──────────────────────┘
```

### Task Selection Flow

When the scheduler needs to pick the next task to run, it walks the class chain:

```
    schedule() called
         │
         ▼
    ┌─────────────────────────────────────────────────────┐
    │  for_each_class(class)                              │
    │    p = class->pick_next_task(rq)                    │
    │    if (p) return p                                  │
    └─────────────────────────────────────────────────────┘
         │
         ├─────────────────────────────────┐
         │                                 │
         ▼                                 │
    ┌──────────────────────┐               │
    │ stop_sched_class     │               │
    │ pick_next_task()     │               │
    │   → NULL (empty)     │               │
    └──────────────────────┘               │
         │                                 │
         ▼                                 │
    ┌──────────────────────┐               │
    │ dl_sched_class       │               │
    │ pick_next_task()     │               │
    │   → NULL (empty)     │               │
    └──────────────────────┘               │
         │                                 │
         ▼                                 │
    ┌──────────────────────┐               │
    │ rt_sched_class       │               │
    │ pick_next_task()     │               │
    │   → task_B ────────────────────────────┐
    └──────────────────────┘               │ │
                                           │ │
    (Fair and Idle classes are skipped)    │ │
                                           │ │
                                           ▼ ▼
                                      task_B runs!
```

The first scheduling class that returns a non-NULL task wins. This ensures higher-priority classes always preempt lower-priority ones.

### Core Operations

We next discuss the functions in the `struct sched_class` that every scheduler class
must implement.

#### 1. `enqueue_task()` - Adding a Task to the Runqueue

```c
void enqueue_task(struct rq *rq, struct task_struct *p, int flags);
```

**Purpose**: Add a task to the runqueue, making it eligible to run.

**When called**:
- Task becomes runnable (e.g., wakes up from sleep)
- Task is moved to this CPU
- Task's scheduling class changes to this one

#### 2. `dequeue_task()` - Removing a Task from the Runqueue

```c
void dequeue_task(struct rq *rq, struct task_struct *p, int flags);
```

**Purpose**: Remove a task from the runqueue, making it ineligible to run.

**When called**:
- Task goes to sleep (waiting for I/O, lock, etc.)
- Task is migrated to another CPU
- Task's scheduling class changes
- Task exits

#### 3. `pick_next_task()` - Selecting the Next Task to Run

```c
struct task_struct *pick_next_task(struct rq *rq);
```

**Purpose**: Select the next task that should run on this CPU.

**When called**:
- During context switch (`schedule()`)
- After current task blocks or yields
- After interrupt when returning to kernel

#### 4. `put_prev_task()` - Handling the Previously Running Task

```c
void put_prev_task(struct rq *rq, struct task_struct *p);
```

**Purpose**: Handle bookkeeping when a task stops running.

**When called**:
- Before `pick_next_task()` selects a new task
- Task is being preempted or yielding

#### 5. `check_preempt_curr()` - Checking if Preemption is Needed

```c
void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags);
```

**Purpose**: Determine if a newly runnable task should preempt the currently running task.

**When called**:
- After `enqueue_task()` adds a new task
- After task priority changes
- After task wakes up

#### 6. `task_tick()` - Periodic Timer Tick

```c
void task_tick(struct rq *rq, struct task_struct *p, int queued);
```

**Purpose**: Called on every scheduler tick (typically every 1-10ms) for the currently running task.

**When called**:
- From `scheduler_tick()` in the timer interrupt handler

#### 7. `select_task_rq()` - Choosing a CPU for a Task

```c
int select_task_rq(struct task_struct *p, int task_cpu, int flags);
```

**Purpose**: Select which CPU a task should run on.

**When called**:
- Task is waking up (`SD_BALANCE_WAKE`)
- Task is being forked (`SD_BALANCE_FORK`)
- Task is being executed (`SD_BALANCE_EXEC`)

#### 8. `balance()` - Load Balancing Across CPUs

```c
int balance(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
```

**Purpose**: Balance load across CPUs in the system.

**When called**:
- Periodically during scheduling decisions
- When a CPU becomes idle

## When is the Scheduler Invoked?

Understanding when and how the kernel invokes the scheduler is critical to understanding Linux scheduling. There are two main concepts: the **scheduler tick** (periodic bookkeeping) and **task selection** (actual context switches).

### The Scheduler Tick

The **scheduler tick** is a periodic interrupt that occurs at a fixed frequency (typically 100-1000 Hz, configurable via `CONFIG_HZ`). On each tick, the kernel performs accounting and checks if scheduling decisions need to be made.

#### Tick Frequency

Common configurations:
- **100 Hz**: Tick every 10ms (servers, lower overhead)
- **250 Hz**: Tick every 4ms (balanced)
- **1000 Hz**: Tick every 1ms (desktops, low latency)

#### The Tick Call Chain

When a timer interrupt fires, the following happens:

```
Hardware Timer Interrupt
         │
         ▼
    do_IRQ() / handle_irq()
         │
         ▼
    tick_periodic() or tick_sched_timer()
         │
         ├─── update_process_times()
         │         │
         │         ├─── account_process_tick()  (account CPU time)
         │         │
         │         └─── scheduler_tick()  ◄───── SCHEDULER TICK ENTRY
         │                   │
         │                   ├─── update_rq_clock()  (update runqueue clock)
         │                   │
         │                   ├─── curr->sched_class->task_tick()  (class-specific tick)
         │                   │         │
         │                   │         ├─── task_tick_fair() (for CFS)
         │                   │         ├─── task_tick_rt() (for RT)
         │                   │         ├─── task_tick_dl() (for deadline)
         │                   │         └─── task_tick_ext() (for sched_ext)
         │                   │
         │                   └─── trigger_load_balance()  (periodic load balancing)
         │
         └─── run_local_timers()
```

#### What the Scheduler Tick Does

The `scheduler_tick()` function (in `kernel/sched/core.c`) performs these tasks:

```c
void scheduler_tick(void)
{
    int cpu = smp_processor_id();
    struct rq *rq = cpu_rq(cpu);
    struct task_struct *curr = rq->curr;
    
    /* Update the runqueue clock */
    update_rq_clock(rq);
    
    /* Call the scheduling class's tick handler */
    curr->sched_class->task_tick(rq, curr, 0);
    
    /* Update CPU load statistics */
    cpu_load_update_active(rq);
    
    /* Trigger load balancing if needed */
    trigger_load_balance(rq);
    
    /* Update thermal pressure, capacity, etc. */
    update_thermal_load_avg(rq_clock_thermal(rq), rq, thermal_pressure);
}
```

**Important**: The scheduler tick does NOT directly cause a context switch. It only:
1. Updates accounting (CPU time used, vruntime, etc.)
2. Checks if the current task should be preempted
3. Sets the `TIF_NEED_RESCHED` flag if preemption is needed

#### Per-Class Tick Handling

Each scheduling class implements its own `task_tick()` function:

**CFS (Completely Fair Scheduler)**:
```c
static void task_tick_fair(struct rq *rq, struct task_struct *curr, int queued)
{
    struct cfs_rq *cfs_rq;
    struct sched_entity *se = &curr->se;
    
    /* Update runtime statistics */
    update_curr(cfs_rq);  // Updates vruntime
    
    /* Check if task should be preempted */
    if (cfs_rq->nr_running > 1)
        check_preempt_tick(cfs_rq, curr);
}
```

**Real-Time Scheduler**:
```c
static void task_tick_rt(struct rq *rq, struct task_struct *p, int queued)
{
    struct sched_rt_entity *rt_se = &p->rt;
    
    update_curr_rt(rq);  // Update runtime
    
    /* For SCHED_RR: decrement timeslice */
    if (p->policy == SCHED_RR) {
        if (--p->rt.time_slice == 0) {
            p->rt.time_slice = sched_rr_timeslice;
            /* Move to end of priority queue */
            requeue_task_rt(rq, p, 0);
            resched_curr(rq);  // Set TIF_NEED_RESCHED
        }
    }
}
```

###  Choosing a New Task

The actual task selection happens when `schedule()` is called. This is separate from the scheduler tick. Here are the situations when `schedule()` is invoked:

#### 1. Explicit Calls to `schedule()`

When a task voluntarily gives up the CPU:

```c
/* Task is waiting for something */
void some_kernel_function(void)
{
    set_current_state(TASK_INTERRUPTIBLE);
    schedule();  // Explicit call - task is blocking
}
```

**Common scenarios**:
- Waiting for I/O: `wait_event()`, `msleep()`
- Waiting for locks: `mutex_lock()`, `down()`
- Yielding CPU: `sched_yield()`
- Exiting: `do_exit()`

#### 2. Returning from Interrupt or Exception

After handling an interrupt or exception, the kernel checks if rescheduling is needed:

```
Hardware Interrupt
         │
         ▼
    IRQ Handler
         │
         ▼
    irq_exit()
         │
         ├─── preempt_count_sub(HARDIRQ_OFFSET)
         │
         └─── if (!in_interrupt() && need_resched())
                   invoke_softirq()  // May trigger reschedule
         
         
    Return path to user/kernel
         │
         ▼
    if (need_resched())
         schedule()  ◄───── ACTUAL TASK SWITCH HAPPENS HERE
```

#### 3. Returning from System Call

When returning to user space from a system call:

```
User Space
    │
    │ syscall instruction
    ▼
entry_SYSCALL_64
    │
    ▼
System Call Handler (e.g., sys_read)
    │
    ▼
syscall_return
    │
    ├─── Check TIF_NEED_RESCHED flag
    │
    └─── if (need_resched())
              schedule()  ◄───── RESCHEDULE BEFORE RETURNING TO USER
    │
    ▼ sysret
User Space
```

#### 4. Preemption Points in Kernel

In preemptible kernels (`CONFIG_PREEMPT=y`), the kernel can be preempted at many points:

```c
/* Example: Preemption after releasing a spinlock */
spin_unlock(&some_lock)
    │
    ├─── raw_spin_unlock()
    │
    └─── preempt_enable()
              │
              └─── if (need_resched() && preemptible())
                        preempt_schedule()
                             │
                             └─── schedule()  ◄───── PREEMPTION
```

#### 5. Wake-up Path

When a task is woken up, it may immediately preempt the current task:

```c
wake_up_process(task)
    │
    ├─── try_to_wake_up(task)
    │         │
    │         ├─── select_task_rq()  (choose CPU)
    │         │
    │         ├─── enqueue_task()  (add to runqueue)
    │         │
    │         └─── check_preempt_curr()  ◄── Check if should preempt
    │                   │
    │                   └─── if (should_preempt)
    │                             resched_curr()  // Sets TIF_NEED_RESCHED
    │
    └─── (at next preemption point or return to user)
              schedule()  ◄───── ACTUAL SWITCH
```

### The `TIF_NEED_RESCHED` Flag

The bridge between "we need to reschedule" and "we actually reschedule" is the `TIF_NEED_RESCHED` thread flag.

**Setting the flag**:
```c
static inline void resched_curr(struct rq *rq)
{
    set_tsk_need_resched(rq->curr);  // Set TIF_NEED_RESCHED
    set_preempt_need_resched();       // Preempt count check
}
```

**Checking the flag**:
```c
/* In various return paths */
if (need_resched()) {
    schedule();
}
```

**Where it's checked**:
1. Return to user space (from syscall/interrupt/exception)
2. After releasing locks (if `CONFIG_PREEMPT=y`)
3. Explicit `cond_resched()` calls in kernel
4. After re-enabling preemption

### The `schedule()` Function

When `schedule()` is finally called, it performs the actual task selection:

```c
/* Simplified from kernel/sched/core.c */
asmlinkage __visible void __sched schedule(void)
{
    struct task_struct *prev, *next;
    struct rq *rq;
    
    /* Get current CPU's runqueue */
    rq = cpu_rq(smp_processor_id());
    prev = rq->curr;
    
    /* Clear the need_resched flag */
    clear_tsk_need_resched(prev);
    
    /* Handle the previously running task */
    if (prev->state != TASK_RUNNING) {
        /* Task is blocking - dequeue it */
        dequeue_task(rq, prev, DEQUEUE_SLEEP);
    } else {
        /* Task is still runnable - put back in queue */
        put_prev_task(rq, prev);
    }
    
    /* Pick the next task to run */
    next = pick_next_task(rq);
    
    /* If same task, no context switch needed */
    if (prev == next) {
        return;
    }
    
    /* Perform context switch */
    context_switch(rq, prev, next);
}
```

### Complete Flow Example

Let's trace a complete example: A task exhausts its timeslice and is preempted.

```
Time: 0ms - Task A is running
    │
Time: 4ms - Timer interrupt fires (250 Hz tick)
    │
    ├─── Timer IRQ Handler
    │        │
    │        └─── scheduler_tick()
    │               │
    │               └─── task_tick_fair()
    │                     │
    │                     ├─── update_curr()  (A's vruntime++)
    │                     │
    │                     └─── check_preempt_tick()
    │                           │
    │                           └─── if (A ran too long && B has lower vruntime)
    │                                     resched_curr()  // Set TIF_NEED_RESCHED
    │
    └─── Return from IRQ
           │
           └─── irq_exit()
                   │
                   └─── Check: need_resched() == true
                            │
                            └─── schedule()  ◄─── CONTEXT SWITCH HAPPENS
                                    │
                                    ├─── put_prev_task(A)  (A back in runqueue)
                                    │
                                    ├─── pick_next_task()  (selects Task B)
                                    │
                                    └─── context_switch(A → B)
                                            │
                                            ├─── switch_mm()  (change page tables)
                                            │
                                            └─── switch_to()  (switch registers/stack)
                                                     │
Task B is now running ◄──────────────────────────────┘
```

### Key Takeaways

1. **Scheduler tick ≠ context switch**: The tick updates accounting and may set `TIF_NEED_RESCHED`, but doesn't directly switch tasks
2. **Lazy rescheduling**: The flag is set during the tick, but the actual `schedule()` call happens later at a safe point
3. **Multiple trigger points**: Scheduling can be triggered by timer ticks, blocking, returning from interrupts, preemption points
4. **Per-class logic**: Each scheduling class decides independently if preemption is needed during its `task_tick()` call
5. **Safety**: Context switches only happen at well-defined points where the kernel state is consistent

### Tickless Kernels (NO_HZ)

Modern kernels support **tickless** mode (`CONFIG_NO_HZ_FULL`), where timer ticks can be disabled when:
- Only one runnable task on a CPU
- CPU is idle

In this mode:
- The scheduler tick is skipped entirely
- Scheduling still happens via other triggers (wakeups, preemption, syscall returns)
- Saves power and reduces overhead
- Critical for real-time and HPC workloads

```c
/* When entering idle or single-task mode */
tick_nohz_idle_enter()
    │
    └─── Stop timer tick (no more scheduler_tick() calls)

/* Task switch or wakeup re-enables the tick if needed */
tick_nohz_idle_exit()
    │
    └─── Restart timer tick
```

This tickless design shows that the scheduler fundamentally operates on events (task wakeup, task blocking, explicit reschedule) rather than relying solely on periodic timer interrupts.


## The Task Struct

Functions in the scheduler are often called through the current task, which is
available as `struct task_struct *p = current`, where `current` is a per-CPU
variale in the kernel. The task struct contains pointers to various objects in
the scheduler:

```
    task_struct (the process)
         │
         ├─→ policy (scheduling policy: SCHED_NORMAL, SCHED_FIFO, SCHED_EXT, etc.)
         │
         ├─→ sched_class* (points to its scheduling class)
         │         │
         │         └──→ &fair_sched_class (for SCHED_NORMAL, SCHED_BATCH)
         │              or &rt_sched_class (for SCHED_FIFO, SCHED_RR)
         │              or &dl_sched_class (for SCHED_DEADLINE)
         │              or &ext_sched_class (for SCHED_EXT)
         │              or &idle_sched_class (for idle thread)
         │
         ├─→ sched_entity (for CFS tasks)
         │      │
         │      ├─→ vruntime (virtual runtime)
         │      ├─→ on_rq (is task on runqueue?)
         │      └─→ load_weight (task weight/priority)
         │
         ├─→ sched_rt_entity (for RT tasks)
         │      │
         │      ├─→ prio (RT priority 0-99)
         │      └─→ time_slice (remaining timeslice)
         │
         ├─→ sched_dl_entity (for deadline tasks)
         │      │
         │      ├─→ deadline
         │      ├─→ runtime
         │      └─→ period
         │
         ├─→ sched_ext_entity (for sched_ext tasks, if CONFIG_SCHED_CLASS_EXT)
         │      │
         │      ├─→ dsq_node (dispatch queue linkage)
         │      ├─→ slice (time slice from BPF scheduler)
         │      ├─→ sticky_cpu (CPU affinity hint)
         │      ├─→ ops_state (BPF program's private flags)
         │      ├─→ dsq (which dispatch queue task is on)
         │      └─→ task_ctx (per-task data allocated by BPF)
         │
         └─→ on_rq (which rq is task on?)
                │
                └──→ struct rq (the per-CPU runqueue)
                       │
                       ├─→ cfs (CFS sub-runqueue)
                       ├─→ rt (RT sub-runqueue)
                       ├─→ dl (Deadline sub-runqueue)
                       ├─→ scx (sched_ext sub-runqueue, if enabled)
                       └─→ curr (currently running task)
```

Each task contains scheduling entities for ALL classes (se, rt, dl, scx), but only
the entity corresponding to the task's current `sched_class` pointer is actively used.
When a task switches scheduling classes (e.g., via `sched_setscheduler()`), the kernel:

1. Dequeues from the old class (using the old entity)
1. Updates the `sched_class` pointer
1. Enqueues to the new class (using the new entity)

## Scheduler Performance

The scheduler walks the `sched_class` chain only when it needs to select a new task.
This happens when a task blocks or yields, preemption is required or a higher priority
task becomes runnable. This does not happen on every timer tick or syscall if the
current task continues running and a new task does not need to be selected.

There are only ~4-6 scheduler classes and the list is usually cache-hot. Walking it is
therefore every fast. The dominant cost is typically within the `pick_next_task()`
functions of each scheduler class. These should be optimized to run very quickly in the
case where the scheduler class has nothing runnable.

## Implementing a Custom Scheduler

To implement a custom scheduling policy, you would:

1. **Define your `sched_class` structure**:
```c
const struct sched_class my_sched_class = {
    .next = &fair_sched_class,  /* Insert in priority chain */
    
    .enqueue_task = enqueue_task_my,
    .dequeue_task = dequeue_task_my,
    .pick_next_task = pick_next_task_my,
    .put_prev_task = put_prev_task_my,
    .check_preempt_curr = check_preempt_curr_my,
    .task_tick = task_tick_my,
    .select_task_rq = select_task_rq_my,
    /* ... implement other required functions ... */
};
```

2. **Implement your runqueue data structure** (typically in your own `struct my_rq`):
```c
struct my_rq {
    struct my_task_list tasks;  /* Your task organization */
    unsigned int nr_running;     /* Number of tasks */
    u64 exec_clock;             /* Runtime accounting */
    /* ... your scheduling state ... */
};
```

3. **Add your runqueue to `struct rq`** (the per-CPU runqueue):
```c
/* In kernel/sched/sched.h */
struct rq {
    /* ... existing fields ... */
    struct my_rq my;  /* Your runqueue */
};
```

4. **Register your scheduling class in the priority chain**:

The scheduler classes are linked together at compile time through static initialization:

```c
/* In kernel/sched/my_sched.c */
DEFINE_SCHED_CLASS(my) = {
    .enqueue_task = enqueue_task_my,
    .dequeue_task = dequeue_task_my,
    /* ... other operations ... */
};
```

Then update the build configuration to specify the priority order:

```makefile
# In kernel/sched/Makefile or similar
# The order here determines the priority chain
SCHED_CLASSES = stop dl rt my fair idle
```

The build system will automatically generate the `.next` pointers based on this ordering.
This is managed by special linker scripts or initialization code.

The highest-priority class must be marked as the chain head:

```c
/* In kernel/sched/sched.h */
#define sched_class_highest (&stop_sched_class)
```

If you're adding a class with higher priority than `stop_sched_class`, you'd need to update this definition.

5. **Add a new scheduling policy** (e.g., `SCHED_MY_POLICY`) that maps to your class.

You need to:

a. Add the policy constant:
```c
/* In include/uapi/linux/sched.h */
#define SCHED_NORMAL    0
#define SCHED_FIFO      1
#define SCHED_RR        2
#define SCHED_BATCH     3
#define SCHED_IDLE      5
#define SCHED_DEADLINE  6
#define SCHED_MY_POLICY 7  /* Your new policy */
```

b. Map the policy to your class:
```c
/* In kernel/sched/core.c */
static const struct sched_class *sched_class_map[8] = {
    [SCHED_NORMAL]     = &fair_sched_class,
    [SCHED_FIFO]       = &rt_sched_class,
    [SCHED_RR]         = &rt_sched_class,
    [SCHED_BATCH]      = &fair_sched_class,
    [SCHED_IDLE]       = &idle_sched_class,
    [SCHED_DEADLINE]   = &dl_sched_class,
    [SCHED_MY_POLICY]  = &my_sched_class,  /* Add this */
};

static inline const struct sched_class *policy_to_class(int policy)
{
    if (policy < 0 || policy >= ARRAY_SIZE(sched_class_map))
        return NULL;
    return sched_class_map[policy];
}
```

c. Allow the policy in `sched_setscheduler()`:
```c
/* In kernel/sched/core.c */
static int check_policy(int policy)
{
    if (policy != SCHED_NORMAL && policy != SCHED_FIFO &&
        policy != SCHED_RR && policy != SCHED_BATCH &&
        policy != SCHED_IDLE && policy != SCHED_DEADLINE &&
        policy != SCHED_MY_POLICY)  /* Add this */
        return -EINVAL;
    
    return 0;
}
```

**Using Your New Scheduler:**

Once registered, user-space programs can use it:

```c
#include <sched.h>

int main(void)
{
    struct sched_param param = {0};
    
    /* Set current process to use your scheduler */
    if (sched_setscheduler(0, SCHED_MY_POLICY, &param) != 0) {
        perror("sched_setscheduler");
        return 1;
    }
    
    /* Now running under my_sched_class */
    /* ... do work ... */
    
    return 0;
}
```

## Using `sched_ext` with BPF

The `sched_ext` (Extensible Scheduler) framework allows you to implement custom scheduling
policies using eBPF programs. This is approach allows scheduler development and deployment
without kernel recompilation or reboots.

### Overview

Unlike traditional scheduling classes that are compiled into the kernel, `sched_ext` schedulers:
- Are written in C (or Rust through Aya) and compiled to eBPF bytecode
- Can be loaded and unloaded at runtime
- Are verified by the BPF verifier for safety
- Can be updated without rebooting the system
- Have access to rich kernel data structures

### The BPF Scheduler Interface

A BPF scheduler implements callbacks defined in `struct sched_ext_ops`:

```c
/* From include/linux/sched/ext.h */
struct sched_ext_ops {
    /* Called when a task is enqueued (becomes runnable) */
    void (*enqueue)(struct task_struct *p, u64 enq_flags);
    
    /* Called when a task is dequeued (stops being runnable) */
    void (*dequeue)(struct task_struct *p, u64 deq_flags);
    
    /* Called to dispatch a task to a CPU */
    void (*dispatch)(s32 cpu, struct task_struct *prev);
    
    /* Called on every scheduler tick for running task */
    void (*running)(struct task_struct *p);
    
    /* Called when a task stops running */
    void (*stopping)(struct task_struct *p, bool runnable);
    
    /* Called to select CPU for a task */
    s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
    
    /* Called when task is forked */
    void (*task_fork)(struct task_struct *p);
    
    /* Called when task exits */
    void (*task_exit)(struct task_struct *p);
    
    /* Scheduler initialization */
    s32 (*init)(void);
    
    /* Scheduler cleanup */
    void (*exit)(struct sched_ext_info *info);
    
    /* Scheduler name (for identification) */
    const char name[SCX_OPS_NAME_LEN];
};
```

### Writing a Simple BPF Scheduler

Here's a minimal BPF scheduler that implements a simple FIFO (First-In-First-Out) policy:

```c
/* simple_fifo.bpf.c - A basic FIFO scheduler */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* Called when a task becomes runnable */
void BPF_STRUCT_OPS(simple_fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
    /*
     * Dispatch task to the global FIFO queue
     * SCX_DSQ_GLOBAL is a built-in dispatch queue
     */
    scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

/* Called to dispatch tasks to CPUs */
void BPF_STRUCT_OPS(simple_fifo_dispatch, s32 cpu, struct task_struct *prev)
{
    /*
     * Consume one task from the global queue and run it on this CPU
     * The scheduler core will call pick_next_task after this
     */
    scx_bpf_consume(SCX_DSQ_GLOBAL);
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS(simple_fifo_init)
{
    return 0;
}

/* Cleanup when scheduler is unloaded */
void BPF_STRUCT_OPS(simple_fifo_exit, struct scx_exit_info *info)
{
    bpf_printk("simple_fifo scheduler exiting: %s",
               info->msg);
}

/* Define the scheduler operations */
SEC(".struct_ops")
struct sched_ext_ops simple_fifo = {
    .enqueue        = (void *)simple_fifo_enqueue,
    .dispatch       = (void *)simple_fifo_dispatch,
    .init           = (void *)simple_fifo_init,
    .exit           = (void *)simple_fifo_exit,
    .name           = "simple_fifo",
};
```

### A More Complex Example: Priority-Based Scheduler

Here's a more sophisticated scheduler that uses task priorities:

```c
/* priority_sched.bpf.c - Priority-based scheduler with multiple queues */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* Define custom dispatch queues for different priority levels */
#define NUM_PRIO_LEVELS 3
#define DSQ_HIGH   0  /* High priority queue */
#define DSQ_NORMAL 1  /* Normal priority queue */
#define DSQ_LOW    2  /* Low priority queue */

/* Per-task context - stored in task->scx.task_ctx */
struct task_ctx {
    u64 last_run;      /* Last time task ran */
    u32 nice_value;    /* Cached nice value */
};

/* Statistics (stored in BPF maps) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, NUM_PRIO_LEVELS);
} queue_stats SEC(".maps");

/* Helper to get priority level from task */
static inline u32 task_prio_level(struct task_struct *p)
{
    /* Get the nice value (-20 to 19) */
    s32 nice = p->se.load.weight;  /* Simplified */
    
    if (nice < -10)
        return DSQ_HIGH;
    else if (nice < 10)
        return DSQ_NORMAL;
    else
        return DSQ_LOW;
}

/* Called when task becomes runnable */
void BPF_STRUCT_OPS(priority_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *tctx;
    u32 prio_level;
    u64 *count;
    
    /* Get per-task context */
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return;
    
    /* Determine priority level */
    prio_level = task_prio_level(p);
    
    /* Update statistics */
    count = bpf_map_lookup_elem(&queue_stats, &prio_level);
    if (count)
        __sync_fetch_and_add(count, 1);
    
    /* Dispatch to appropriate priority queue with time slice based on priority */
    u64 slice = SCX_SLICE_DFL;
    if (prio_level == DSQ_HIGH)
        slice = SCX_SLICE_DFL * 2;  /* High priority gets 2x time slice */
    else if (prio_level == DSQ_LOW)
        slice = SCX_SLICE_DFL / 2;  /* Low priority gets 0.5x time slice */
    
    scx_bpf_dispatch(p, prio_level, slice, enq_flags);
}

/* Select CPU for task - prefer CPU with least load */
s32 BPF_STRUCT_OPS(priority_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;
    
    /* Try to find an idle CPU */
    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, NULL);
    if (cpu >= 0)
        return cpu;
    
    /* No idle CPU, stick with previous */
    return prev_cpu;
}

/* Dispatch tasks to CPU - check queues in priority order */
void BPF_STRUCT_OPS(priority_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Try high priority queue first */
    if (scx_bpf_consume(DSQ_HIGH))
        return;
    
    /* Then normal priority */
    if (scx_bpf_consume(DSQ_NORMAL))
        return;
    
    /* Finally low priority */
    if (scx_bpf_consume(DSQ_LOW))
        return;
    
    /* No tasks available */
}

/* Called on every tick for running task */
void BPF_STRUCT_OPS(priority_running, struct task_struct *p)
{
    struct task_ctx *tctx;
    
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (tctx)
        tctx->last_run = bpf_ktime_get_ns();
}

/* Initialize scheduler */
s32 BPF_STRUCT_OPS(priority_init)
{
    /* Create custom dispatch queues */
    scx_bpf_create_dsq(DSQ_HIGH, -1);
    scx_bpf_create_dsq(DSQ_NORMAL, -1);
    scx_bpf_create_dsq(DSQ_LOW, -1);
    
    bpf_printk("Priority scheduler initialized with %d levels",
               NUM_PRIO_LEVELS);
    
    return 0;
}

void BPF_STRUCT_OPS(priority_exit, struct scx_exit_info *info)
{
    bpf_printk("Priority scheduler exiting");
}

SEC(".struct_ops")
struct sched_ext_ops priority_sched = {
    .enqueue        = (void *)priority_enqueue,
    .select_cpu     = (void *)priority_select_cpu,
    .dispatch       = (void *)priority_dispatch,
    .running        = (void *)priority_running,
    .init           = (void *)priority_init,
    .exit           = (void *)priority_exit,
    .name           = "priority_sched",
};
```

### Building a BPF Scheduler

**1. Set up the build environment:**

```bash
# Install required tools
sudo apt-get install clang llvm libbpf-dev

# Clone sched_ext utilities (contains headers and tools)
git clone https://github.com/sched-ext/scx.git
cd scx
```

**2. Create a Makefile:**

```makefile
# Makefile for BPF scheduler
CLANG := clang
LLC := llc
BPFTOOL := bpftool

BPF_CFLAGS := -target bpf -O2 -g -Wall
BPF_INCLUDES := -I/usr/include -I./include

simple_fifo: simple_fifo.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o simple_fifo.bpf.o
	$(BPFTOOL) gen skeleton simple_fifo.bpf.o > simple_fifo.skel.h

clean:
	rm -f *.o *.skel.h
```

**3. Compile the scheduler:**

```bash
make simple_fifo
```

### Loading and Managing a BPF Scheduler

**User-space loader program:**

```c
/* simple_fifo_loader.c - Load and attach the BPF scheduler */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "simple_fifo.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct simple_fifo_bpf *skel;
    struct bpf_link *link;
    int err;
    
    /* Set up signal handler for clean exit */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Open and load BPF program */
    skel = simple_fifo_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    /* Attach the scheduler */
    link = bpf_map__attach_struct_ops(skel->maps.simple_fifo);
    if (!link) {
        fprintf(stderr, "Failed to attach scheduler\n");
        err = -1;
        goto cleanup;
    }
    
    printf("Simple FIFO scheduler loaded and running\n");
    printf("Press Ctrl-C to exit\n");
    
    /* Keep running until signal */
    while (!exiting) {
        sleep(1);
        
        /* Could print statistics here */
        printf("Scheduler still running...\n");
    }
    
    printf("Detaching scheduler...\n");
    bpf_link__destroy(link);
    
cleanup:
    simple_fifo_bpf__destroy(skel);
    return err;
}
```

**Compile and run:**

```bash
# Compile loader
gcc -o simple_fifo_loader simple_fifo_loader.c \
    -lbpf -lelf -lz

# Load the scheduler (requires root/CAP_SYS_ADMIN)
sudo ./simple_fifo_loader
```

### Built-in Helper Functions

BPF schedulers have access to special helper functions:

```c
/* Dispatch a task to a dispatch queue */
void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id,
                      u64 slice, u64 enq_flags);

/* Consume a task from a dispatch queue */
bool scx_bpf_consume(u64 dsq_id);

/* Create a custom dispatch queue */
s32 scx_bpf_create_dsq(u64 dsq_id, s32 node);

/* Select CPU using default policy */
s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu,
                            u64 wake_flags, bool *found);

/* Test if a CPU is idle */
bool scx_bpf_test_and_clear_cpu_idle(s32 cpu);

/* Get task weight (priority) */
u32 scx_bpf_task_weight(struct task_struct *p);

/* Kick a CPU to reschedule */
void scx_bpf_kick_cpu(s32 cpu, u64 flags);
```

### Debugging BPF Schedulers

**1. Using bpf_printk():**

```c
void BPF_STRUCT_OPS(my_enqueue, struct task_struct *p, u64 enq_flags)
{
    bpf_printk("Enqueuing task PID=%d comm=%s",
               p->pid, p->comm);
    /* ... */
}
```

View output:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**2. BPF Maps for Statistics:**

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);    /* PID */
    __type(value, u64);  /* Run time */
    __uint(max_entries, 10000);
} task_stats SEC(".maps");
```

Read from user-space:
```c
u32 pid = 1234;
u64 runtime;
bpf_map_lookup_elem(map_fd, &pid, &runtime);
printf("PID %d runtime: %llu ns\n", pid, runtime);
```

**3. Using bpftool:**

```bash
# List loaded BPF programs
sudo bpftool prog list

# Show scheduler struct_ops
sudo bpftool struct_ops list

# Dump scheduler state
sudo bpftool struct_ops dump name simple_fifo

# Show BPF map contents
sudo bpftool map dump name queue_stats
```

### Advantages of BPF Schedulers

1. **Rapid Development**: Write, compile, test cycle in seconds
2. **Safety**: BPF verifier ensures scheduler can't crash the kernel
3. **Flexibility**: Easy to experiment with different policies
4. **No Downtime**: Load/unload without rebooting
5. **Rich Access**: Can read task state, cgroups, CPU info
6. **Performance**: Compiled to native code, runs at kernel speed

### Limitations

1. **BPF Constraints**: 
   - Limited stack size (512 bytes)
   - No unbounded loops
   - Limited recursion
   - Must pass verifier checks

2. **Complexity Limits**:
   - Very complex algorithms may not fit in BPF
   - Some kernel functions not accessible

3. **Fallback to CFS**:
   - If BPF scheduler has issues, tasks automatically fall back to CFS
   - Ensures system stability

### Real-World Example: CPU Hotplug Handling

```c
void BPF_STRUCT_OPS(my_cpu_online, s32 cpu)
{
    bpf_printk("CPU %d came online", cpu);
    /* Could rebalance tasks to new CPU */
}

void BPF_STRUCT_OPS(my_cpu_offline, s32 cpu)
{
    bpf_printk("CPU %d going offline", cpu);
    /* Migrate tasks away from offline CPU */
}

SEC(".struct_ops")
struct sched_ext_ops my_sched = {
    /* ... other ops ... */
    .cpu_online  = (void *)my_cpu_online,
    .cpu_offline = (void *)my_cpu_offline,
    .name        = "my_sched",
};
```

This demonstrates the power of `sched_ext`: you can implement sophisticated scheduling policies
entirely in BPF, with full access to kernel scheduling infrastructure, while maintaining system
safety and stability.
