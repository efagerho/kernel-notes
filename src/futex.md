# Futex: Fast Userspace Mutexes

## Overview

**Futex (Fast Userspace Mutex)** is a Linux kernel mechanism that provides efficient synchronization primitives for userspace applications. Unlike traditional semaphores or mutexes that require a system call for every operation, futexes allow uncontended lock operations to execute entirely in userspace, only involving the kernel when threads actually need to block.

This chapter covers:

1. **Futex Fundamentals**: The basic concept and why futexes are fast
2. **Kernel Implementation**: How the kernel manages waiting threads and wake operations
3. **Futex Operations**: The different FUTEX_* operations and their semantics
4. **Typical Applications**: How futexes implement mutexes, condition variables, semaphores, and barriers
5. **Advanced Features**: Priority inheritance, robust futexes, and real-time considerations

**Key insight**: Futexes exploit the observation that most lock operations are uncontended. In the fast path (no contention), operations are entirely userspace atomic operations. Only when contention occurs does the kernel get involved.

## Futex Fundamentals

### The Problem: Traditional Lock Overhead

Traditional kernel-provided synchronization primitives require system calls:

```c
/* Traditional semaphore */
sem_wait(sem);     // System call EVERY time
/* Critical section */
sem_post(sem);     // System call EVERY time
```

**Cost of system calls**:
- ~100-200 cycles: syscall entry/exit overhead
- Context switching to kernel mode
- Cache pollution
- Lost opportunity for optimization

For frequently-acquired locks that are rarely contended, this is wasteful.

### The Futex Solution

Futexes split synchronization into two paths:

**Fast path (uncontended)**: Entirely in userspace
```c
/* Lock acquisition */
if (atomic_cmpxchg(futex, 0, 1) == 0) {
    /* Got the lock! No syscall needed */
}
```

**Slow path (contended)**: Involve kernel
```c
/* Failed to get lock, need to wait */
futex(futex_addr, FUTEX_WAIT, expected_val, ...);  // Syscall
```

**Result**: Most operations (uncontended) take ~10-20 cycles. Only contended operations pay the syscall cost.

### Futex Address Space

A futex is identified by:
- **Virtual address** of an integer (typically `int *`)
- **Process address space** (different processes can have futexes at same virtual address)

```c
int futex_word = 0;  /* The futex itself - just an integer in memory */

/* No kernel allocation needed - it's just userspace memory */
```

**Important**: The futex "word" is just normal userspace memory. The kernel doesn't allocate anything until a thread tries to wait.

### Basic Futex Operations

```c
#include <linux/futex.h>
#include <sys/syscall.h>

/* System call wrapper */
long futex(int *uaddr, int futex_op, int val,
           const struct timespec *timeout,
           int *uaddr2, int val3);
```

**Core operations**:

1. **FUTEX_WAIT**: Block if `*uaddr == val`
   ```c
   /* "If the value is still 'expected', put me to sleep" */
   futex(uaddr, FUTEX_WAIT, expected, timeout, NULL, 0);
   ```

2. **FUTEX_WAKE**: Wake up to `val` waiting threads
   ```c
   /* "Wake up N threads waiting on this futex" */
   futex(uaddr, FUTEX_WAKE, num_to_wake, NULL, NULL, 0);
   ```

### Simple Example: Userspace Mutex

```c
/* Mutex is just an integer: 0 = unlocked, 1 = locked */
int mutex = 0;

void lock(int *mutex)
{
    int c;
    
    /* Fast path: try to acquire lock with atomic compare-and-swap */
    if ((c = __sync_val_compare_and_swap(mutex, 0, 1)) == 0) {
        /* Success! Lock acquired, no syscall */
        return;
    }
    
    /* Slow path: lock is contended */
    do {
        /* If lock shows contention (value > 1), wait */
        if (c == 2 || __sync_val_compare_and_swap(mutex, 1, 2) != 0) {
            /* Block until woken */
            futex(mutex, FUTEX_WAIT, 2, NULL, NULL, 0);
        }
    } while ((c = __sync_val_compare_and_swap(mutex, 0, 2)) != 0);
}

void unlock(int *mutex)
{
    /* Decrement: if result is not 0, there were waiters */
    if (__sync_fetch_and_sub(mutex, 1) != 1) {
        /* There are waiters - wake one */
        *mutex = 0;
        futex(mutex, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
}
```

**Why this is fast**:
- Uncontended lock: one atomic operation, ~10 cycles
- Uncontended unlock: one atomic operation, ~10 cycles
- Contended operations: pay syscall cost, but rare

## Kernel Implementation

### Futex Hash Table

The kernel maintains a global hash table of futex wait queues:

```c
/* From kernel/futex/core.c */

/* Hash table of futex queues */
struct futex_hash_bucket {
    atomic_t waiters;           /* Number of waiters on this bucket */
    spinlock_t lock;            /* Protects the list */
    struct plist_head chain;    /* Priority-sorted list of waiting tasks */
};

static struct futex_hash_bucket *futex_queues;
```

**Hash key**: Computed from the futex address and memory mapping:

```c
/* From kernel/futex/core.c */
static inline unsigned int hash_futex(union futex_key *key)
{
    return jhash2((u32 *)key, offsetof(typeof(*key), both.offset) / 4,
                  key->both.offset) & (futex_hashsize - 1);
}
```

**Why hash table?**
- Can't allocate kernel memory for every futex (would require syscall)
- Hash table allows kernel to lazily track only futexes with waiters
- Multiple futexes can hash to same bucket (handled by full key comparison)

### Futex Key

A futex is uniquely identified by:

```c
/* From kernel/futex/futex.h */
union futex_key {
    struct {
        u64 i_seq;              /* inode sequence number (for files) */
        unsigned long pgoff;    /* Page offset within file */
        unsigned int offset;    /* Offset within page */
    } shared;
    struct {
        union {
            struct mm_struct *mm;   /* Process address space */
            u64 __tmp;
        };
        unsigned long address;  /* Virtual address (aligned) */
        unsigned int offset;    /* Offset within page */
    } private;
    struct {
        u64 ptr;
        unsigned long word;
        unsigned int offset;
    } both;
};
```

**Two types of futexes**:

1. **Private futexes** (FUTEX_PRIVATE_FLAG): Only for threads in same process
   - Key: `{mm_struct, virtual_address, offset}`
   - Faster: no need to handle shared memory

2. **Shared futexes**: Can be shared between processes
   - Key: `{inode, page_offset, offset}`
   - Used for futexes in shared memory (mmap, shm_open)

### FUTEX_WAIT Implementation

```c
/* Simplified from kernel/futex/waitwake.c */

static int futex_wait(u32 __user *uaddr, unsigned int flags,
                      u32 val, ktime_t *abs_time, u32 bitset)
{
    struct hrtimer_sleeper timeout, *to;
    struct futex_hash_bucket *hb;
    struct futex_q q = futex_q_init;
    union futex_key key;
    u32 uval;
    int ret;
    
    /* Get futex key (identifies this futex) */
    ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &key, FUTEX_READ);
    if (unlikely(ret))
        return ret;
    
    /* Find hash bucket for this futex */
    hb = futex_hash(&key);
    
    /* Setup timeout if specified */
    if (abs_time) {
        to = &timeout;
        hrtimer_init_sleeper_on_stack(to, CLOCK_REALTIME,
                                       HRTIMER_MODE_ABS);
        hrtimer_set_expires(&to->timer, *abs_time);
    }
    
retry:
    /* Lock the hash bucket */
    spin_lock(&hb->lock);
    
    /* Re-check the futex value atomically with queue insertion */
    ret = get_futex_value_locked(&uval, uaddr);
    if (ret) {
        spin_unlock(&hb->lock);
        /* Page fault - handle it and retry */
        ret = fault_in_user_writeable(uaddr);
        if (!ret)
            goto retry;
        return ret;
    }
    
    /* Has the value changed? */
    if (uval != val) {
        spin_unlock(&hb->lock);
        return -EAGAIN;  /* Value changed - don't wait */
    }
    
    /* Value matches - queue ourselves */
    q.key = key;
    __queue_me(&q, hb);
    
    /* Release bucket lock and sleep */
    spin_unlock(&hb->lock);
    
    /* Sleep until woken or timeout */
    if (!to) {
        /* Sleep indefinitely */
        freezable_schedule();
    } else {
        hrtimer_sleeper_start_expires(to, HRTIMER_MODE_ABS);
        if (!hrtimer_active(&to->timer))
            ret = -ETIMEDOUT;
        else {
            freezable_schedule();
            /* Check if timeout occurred */
            if (to && !to->task)
                ret = -ETIMEDOUT;
        }
    }
    
    /* Woken up - remove from queue if not already removed */
    __unqueue_me(&q);
    
    return ret;
}
```

**Key steps**:

1. **Get futex key**: Identify the futex (address + memory mapping)
2. **Hash to bucket**: Find the wait queue
3. **Lock bucket**: Prevent races
4. **Re-check value**: CRITICAL - value must still match
5. **Queue task**: Add current task to wait queue
6. **Unlock and sleep**: Release lock, put task to sleep
7. **Wake up**: Eventually woken by FUTEX_WAKE or timeout

**Race prevention**: The re-check with bucket lock held prevents lost wakeups:

```
Thread A (lock holder)          Thread B (waiter)
━━━━━━━━━━━━━━━━━━━━          ━━━━━━━━━━━━━━━━
                                Check: mutex == 1
                                Try CAS, fails
Unlock: mutex = 0               
futex_wake()                    Enter kernel (FUTEX_WAIT)
  - No waiters, returns         Lock bucket
                                Re-check: mutex == 0 ✓
                                - Doesn't wait! Returns -EAGAIN
```

### FUTEX_WAKE Implementation

```c
/* Simplified from kernel/futex/waitwake.c */

static int futex_wake(u32 __user *uaddr, unsigned int flags,
                      int nr_wake, u32 bitset)
{
    struct futex_hash_bucket *hb;
    struct futex_q *this, *next;
    union futex_key key;
    int ret;
    
    /* Get futex key */
    ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &key, FUTEX_READ);
    if (unlikely(ret))
        return ret;
    
    /* Find hash bucket */
    hb = futex_hash(&key);
    
    /* Lock bucket */
    spin_lock(&hb->lock);
    
    /* Walk the wait queue, wake up to nr_wake tasks */
    plist_for_each_entry_safe(this, next, &hb->chain, list) {
        /* Does this waiter match our key? */
        if (match_futex(&this->key, &key)) {
            /* Check bitset (for FUTEX_WAKE_BITSET) */
            if (!(this->bitset & bitset))
                continue;
            
            /* Wake this task */
            mark_wake_futex(&wake_q, this);
            
            /* Woken enough tasks? */
            if (++ret >= nr_wake)
                break;
        }
    }
    
    spin_unlock(&hb->lock);
    
    /* Actually wake the tasks (outside the spinlock) */
    wake_up_q(&wake_q);
    
    return ret;  /* Number of tasks woken */
}
```

**Key steps**:

1. **Find bucket**: Hash the futex address
2. **Lock bucket**: Prevent races
3. **Scan wait queue**: Find matching waiters
4. **Mark for wakeup**: Add to wake queue (but don't wake yet)
5. **Unlock bucket**: Release lock
6. **Wake tasks**: Actually wake the tasks (expensive operation done outside spinlock)

**Why defer wakeup?** 
- `wake_up_process()` can be expensive (reschedule, IPI to other CPU)
- Doing it inside spinlock would hurt scalability
- Build list while holding lock, wake after releasing

### Priority Inheritance

For real-time applications, futexes support **priority inheritance** to prevent priority inversion:

```c
/* FUTEX_LOCK_PI: Priority-inheriting lock */
futex(uaddr, FUTEX_LOCK_PI, 0, timeout, NULL, 0);
```

**Priority inversion problem**:

```
High-priority task H needs lock held by low-priority task L
Medium-priority task M preempts L
→ H blocked waiting for L, but L can't run because M is running
→ H effectively runs at priority M (priority inversion)
```

**Priority inheritance solution**:

```c
/* From kernel/futex/pi.c */

static int futex_lock_pi(u32 __user *uaddr, unsigned int flags,
                         ktime_t *time, int trylock)
{
    struct task_struct *task = current;
    struct futex_pi_state *pi_state = NULL;
    struct rt_mutex_waiter rt_waiter;
    struct futex_hash_bucket *hb;
    struct futex_q q = futex_q_init;
    /* ... */
    
    /* Try to acquire the lock */
    ret = futex_lock_pi_atomic(uaddr, hb, &q.key, &q.pi_state,
                                task, &vpid, 0);
    if (ret == 0) {
        /* Got it! */
        return 0;
    }
    
    /* Couldn't get lock - need to wait */
    /* Current owner will boost its priority to our priority */
    rt_mutex_init_waiter(&rt_waiter);
    ret = rt_mutex_start_proxy_lock(&q.pi_state->pi_mutex,
                                     &rt_waiter, task);
    
    /* ... sleep until lock available ... */
}
```

**How it works**:

1. Task H tries to acquire futex held by L
2. Kernel detects that H (high priority) is waiting for L (low priority)
3. Kernel boosts L's priority to H's priority
4. L runs at elevated priority, finishes critical section faster
5. L releases lock, priority restored to normal
6. H acquires lock

This is implemented using the kernel's `rt_mutex` infrastructure.

### Robust Futexes

**Problem**: What if a thread holding a futex dies?

```c
pthread_mutex_lock(&mutex);
/* Critical section */
CRASH!  /* Mutex never unlocked - other threads deadlocked forever */
```

**Solution**: Robust futexes

```c
/* Thread registers list of held futexes with kernel */
set_robust_list(struct robust_list_head *head, size_t len);

/* Each futex has a list node */
struct robust_list {
    struct robust_list *next;
};

struct robust_list_head {
    struct robust_list list;     /* List of held futexes */
    long futex_offset;           /* Offset to futex word in each node */
    struct robust_list *list_op_pending;  /* Currently processing */
};
```

**When thread exits**:

```c
/* From kernel/futex/core.c */

void exit_robust_list(struct task_struct *curr)
{
    struct robust_list_head __user *head = curr->robust_list;
    struct robust_list __user *entry, *next;
    unsigned int limit = ROBUST_LIST_LIMIT;
    unsigned long futex_offset;
    
    if (!head)
        return;
    
    /* Get futex offset */
    if (get_user(futex_offset, &head->futex_offset))
        return;
    
    /* Walk the list of held futexes */
    if (get_user(entry, &head->list.next))
        return;
    
    while (entry != &head->list && --limit) {
        /* Get futex word address */
        void __user *futex = (void __user *)entry + futex_offset;
        
        /* Mark futex as owner-died */
        handle_futex_death(futex, curr, HANDLE_DEATH_LIST);
        
        /* Next entry */
        if (get_user(entry, &entry->next))
            break;
    }
}

static void handle_futex_death(u32 __user *uaddr,
                                struct task_struct *curr, int pi)
{
    u32 uval, nval;
    
    /* Atomically mark futex as FUTEX_OWNER_DIED */
    if (get_user(uval, uaddr))
        return;
    
    /* Clear owner TID, set OWNER_DIED bit */
    nval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    
    if (cmpxchg_futex_value_locked(&uval, uaddr, uval, nval) == 0) {
        /* Wake any waiters */
        if (uval & FUTEX_WAITERS)
            futex_wake(uaddr, FLAGS_SIZE_32, 1, FUTEX_BITSET_MATCH_ANY);
    }
}
```

**Result**: Next thread that acquires the futex sees `FUTEX_OWNER_DIED` bit and knows to:
- Clean up any inconsistent state left by dead thread
- Continue or return error (depending on application)

## Futex Operations

### Core Operations

#### FUTEX_WAIT

Wait until futex value changes:

```c
int futex(int *uaddr, FUTEX_WAIT, int val,
          const struct timespec *timeout, NULL, 0);
```

**Semantics**:
- If `*uaddr == val`, sleep until woken or timeout
- If `*uaddr != val`, return immediately with `-EAGAIN`
- Atomic check and sleep (prevents lost wakeups)

**Use case**: Waiting for a condition

```c
/* Producer */
while (queue_full) {
    futex(&queue_full, FUTEX_WAIT, 1, NULL, NULL, 0);
}

/* Consumer */
queue_full = 0;
futex(&queue_full, FUTEX_WAKE, 1, NULL, NULL, 0);
```

#### FUTEX_WAKE

Wake waiting threads:

```c
int futex(int *uaddr, FUTEX_WAKE, int nr_wake, NULL, NULL, 0);
```

**Semantics**:
- Wake up to `nr_wake` threads waiting on `uaddr`
- Returns number of threads actually woken
- Common values: 1 (wake one), INT_MAX (wake all)

**Use case**: Signaling a condition

#### FUTEX_WAIT_BITSET / FUTEX_WAKE_BITSET

Selective wakeup using bitmasks:

```c
/* Wait with bitset */
futex(uaddr, FUTEX_WAIT_BITSET, val, timeout, NULL, bitset);

/* Wake with bitset */
futex(uaddr, FUTEX_WAKE_BITSET, nr_wake, NULL, NULL, bitset);
```

**Semantics**:
- Waiter specifies a bitset (which wakeup patterns it responds to)
- Waker specifies a bitset (which waiters to wake)
- Waiter is woken if `waiter_bitset & waker_bitset != 0`

**Use case**: Condition variables with broadcast vs signal

```c
/* pthread_cond_signal: wake one */
#define FUTEX_BITSET_SIGNAL  0x1

/* pthread_cond_broadcast: wake all */
#define FUTEX_BITSET_BROADCAST  0xFFFFFFFF

/* Wait */
futex(uaddr, FUTEX_WAIT_BITSET, val, timeout, NULL,
      FUTEX_BITSET_SIGNAL | FUTEX_BITSET_BROADCAST);

/* Signal one */
futex(uaddr, FUTEX_WAKE_BITSET, 1, NULL, NULL, FUTEX_BITSET_SIGNAL);

/* Broadcast all */
futex(uaddr, FUTEX_WAKE_BITSET, INT_MAX, NULL, NULL, FUTEX_BITSET_BROADCAST);
```

### Requeue Operations

#### FUTEX_CMP_REQUEUE

Move waiters from one futex to another:

```c
int futex(int *uaddr1, FUTEX_CMP_REQUEUE, int nr_wake,
          int nr_requeue, int *uaddr2, int val3);
```

**Semantics**:
- If `*uaddr1 != val3`, return `-EAGAIN` (prevents race)
- Wake up to `nr_wake` threads on `uaddr1`
- Move up to `nr_requeue` remaining threads from `uaddr1` to `uaddr2`

**Use case**: Condition variable broadcast

```
Problem: pthread_cond_broadcast() with many waiters
- Naive: wake all threads
- All threads wake up, try to acquire mutex
- N-1 threads fail, go back to sleep
- Lots of unnecessary wakeups (thundering herd)

Solution: Requeue waiters to the mutex
- Wake one thread
- Requeue others to mutex futex
- As each thread releases mutex, next one wakes
- Only one thread running at a time
```

```c
/* pthread_cond_broadcast implementation */
void cond_broadcast(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    /* Wake one, requeue rest to mutex */
    futex(&cond->futex,
          FUTEX_CMP_REQUEUE,
          1,              /* Wake 1 thread */
          INT_MAX,        /* Requeue all others */
          &mutex->futex,  /* Requeue to mutex */
          cond->seq);     /* Check seq hasn't changed */
}
```

#### FUTEX_WAKE_OP

Atomic wake on two futexes:

```c
int futex(int *uaddr1, FUTEX_WAKE_OP, int nr_wake1,
          int nr_wake2, int *uaddr2, int op);
```

**Semantics**:
- Atomically performs operation `op` on `uaddr2`
- Wakes `nr_wake1` threads on `uaddr1`
- If operation result meets condition, wakes `nr_wake2` threads on `uaddr2`

**Use case**: Condition variable + mutex release

```c
/* Unlock mutex and signal condition variable */
/* Operation: oldval = *uaddr2; *uaddr2 op= oparg; */
futex(&cond->futex, FUTEX_WAKE_OP,
      1,              /* Wake 1 on condition */
      1,              /* Wake 1 on mutex if... */
      &mutex->futex,  /* ...this futex */
      FUTEX_OP_SET);  /* ...is set */
```

### Priority Inheritance Operations

#### FUTEX_LOCK_PI

Acquire a priority-inheriting lock:

```c
int futex(int *uaddr, FUTEX_LOCK_PI, 0, timeout, NULL, 0);
```

**Semantics**:
- Try to acquire lock
- If contended, block with priority inheritance
- Lock value encodes TID of owner

**Use case**: Real-time applications requiring predictable latency

#### FUTEX_UNLOCK_PI

Release a priority-inheriting lock:

```c
int futex(int *uaddr, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
```

#### FUTEX_TRYLOCK_PI

Try to acquire PI lock without blocking:

```c
int futex(int *uaddr, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
```

## Typical Applications

### Mutex Implementation

A complete mutex using futexes:

```c
typedef struct {
    int state;  /* 0 = unlocked, 1 = locked no waiters, 2 = locked with waiters */
} futex_mutex_t;

void futex_mutex_init(futex_mutex_t *m)
{
    m->state = 0;
}

void futex_mutex_lock(futex_mutex_t *m)
{
    int c;
    
    /* Try fast path: unlocked (0) → locked (1) */
    if ((c = __sync_val_compare_and_swap(&m->state, 0, 1)) == 0)
        return;  /* Success! */
    
    /* Slow path: contended */
    do {
        /* If state is 2 or we set it to 2, there are waiters */
        if (c == 2 || __sync_val_compare_and_swap(&m->state, 1, 2) != 0) {
            /* Wait for wakeup */
            futex(&m->state, FUTEX_WAIT, 2, NULL, NULL, 0);
        }
        /* Try to acquire: unlocked (0) → locked with waiters (2) */
    } while ((c = __sync_val_compare_and_swap(&m->state, 0, 2)) != 0);
}

int futex_mutex_trylock(futex_mutex_t *m)
{
    /* Try to acquire: unlocked (0) → locked (1) */
    return __sync_bool_compare_and_swap(&m->state, 0, 1);
}

void futex_mutex_unlock(futex_mutex_t *m)
{
    int c;
    
    /* Decrement state */
    c = __sync_fetch_and_sub(&m->state, 1);
    
    /* If state was 2 (locked with waiters), wake a waiter */
    if (c != 1) {
        m->state = 0;
        futex(&m->state, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
}
```

**State transitions**:
```
0 (unlocked) → 1 (locked, no waiters)
1 (locked, no waiters) → 2 (locked, waiters)
2 (locked, waiters) → 0 (unlocked)
```

**Performance**:
- Uncontended lock: ~10 cycles (one atomic CAS)
- Uncontended unlock: ~10 cycles (one atomic decrement)
- Contended: ~5000 cycles (syscall overhead)

### Condition Variable Implementation

```c
typedef struct {
    int seq;        /* Sequence number for broadcast */
    int waiters;    /* Number of waiting threads */
} futex_cond_t;

typedef futex_mutex_t futex_mutex_t;  /* From above */

void futex_cond_init(futex_cond_t *c)
{
    c->seq = 0;
    c->waiters = 0;
}

void futex_cond_wait(futex_cond_t *c, futex_mutex_t *m)
{
    int seq = c->seq;
    
    /* Increment waiters */
    __sync_fetch_and_add(&c->waiters, 1);
    
    /* Release mutex */
    futex_mutex_unlock(m);
    
    /* Wait for signal (seq changes) */
    futex(&c->seq, FUTEX_WAIT, seq, NULL, NULL, 0);
    
    /* Decrement waiters */
    __sync_fetch_and_sub(&c->waiters, 1);
    
    /* Re-acquire mutex */
    futex_mutex_lock(m);
}

void futex_cond_signal(futex_cond_t *c)
{
    /* Increment seq to wake waiters */
    __sync_fetch_and_add(&c->seq, 1);
    
    /* Wake one waiter */
    futex(&c->seq, FUTEX_WAKE, 1, NULL, NULL, 0);
}

void futex_cond_broadcast(futex_cond_t *c)
{
    /* Increment seq to wake waiters */
    __sync_fetch_and_add(&c->seq, 1);
    
    /* Wake all waiters */
    futex(&c->seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}
```

**Optimized broadcast with requeue**:

```c
void futex_cond_broadcast_optimized(futex_cond_t *c, futex_mutex_t *m)
{
    int seq = c->seq;
    
    /* Increment seq */
    __sync_fetch_and_add(&c->seq, 1);
    
    /* Wake one, requeue rest to mutex */
    futex(&c->seq, FUTEX_CMP_REQUEUE,
          1,              /* Wake 1 */
          INT_MAX,        /* Requeue all others */
          &m->state,      /* To mutex */
          seq);           /* If seq unchanged */
}
```

**Why requeue is better**:
- Without requeue: Wake N threads → all try to lock mutex → N-1 immediately block again
- With requeue: Wake 1 thread → requeue N-1 to mutex → each wakes as mutex becomes available

### Semaphore Implementation

```c
typedef struct {
    int count;  /* Available resources */
} futex_sem_t;

void futex_sem_init(futex_sem_t *s, int initial_count)
{
    s->count = initial_count;
}

void futex_sem_wait(futex_sem_t *s)
{
    int c;
    
    /* Try to decrement count */
    while ((c = __sync_fetch_and_sub(&s->count, 1)) <= 0) {
        /* No resources available */
        __sync_fetch_and_add(&s->count, 1);  /* Undo decrement */
        
        /* Wait for count to become positive */
        futex(&s->count, FUTEX_WAIT, 0, NULL, NULL, 0);
    }
}

void futex_sem_post(futex_sem_t *s)
{
    /* Increment count */
    int c = __sync_fetch_and_add(&s->count, 1);
    
    /* If count was negative or zero, wake a waiter */
    if (c <= 0) {
        futex(&s->count, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
}

int futex_sem_trywait(futex_sem_t *s)
{
    int c;
    
    /* Try to decrement if positive */
    do {
        c = s->count;
        if (c <= 0)
            return 0;  /* Failure */
    } while (!__sync_bool_compare_and_swap(&s->count, c, c - 1));
    
    return 1;  /* Success */
}
```

### Barrier Implementation

```c
typedef struct {
    int count;      /* Number of threads that have arrived */
    int total;      /* Total number of threads in barrier */
    int seq;        /* Sequence number (generation) */
} futex_barrier_t;

void futex_barrier_init(futex_barrier_t *b, int num_threads)
{
    b->count = 0;
    b->total = num_threads;
    b->seq = 0;
}

void futex_barrier_wait(futex_barrier_t *b)
{
    int seq = b->seq;
    int count;
    
    /* Increment count */
    count = __sync_add_and_fetch(&b->count, 1);
    
    if (count < b->total) {
        /* Not the last thread - wait */
        do {
            futex(&b->seq, FUTEX_WAIT, seq, NULL, NULL, 0);
        } while (b->seq == seq);  /* Spurious wakeup protection */
    } else {
        /* Last thread - reset and wake all */
        b->count = 0;
        __sync_fetch_and_add(&b->seq, 1);
        futex(&b->seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    }
}
```

### Read-Write Lock Implementation

```c
typedef struct {
    int state;  /* High bit: write lock, low bits: reader count */
    /* state = 0x80000000 | readers */
} futex_rwlock_t;

#define WRITE_LOCK_BIT  0x80000000
#define READER_MASK     0x7FFFFFFF

void futex_rwlock_init(futex_rwlock_t *rw)
{
    rw->state = 0;
}

void futex_rwlock_rdlock(futex_rwlock_t *rw)
{
    int s;
    
    for (;;) {
        s = rw->state;
        
        /* If write-locked, wait */
        if (s & WRITE_LOCK_BIT) {
            futex(&rw->state, FUTEX_WAIT, s, NULL, NULL, 0);
            continue;
        }
        
        /* Try to increment reader count */
        if (__sync_bool_compare_and_swap(&rw->state, s, s + 1))
            break;
    }
}

void futex_rwlock_rdunlock(futex_rwlock_t *rw)
{
    int s;
    
    /* Decrement reader count */
    s = __sync_fetch_and_sub(&rw->state, 1);
    
    /* If we were the last reader, wake waiting writers */
    if ((s & READER_MASK) == 1) {
        futex(&rw->state, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
}

void futex_rwlock_wrlock(futex_rwlock_t *rw)
{
    int s;
    
    for (;;) {
        s = rw->state;
        
        /* If any locks held, wait */
        if (s != 0) {
            futex(&rw->state, FUTEX_WAIT, s, NULL, NULL, 0);
            continue;
        }
        
        /* Try to acquire write lock */
        if (__sync_bool_compare_and_swap(&rw->state, 0, WRITE_LOCK_BIT))
            break;
    }
}

void futex_rwlock_wrunlock(futex_rwlock_t *rw)
{
    /* Release write lock */
    rw->state = 0;
    
    /* Wake all waiting threads (readers and writers) */
    futex(&rw->state, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}
```

## Performance Considerations

### Fast Path Optimization

**Goal**: Make uncontended operations as fast as possible.

```c
/* Typical mutex lock fast path */
lock:
    mov    $1, %eax              /* Load 1 into eax */
    lock cmpxchg %eax, (%rdi)    /* Atomic CAS: if *rdi == 0, *rdi = 1 */
    jnz    slow_path             /* If failed, go to slow path */
    ret                          /* Success - return */

slow_path:
    /* ... futex syscall ... */
```

**Cost breakdown**:
- `lock cmpxchg`: ~10 cycles (uncontended)
- Conditional jump: ~1 cycle (predicted)
- Total: ~11 cycles

Compare to syscall: ~150-200 cycles minimum.

### Cache Line Bouncing

**Problem**: Multiple threads accessing same futex word causes cache line bouncing.

```c
struct {
    int lock1;  /* Futex 1 */
    int lock2;  /* Futex 2 - same cache line! */
} shared;

/* Thread 1 */
futex_lock(&shared.lock1);  /* Cache line to CPU 1 */

/* Thread 2 */
futex_lock(&shared.lock2);  /* Cache line bounces to CPU 2 */
```

**Solution**: Pad futexes to separate cache lines

```c
struct {
    int lock1;
    char pad1[64 - sizeof(int)];  /* Separate cache lines */
    int lock2;
    char pad2[64 - sizeof(int)];
} shared __attribute__((aligned(64)));
```

### Spurious Wakeups

Futexes can have spurious wakeups (wake without corresponding wake call):

**Causes**:
- Hash collision in kernel futex hash table
- Signal delivery
- FUTEX_WAKE on different futex that hashed to same bucket

**Solution**: Always re-check condition after wake

```c
/* WRONG - doesn't handle spurious wakeup */
if (condition)
    futex_wait(&futex, val, ...);

/* CORRECT - loop and re-check */
while (condition) {
    futex_wait(&futex, val, ...);
}
```

### Memory Ordering

Futex operations have specific memory ordering guarantees:

```c
/* Thread 1 */
data = 42;              /* Write data */
__sync_synchronize();   /* Memory barrier */
futex_wake(&futex, 1);  /* Wake thread 2 */

/* Thread 2 */
futex_wait(&futex, 0);  /* Wait for thread 1 */
__sync_synchronize();   /* Memory barrier */
x = data;               /* Read data - guaranteed to see 42 */
```

**Guarantee**: 
- Writes before `futex_wake` are visible to thread after `futex_wait`
- Futex operations have acquire/release semantics

### Private vs Shared Futexes

**Private futexes** (FUTEX_PRIVATE_FLAG): ~5-10% faster

```c
/* Private futex - only for threads in same process */
futex(uaddr, FUTEX_WAIT_PRIVATE, val, NULL, NULL, 0);

/* Shared futex - can be used between processes */
futex(uaddr, FUTEX_WAIT, val, NULL, NULL, 0);
```

**Why private is faster**:
- Simpler key (no need to look up inode)
- No need to handle memory unmapping
- No cross-process concerns

**When to use private**:
- pthread mutexes, condition variables within one process
- Default for most applications

**When to use shared**:
- Synchronization in shared memory (mmap, shm_open)
- Inter-process synchronization

## Advanced Topics

### Priority Inheritance Details

**Priority inversion scenario**:

```
Priority levels: H (high) > M (medium) > L (low)

Time 0: L acquires lock
Time 1: H tries to acquire lock, blocks
Time 2: M becomes runnable, preempts L
Time 3: M runs while H waits for L
        → Priority inversion: H waiting for L, but L can't run
```

**With priority inheritance**:

```c
/* Thread H (high priority) */
futex(&lock, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  ↓
Kernel sees L holds lock, H wants it
Kernel boosts L to H's priority
L runs at high priority, finishes critical section
L releases lock, priority restored
H acquires lock
```

**Implementation**:

```c
/* From kernel/futex/pi.c */

static int attach_to_pi_owner(u32 __user *uaddr, u32 uval,
                               union futex_key *key,
                               struct futex_pi_state **ps,
                               struct task_struct **exiting)
{
    struct task_struct *p;
    struct futex_pi_state *pi_state;
    pid_t pid = uval & FUTEX_TID_MASK;
    
    /* Find the owner task */
    p = futex_find_get_task(pid);
    if (!p)
        return -ESRCH;
    
    /* Allocate PI state */
    pi_state = alloc_pi_state();
    if (!pi_state) {
        put_task_struct(p);
        return -ENOMEM;
    }
    
    /* Initialize rt_mutex for priority inheritance */
    rt_mutex_init_proxy_locked(&pi_state->pi_mutex, p);
    
    /* Now current task will boost p's priority if needed */
    *ps = pi_state;
    return 0;
}
```

### Robust Futex Details

**Registration**:

```c
/* Each thread registers its robust list */
struct robust_list_head {
    struct robust_list list;
    long futex_offset;              /* Offset to futex word */
    struct robust_list *list_op_pending;
};

/* Register with kernel */
syscall(SYS_set_robust_list, &head, sizeof(head));
```

**Usage**:

```c
struct futex_node {
    struct robust_list list;
    int futex;
    /* ... other data ... */
};

void add_to_robust_list(struct futex_node *node, struct robust_list_head *head)
{
    /* Add to list */
    node->list.next = head->list.next;
    head->list.next = &node->list;
}

void remove_from_robust_list(struct futex_node *node, struct robust_list_head *head)
{
    /* Mark as in-progress */
    head->list_op_pending = &node->list;
    
    /* Remove from list */
    /* ... */
    
    /* Clear in-progress */
    head->list_op_pending = NULL;
}
```

**Cleanup on death**:

```c
/* Kernel walks the list and marks each futex as FUTEX_OWNER_DIED */
#define FUTEX_OWNER_DIED  0x40000000

/* Next waiter sees this bit */
int val;
futex_wait(&futex, val);

if (val & FUTEX_OWNER_DIED) {
    /* Previous owner died - handle inconsistent state */
    /* Could return error (EOWNERDEAD for pthread_mutex) */
}
```

### Futex2: Next Generation

Recent Linux kernels have added futex2, which provides:

1. **Variable-sized futexes**: Not just 32-bit integers
2. **Better scalability**: Improved hash table
3. **Simplified interface**: Cleaner API

```c
/* New futex2 interface (Linux 5.16+) */
struct futex_waitv {
    __u64 val;         /* Expected value */
    __u64 uaddr;       /* Futex address */
    __u32 flags;       /* Flags */
    __u32 __reserved;
};

/* Wait on multiple futexes */
syscall(SYS_futex_waitv, struct futex_waitv *waiters,
        unsigned int nr_futexes,
        unsigned int flags,
        struct timespec *timeout,
        clockid_t clockid);
```

**Benefits**:
- Can wait on multiple futexes simultaneously
- Better support for 64-bit futexes
- More consistent semantics

## Summary

Futexes are the foundation of efficient userspace synchronization on Linux:

**Key advantages**:
- **Fast path**: Uncontended operations are entirely userspace (~10 cycles)
- **Scalable**: No kernel overhead for uncontended locks
- **Flexible**: Support mutexes, semaphores, barriers, condition variables, rwlocks
- **Advanced features**: Priority inheritance, robust futexes, requeue operations

**How they work**:
1. Futex is just an integer in userspace memory
2. Uncontended: atomic operations only
3. Contended: syscall to kernel
4. Kernel maintains hash table of wait queues
5. Critical re-check prevents lost wakeups

**Real-world usage**:
- **glibc**: pthread mutexes, condition variables use futexes
- **Java**: `synchronized`, `wait()`/`notify()` use futexes
- **Go**: sync.Mutex, sync.Cond use futexes
- All modern languages/runtimes use futexes for synchronization

**Performance impact**:
- Uncontended lock/unlock: ~10-20 cycles (vs ~150-200 for syscall)
- 10-20x faster than traditional kernel semaphores
- Critical for highly-concurrent applications

For more on how futexes relate to real-time scheduling, see [Scheduler](./scheduler.md). For details on how system calls work, see [System Calls](./syscalls.md).
