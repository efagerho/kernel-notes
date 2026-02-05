# TCP Congestion Control

## Introduction

TCP congestion control is the mechanism that prevents the network from being overwhelmed by too much traffic. While **flow control** (covered in the previous chapter) prevents overwhelming the **receiver**, congestion control prevents overwhelming the **network**.

The core insight: **packet loss and increasing delay are symptoms of network congestion**. TCP reacts to these signals by reducing its sending rate.

### Why Congestion Control?

Without congestion control:

```
Network capacity: 100 Mbps
10 TCP connections each try to send at 100 Mbps
Total offered load: 1000 Mbps
Result: 90% packet loss, network collapses to near-zero throughput

With congestion control:
Each connection backs off when detecting loss
Connections share bandwidth fairly
Total throughput: ~100 Mbps (full utilization)
Fair share per connection: ~10 Mbps each
```

### Historical Context

**1980s**: Internet congestion collapses
- Symptom: Throughput drops from Mbps to kbps
- Cause: No congestion control

**1988**: Van Jacobson introduces TCP congestion control
- Slow start
- Congestion avoidance
- Fast retransmit
- Fast recovery

**Result**: Internet survives and thrives

**Evolution**:
- **1990s**: Reno (standard algorithm for decades)
- **2000s**: CUBIC (default in Linux since 2.6.19)
- **2010s**: BBR (Google's bottleneck bandwidth and RTT algorithm)
- **2020s**: BBRv2, BBRv3, eBPF-based custom algorithms

### Congestion Window vs Receive Window

TCP's actual sending rate is limited by **both** windows:

```c
/* Effective window */
effective_window = min(cwnd, rwnd)

where:
  cwnd = congestion window (controlled by congestion control)
  rwnd = receive window (advertised by receiver, flow control)
```

**Example**:

```
State: cwnd = 100 packets, rwnd = 200 packets
  → Can send 100 packets (cwnd is limiting)

State: cwnd = 200 packets, rwnd = 50 packets
  → Can send 50 packets (rwnd is limiting, receiver buffer full)

Typical bulk transfer:
  - Start: cwnd is limiting (small initial cwnd)
  - Steady state: cwnd is limiting (network bottleneck)
  - Buffer full: rwnd is limiting (application not reading fast enough)
```

### Key Metrics

```c
/* From include/linux/tcp.h */

struct tcp_sock {
    /* Congestion control state */
    u32  snd_cwnd;         /* Congestion window (in packets) */
    u32  snd_ssthresh;     /* Slow start threshold */
    u32  snd_cwnd_cnt;     /* Counter for congestion window adjustment */
    u32  snd_cwnd_clamp;   /* Do not allow snd_cwnd to grow above this */
    
    /* Congestion control tracking */
    u32  prior_cwnd;       /* Congestion window before reduction */
    u32  prr_delivered;    /* Packets delivered during recovery */
    u32  prr_out;          /* Packets sent during recovery */
    
    /* Congestion control algorithm */
    const struct tcp_congestion_ops *ca_ops;
    
    /* Algorithm-specific state (opaque) */
    union tcp_cc_info *icsk_ca_priv;
    
    /* ... */
};
```

**Visual representation**:

```
Congestion window over time:

cwnd (packets)
    ^
100 |                     ╱╲
    |                    ╱  ╲
    |                   ╱    ╲
 80 |                  ╱      ╲    ╱
    |                 ╱        ╲  ╱
 60 |                ╱          ╲╱
    |               ╱          (loss)
 40 |            ╱╱
    |         ╱╱
 20 |      ╱╱
    |   ╱╱
  0 |__╱_________________________________> time
      |    |          |         |
      SS   CA         Loss      Recovery

SS = Slow Start (exponential growth)
CA = Congestion Avoidance (linear growth)
Loss = Packet loss detected (cwnd reduced)
Recovery = Retransmit and grow again
```

### Congestion Signals

TCP detects congestion through:

1. **Packet Loss** (traditional signal)
   - Timeout: Severe congestion
   - Duplicate ACKs: Mild congestion (network still delivering packets)

2. **ECN (Explicit Congestion Notification)** (RFC 3168)
   - Routers mark packets instead of dropping
   - Allows early congestion response without loss

3. **Delay** (modern signal)
   - RTT increase indicates queue buildup
   - Used by BBR and delay-based algorithms

```c
/* From include/uapi/linux/tcp.h */

/* Congestion control states */
enum tcp_ca_state {
    TCP_CA_Open = 0,       /* Normal state, no congestion */
    TCP_CA_Disorder = 1,   /* Reordering detected, not yet loss */
    TCP_CA_CWR = 2,        /* Congestion window reduced (ECN response) */
    TCP_CA_Recovery = 3,   /* Fast recovery (after 3 dupacks) */
    TCP_CA_Loss = 4,       /* Timeout, severe congestion */
};
```

---

## Pluggable Congestion Control Framework

Linux provides a pluggable framework allowing multiple congestion control algorithms to coexist. Applications or administrators can select the algorithm per connection or system-wide.

### The `tcp_congestion_ops` Structure

Every congestion control algorithm implements this interface:

```c
/* From include/net/tcp.h */

struct tcp_congestion_ops {
    /* Name of the algorithm (used for selection) */
    char name[TCP_CA_NAME_MAX];
    
    /* Owner module */
    struct module *owner;
    
    /* Required callbacks */
    
    /* Initialize congestion control state for new connection */
    void (*init)(struct sock *sk);
    
    /* Release congestion control state */
    void (*release)(struct sock *sk);
    
    /* Handle acknowledgment received */
    void (*cong_control)(struct sock *sk, const struct rate_sample *rs);
    
    /* Alternative to cong_control: traditional cwnd-based */
    void (*cong_avoid)(struct sock *sk, u32 ack, u32 acked);
    
    /* Set congestion window after loss/timeout */
    u32 (*ssthresh)(struct sock *sk);
    
    /* Undo cwnd reduction (spurious timeout detected) */
    void (*undo_cwnd)(struct sock *sk);
    
    /* Optional callbacks */
    
    /* Called when entering/exiting congestion state */
    void (*set_state)(struct sock *sk, u8 new_state);
    
    /* Called when ACKed packets removed from queue */
    void (*pkts_acked)(struct sock *sk, const struct ack_sample *sample);
    
    /* Return current cwnd */
    u32 (*get_cwnd)(struct sock *sk);
    
    /* Handle ECN (Explicit Congestion Notification) */
    void (*cwnd_event)(struct sock *sk, enum tcp_ca_event event);
    
    /* Get algorithm-specific info for diagnostics */
    size_t (*get_info)(struct sock *sk, u32 ext, int *attr,
                       union tcp_cc_info *info);
    
    /* Flags */
    u32 flags;
};

/* Flags for tcp_congestion_ops */
#define TCP_CONG_NON_RESTRICTED  0x1  /* Available to non-privileged users */
#define TCP_CONG_RTT_STAMP       0x2  /* Needs RTT measurements */
#define TCP_CONG_NEEDS_ECN       0x4  /* Requires ECN support */
```

**Key callbacks**:

| Callback | When Called | Purpose |
|----------|-------------|---------|
| `init()` | Connection established | Initialize algorithm state |
| `release()` | Connection closed | Free algorithm state |
| `cong_control()` | ACK received | Main congestion control logic (modern) |
| `cong_avoid()` | ACK received in open state | Adjust cwnd (traditional) |
| `ssthresh()` | Loss detected | Calculate new slow start threshold |
| `set_state()` | State transition | React to congestion state changes |
| `pkts_acked()` | Packets ACKed | Update RTT estimates, track delivery |
| `cwnd_event()` | ECN or other event | Handle explicit congestion signals |

### Algorithm Registration

```c
/* From net/ipv4/tcp_cong.c */

/* List of registered congestion control algorithms */
static LIST_HEAD(tcp_cong_list);
static DEFINE_SPINLOCK(tcp_cong_list_lock);

/* Register new congestion control algorithm */
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    int ret = 0;
    
    /* Validate algorithm */
    if (!ca->ssthresh || !ca->undo_cwnd ||
        !(ca->cong_avoid || ca->cong_control)) {
        pr_err("%s does not implement required ops\n", ca->name);
        return -EINVAL;
    }
    
    spin_lock(&tcp_cong_list_lock);
    
    /* Check for duplicate name */
    if (tcp_ca_find(ca->name)) {
        pr_notice("%s already registered\n", ca->name);
        ret = -EEXIST;
    } else {
        list_add_tail_rcu(&ca->list, &tcp_cong_list);
        pr_info("TCP %s registered\n", ca->name);
    }
    
    spin_unlock(&tcp_cong_list_lock);
    
    return ret;
}
EXPORT_SYMBOL_GPL(tcp_register_congestion_control);

/* Unregister congestion control algorithm */
void tcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
    spin_lock(&tcp_cong_list_lock);
    list_del_rcu(&ca->list);
    spin_unlock(&tcp_cong_list_lock);
    
    /* Wait for grace period (RCU) */
    synchronize_rcu();
}
EXPORT_SYMBOL_GPL(tcp_unregister_congestion_control);

/* Find algorithm by name */
static struct tcp_congestion_ops *tcp_ca_find(const char *name)
{
    struct tcp_congestion_ops *e;
    
    list_for_each_entry_rcu(e, &tcp_cong_list, list) {
        if (strcmp(e->name, name) == 0)
            return e;
    }
    
    return NULL;
}
```

### Algorithm Selection

Multiple ways to select congestion control algorithm:

#### 1. System-wide default

```bash
# Set default algorithm
sysctl -w net.ipv4.tcp_congestion_control=cubic

# View available algorithms
sysctl net.ipv4.tcp_available_congestion_control
# net.ipv4.tcp_available_congestion_control = reno cubic bbr

# View allowed algorithms (non-root)
sysctl net.ipv4.tcp_allowed_congestion_control
# net.ipv4.tcp_allowed_congestion_control = reno cubic
```

#### 2. Per-socket selection

```c
/* From application code */

int sockfd = socket(AF_INET, SOCK_STREAM, 0);

/* Set congestion control algorithm */
const char *algo = "bbr";
setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, algo, strlen(algo));
```

#### 3. Per-route selection

```bash
# Set algorithm for specific route
ip route change 10.0.0.0/8 via 192.168.1.1 dev eth0 congctl cubic
```

**Selection logic in kernel**:

```c
/* From net/ipv4/tcp_cong.c */

/* Assign congestion control algorithm to socket */
void tcp_assign_congestion_control(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    const struct tcp_congestion_ops *ca;
    
    rcu_read_lock();
    
    /* Check if socket already has algorithm assigned */
    if (icsk->icsk_ca_ops != &tcp_init_congestion_ops)
        goto out;
    
    /* Try per-route algorithm */
    ca = tcp_ca_find_route(sk);
    if (ca)
        goto assign;
    
    /* Use default algorithm */
    ca = rcu_dereference(tcp_default_congestion_ops);
    if (!ca)
        ca = &tcp_reno_ops;  /* Fallback to Reno */
    
assign:
    /* Ensure module is loaded and usable */
    if (!try_module_get(ca->owner))
        ca = &tcp_reno_ops;
    
    icsk->icsk_ca_ops = ca;
    
    /* Initialize algorithm */
    if (ca->init)
        ca->init(sk);
    
out:
    rcu_read_unlock();
}
```

### Congestion Control Invocation

The framework calls congestion control callbacks at appropriate times:

```c
/* From net/ipv4/tcp_input.c */

/* Main entry point: ACK received */
static void tcp_cong_control(struct sock *sk, u32 ack, u32 acked_sacked,
                              int flag, const struct rate_sample *rs)
{
    const struct inet_connection_sock *icsk = inet_csk(sk);
    
    /* Call algorithm's congestion control callback */
    if (icsk->icsk_ca_ops->cong_control) {
        /* Modern callback (rate-based, like BBR) */
        icsk->icsk_ca_ops->cong_control(sk, rs);
    } else {
        /* Traditional callback (cwnd-based, like CUBIC) */
        tcp_cong_avoid(sk, ack, acked_sacked);
    }
}

/* Traditional congestion avoidance (cwnd-based algorithms) */
static void tcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    const struct inet_connection_sock *icsk = inet_csk(sk);
    
    /* Invoke algorithm's cong_avoid callback */
    icsk->icsk_ca_ops->cong_avoid(sk, ack, acked);
}
```

**Call flow**:

```
Application sends data
         ↓
tcp_sendmsg()
         ↓
tcp_write_xmit()  (transmit packets, limited by cwnd)
         ↓
   ... network ...
         ↓
ACK received
         ↓
tcp_ack()
         ↓
tcp_clean_rtx_queue()  (remove ACKed packets)
         ↓
tcp_cong_control()
         ↓
    ca_ops->cong_control() or ca_ops->cong_avoid()
         ↓
Update cwnd based on algorithm logic
         ↓
tcp_write_xmit()  (send more data if cwnd allows)
```

### State Transitions

Congestion control algorithms receive state change notifications:

```c
/* From net/ipv4/tcp_input.c */

void tcp_set_ca_state(struct sock *sk, const u8 ca_state)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    
    /* Notify algorithm of state change */
    if (icsk->icsk_ca_ops->set_state)
        icsk->icsk_ca_ops->set_state(sk, ca_state);
    
    icsk->icsk_ca_state = ca_state;
}
```

**State transition diagram**:

```
        ┌─────────────┐
        │   CA_Open   │ ◄─┐ Normal transmission
        │  (Normal)   │   │
        └─────────────┘   │
              │           │
              │ (reordering)
              ↓           │
        ┌─────────────┐   │
        │ CA_Disorder │   │
        │ (Reorder)   │   │
        └─────────────┘   │
              │           │
              │ (3 dupacks / SACK)
              ↓           │
        ┌─────────────┐   │
        │ CA_Recovery │   │ All data ACKed
        │(Fast Recov) │───┘
        └─────────────┘
              │
              │ (timeout)
              ↓
        ┌─────────────┐
        │   CA_Loss   │───┐ RTO expires
        │  (Timeout)  │   │ Data ACKed
        └─────────────┘   │
              │           │
              └───────────┘

        ┌─────────────┐
        │   CA_CWR    │ ECN response
        │(ECN reduce) │
        └─────────────┘
```

### Rate Sampling for Modern Algorithms

Modern algorithms (like BBR) need delivery rate measurements:

```c
/* From include/net/tcp.h */

/* Rate sample delivered to congestion control */
struct rate_sample {
    u64  prior_mstamp;     /* Timestamp of prior packet */
    u32  prior_delivered;  /* Packets delivered before this sample */
    s32  delivered;        /* Packets delivered in this sample */
    long interval_us;      /* Time interval for this sample */
    u32  snd_interval_us;  /* Send interval */
    u32  rcv_interval_us;  /* Receive interval */
    long rtt_us;           /* RTT of this sample */
    int  losses;           /* Packets lost */
    u32  acked_sacked;     /* Packets ACKed */
    u32  prior_in_flight;  /* Packets in flight before ACK */
    bool is_app_limited;   /* Was send limited by application? */
    bool is_retrans;       /* Included retransmitted packets? */
};
```

**Rate sampling logic**:

```c
/* From net/ipv4/tcp_rate.c */

void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
                   bool is_sack_reneg, struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u64 now = tcp_mstamp_us(tp);
    
    /* Calculate delivery interval */
    rs->prior_delivered = tp->delivered;
    rs->delivered = delivered;
    rs->interval_us = now - tp->first_tx_mstamp;
    
    /* Calculate delivery rate */
    if (rs->interval_us > 0) {
        rs->delivery_rate = (rs->delivered * USEC_PER_SEC) / rs->interval_us;
    }
    
    /* Capture RTT */
    rs->rtt_us = tcp_stamp_us_delta(now, tp->tcp_mstamp);
    
    /* Capture losses */
    rs->losses = lost;
    
    /* Application limited? */
    rs->is_app_limited = tp->app_limited ? 1 : 0;
}
```

### Monitoring Congestion Control

```bash
# View current algorithm per connection
ss -tin

# Example output:
# State    Recv-Q  Send-Q  Local:Port    Peer:Port
# ESTAB    0       0       10.0.0.1:22   10.0.0.2:54321
#  cubic wscale:7,7 rto:204 rtt:3.5/1.75 ato:40 mss:1448 pmtu:1500
#  rcvmss:1448 advmss:1448 cwnd:10 ssthresh:7 bytes_acked:1234 bytes_received:5678
#  segs_out:15 segs_in:12 data_segs_out:10 data_segs_in:8
#  send 33.1Mbps lastsnd:204 lastrcv:204 lastack:204 pacing_rate 39.7Mbps
#  delivery_rate 28.8Mbps app_limited

# Key metrics:
#   cubic: Algorithm in use
#   cwnd:10: Congestion window (10 packets)
#   ssthresh:7: Slow start threshold
#   pacing_rate: Sending rate limit
#   delivery_rate: Measured delivery rate

# Get algorithm-specific info via TCP_INFO
struct tcp_info info;
socklen_t len = sizeof(info);
getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &info, &len);

printf("cwnd: %u\n", info.tcpi_snd_cwnd);
printf("ssthresh: %u\n", info.tcpi_snd_ssthresh);
printf("rtt: %u us\n", info.tcpi_rtt);
printf("delivery_rate: %llu bps\n", info.tcpi_delivery_rate);
```

---


## Built-in Congestion Control Algorithms

Linux includes several congestion control algorithms. Let's examine the major ones.

### TCP Reno (Classic Algorithm)

Reno was the standard algorithm for decades. While superseded by CUBIC, it's still available and serves as a reference implementation.

**Core principles**:

1. **Slow Start**: Exponential growth until reaching `ssthresh`
2. **Congestion Avoidance**: Linear growth (AIMD - Additive Increase, Multiplicative Decrease)
3. **Fast Retransmit**: Retransmit after 3 duplicate ACKs
4. **Fast Recovery**: Inflate window during recovery

```c
/* From net/ipv4/tcp_cong.c */

/* Reno congestion control operations */
struct tcp_congestion_ops tcp_reno = {
    .name = "reno",
    .owner = THIS_MODULE,
    .ssthresh = tcp_reno_ssthresh,
    .cong_avoid = tcp_reno_cong_avoid,
    .undo_cwnd = tcp_reno_undo_cwnd,
};

/* Calculate slow start threshold after loss */
u32 tcp_reno_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    
    /* Reduce cwnd to half (multiplicative decrease) */
    return max(tp->snd_cwnd >> 1U, 2U);
}
EXPORT_SYMBOL_GPL(tcp_reno_ssthresh);

/* Undo cwnd reduction (spurious timeout) */
u32 tcp_reno_undo_cwnd(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    
    /* Restore previous cwnd */
    return max(tp->snd_cwnd, tp->prior_cwnd);
}
EXPORT_SYMBOL_GPL(tcp_reno_undo_cwnd);

/* Congestion avoidance logic */
void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    
    /* Check if in slow start or congestion avoidance */
    if (tcp_in_slow_start(tp)) {
        /* Slow start: Exponential growth */
        /* Increase cwnd by 1 for each ACK (doubles per RTT) */
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }
    
    /* Congestion avoidance: Linear growth */
    /* Increase cwnd by 1/cwnd for each ACK (adds 1 per RTT) */
    tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}
EXPORT_SYMBOL_GPL(tcp_reno_cong_avoid);

/* From net/ipv4/tcp_cong.c */

/* Slow start helper: Increase cwnd exponentially */
u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
    u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);
    
    acked -= cwnd - tp->snd_cwnd;
    tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
    
    return acked;
}
EXPORT_SYMBOL_GPL(tcp_slow_start);

/* Congestion avoidance helper: Increase cwnd linearly */
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
    /* Increase by 1 MSS per RTT */
    /* w = target window, acked = segments ACKed */
    
    if (tp->snd_cwnd_cnt >= w) {
        tp->snd_cwnd_cnt = 0;
        tp->snd_cwnd++;
    }
    
    tp->snd_cwnd_cnt += acked;
    if (tp->snd_cwnd_cnt >= w) {
        u32 delta = tp->snd_cwnd_cnt / w;
        tp->snd_cwnd_cnt -= delta * w;
        tp->snd_cwnd += delta;
    }
    
    tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}
EXPORT_SYMBOL_GPL(tcp_cong_avoid_ai);
```

**Reno behavior**:

```
Time (RTTs):  0   1   2   3   4   5   6   7   8   9  10
cwnd:         2   4   8  16  32  64  48  49  50  51  52
                  └─ Slow Start ─┘│  └─ Congestion Avoidance ─┘
                                Loss
                                (ssthresh = 32)

Slow Start (cwnd < ssthresh):
  - cwnd += 1 per ACK
  - Doubles per RTT
  - Exponential growth

Congestion Avoidance (cwnd >= ssthresh):
  - cwnd += 1/cwnd per ACK
  - Adds 1 per RTT
  - Linear growth (AIMD)

Loss:
  - ssthresh = cwnd / 2
  - cwnd = ssthresh (fast recovery)
  - Resume congestion avoidance
```

**Limitations**:

- **Slow bandwidth probing**: Linear increase is conservative
- **Unfair with high RTT**: Connections with longer RTT grow slower
- **Poor on high-speed networks**: Takes forever to reach high cwnd

---

### TCP CUBIC (Default since 2006)

CUBIC is the default congestion control algorithm in Linux since kernel 2.6.19. It was designed for high-speed, high-latency networks.

**Key innovation**: cwnd growth is a **cubic function** of time since last loss, independent of RTT.

```c
/* From net/ipv4/tcp_cubic.c */

/* CUBIC state */
struct bictcp {
    u32  cnt;                   /* Increase cwnd by 1 after this many ACKs */
    u32  last_max_cwnd;         /* Last maximum cwnd before reduction */
    u32  last_cwnd;             /* Last cwnd */
    u32  last_time;             /* Time when cwnd was last updated */
    u32  epoch_start;           /* Beginning of epoch (time since last loss) */
    u32  origin_point;          /* Origin point for cubic function */
    u32  d_min;                 /* Minimum RTT (in microseconds) */
    u32  W_tcp;                 /* cwnd for Reno-equivalent growth */
    u32  K;                     /* Time to reach W_max (inflection point) */
    u32  ack_cnt;               /* Number of ACKs */
    u32  tcp_cwnd;              /* Estimated cwnd in Reno mode */
    u8   sample_cnt;            /* Sample counter for RTT */
    u8   found;                 /* Whether we found W_max */
    u32  round_start;           /* Round start time */
    u32  end_seq;               /* End sequence of the round */
    u32  last_ack;              /* Last ACK time */
    u32  curr_rtt;              /* Current RTT estimate */
};

/* CUBIC congestion control operations */
static struct tcp_congestion_ops cubictcp __read_mostly = {
    .init       = bictcp_init,
    .ssthresh   = bictcp_recalc_ssthresh,
    .cong_avoid = bictcp_cong_avoid,
    .set_state  = bictcp_state,
    .undo_cwnd  = tcp_reno_undo_cwnd,
    .cwnd_event = bictcp_cwnd_event,
    .pkts_acked = bictcp_acked,
    .owner      = THIS_MODULE,
    .name       = "cubic",
};
```

**CUBIC function**:

```
W(t) = C(t - K)³ + W_max

where:
  W(t)   = cwnd at time t
  C      = scaling constant (0.4)
  t      = time since last cwnd reduction (epoch start)
  K      = time to reach W_max (cube root of (W_max * β / C))
  W_max  = cwnd just before last reduction
  β      = multiplicative decrease factor (0.7 for CUBIC, vs 0.5 for Reno)
```

**Key implementation**:

```c
/* From net/ipv4/tcp_cubic.c */

/* CUBIC congestion avoidance */
static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);
    
    /* Slow start */
    if (tcp_in_slow_start(tp)) {
        if (hystart && after(ack, ca->end_seq))
            bictcp_hystart_reset(sk);
        
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }
    
    /* Congestion avoidance */
    bictcp_update(ca, tp->snd_cwnd, acked);
    tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

/* Update CUBIC state and calculate cnt (ACKs needed for cwnd increment) */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
    u32 delta, bic_target, max_cnt;
    u64 offs, t;
    
    /* Calculate time since last congestion event */
    ca->ack_cnt += acked;
    
    if (ca->last_cwnd == cwnd &&
        (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
        return;
    
    /* Update time */
    ca->last_cwnd = cwnd;
    ca->last_time = tcp_jiffies32;
    
    if (ca->epoch_start == 0) {
        /* First ACK after congestion event */
        ca->epoch_start = tcp_jiffies32;
        ca->ack_cnt = acked;
        ca->tcp_cwnd = cwnd;
        
        if (ca->last_max_cwnd <= cwnd) {
            /* Fast convergence: Reset W_max if we're back to it quickly */
            ca->K = 0;
            ca->origin_point = cwnd;
        } else {
            /* Compute K (time to reach W_max) */
            /* K = cubic_root((W_max - cwnd) / C) */
            ca->K = cubic_root(cube_factor * (ca->last_max_cwnd - cwnd));
            ca->origin_point = ca->last_max_cwnd;
        }
    }
    
    /* t = time since epoch start (in ms) */
    t = (s32)(tcp_jiffies32 - ca->epoch_start) * USEC_PER_JIFFY;
    
    /* Calculate CUBIC target: W_cubic(t) = C(t-K)³ + W_max */
    if (t < ca->K) {
        /* t < K: Concave region (below W_max) */
        offs = ca->K - t;
    } else {
        /* t >= K: Convex region (above W_max) */
        offs = t - ca->K;
    }
    
    /* delta = |C(t-K)³| */
    delta = (cube_rtt_scale * offs * offs * offs) >> (10 + 3 * BICTCP_HZ);
    
    if (t < ca->K) {
        /* Concave: bic_target = origin_point - delta */
        bic_target = ca->origin_point - delta;
    } else {
        /* Convex: bic_target = origin_point + delta */
        bic_target = ca->origin_point + delta;
    }
    
    /* Clamp bic_target */
    bic_target = max(bic_target, 2U);
    
    /* CUBIC vs Reno-friendly comparison */
    if (bic_target > cwnd) {
        /* CUBIC is faster: Use CUBIC target */
        ca->cnt = cwnd / (bic_target - cwnd);
    } else {
        /* Reno is faster: Use Reno-friendly target for fairness */
        ca->tcp_cwnd = max(ca->tcp_cwnd + (3 * acked) / (2 * ca->tcp_cwnd), 2U);
        ca->cnt = max(cwnd / (ca->tcp_cwnd - cwnd), 2U);
    }
}
```

**CUBIC behavior**:

```
cwnd over time (after loss at t=0):

cwnd
 ^
 │                          ╱
 │                        ╱
W_max ├─────────────────╱─────────
 │                    ╱ │
 │                  ╱   │ Convex (aggressive probing)
 │                ╱     │
 │              ╱       │
 │            ╱  │      │
 │          ╱    │      │
 │        ╱      │ Concave (cautious, recovering to W_max)
 │      ╱        │      │
 │    ╱          │      │
 │  ╱            │      │
 │╱              │      │
0├───────────────┼──────┼─────────> time
 0               K   (time to W_max)

Phases:
1. t < K (Concave): Cautiously approach previous W_max
2. t = K: Reach W_max (inflection point)
3. t > K (Convex): Aggressively probe for more bandwidth

Key property: Growth rate independent of RTT!
  - High-RTT and low-RTT flows grow at same rate
  - Fairer bandwidth sharing
```

**Fast Convergence**:

```c
/* Recalculate ssthresh (slow start threshold) */
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);
    
    ca->epoch_start = 0;  /* End of epoch */
    
    /* Fast convergence */
    if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence) {
        /* Reduce W_max if we lost before reaching it */
        ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
                            / (2 * BICTCP_BETA_SCALE);
    } else {
        ca->last_max_cwnd = tp->snd_cwnd;
    }
    
    /* Return new ssthresh (β * cwnd, where β = 0.7) */
    return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}
```

**HyStart (Hybrid Slow Start)**:

CUBIC includes HyStart to exit slow start earlier (before loss):

```c
/* HyStart: Exit slow start based on delay increase */
static void bictcp_acked(struct sock *sk, const struct ack_sample *sample)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);
    u32 delay;
    
    /* Only in slow start */
    if (!tcp_in_slow_start(tp))
        return;
    
    /* Measure RTT */
    delay = sample->rtt_us;
    if (delay == 0)
        return;
    
    /* First RTT sample of round */
    if (ca->curr_rtt == 0)
        ca->curr_rtt = delay;
    
    /* Check for delay increase (queue buildup) */
    if (delay > ca->curr_rtt + HYSTART_DELAY_THRESH(ca->curr_rtt >> 3)) {
        /* Delay increased: Exit slow start */
        tp->snd_ssthresh = tp->snd_cwnd;
    }
    
    /* Track minimum RTT */
    if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
        if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
            ca->curr_rtt = delay;
        ca->sample_cnt++;
    }
}
```

**CUBIC advantages**:

- **RTT-independent**: Fair bandwidth sharing regardless of RTT
- **Fast convergence**: Quickly reaches optimal bandwidth
- **Scalable**: Works well on high-speed networks (10+ Gbps)
- **Better than Reno**: 10-30% throughput improvement in most scenarios

---

### TCP BBR (Bottleneck Bandwidth and RTT)

BBR (developed by Google, available since Linux 4.9) represents a paradigm shift: instead of reacting to **loss**, it proactively models the network by measuring **bandwidth and RTT**.

**Core insight**: The network has two constraints:
1. **Bottleneck bandwidth** (BtlBw): Maximum throughput
2. **Round-trip propagation time** (RTprop): Minimum RTT without queueing

**Optimal operating point**:

```
             Bandwidth
                ^
                │     ╱────────────  BtlBw (bottleneck bandwidth)
                │    ╱
                │   ╱
                │  │ Optimal point:
                │  │ cwnd = BtlBw × RTprop (BDP)
                │ ╱
                │╱
                └─────────────────> Queue depth
                  RTprop  (min RTT)

Traditional algorithms operate here ──────> (full buffer, high latency)
BBR operates here ──────────────────────> (near-empty buffer, low latency)
```

**BBR state machine**:

```
┌──────────────┐
│   STARTUP    │  Exponential search for BtlBw
│ (2x/RTT)     │
└──────────────┘
       │
       ↓ (BtlBw plateau detected)
┌──────────────┐
│   DRAIN      │  Drain queue built up during STARTUP
│              │
└──────────────┘
       │
       ↓ (inflight ≈ BDP)
┌──────────────┐  ←───────────────┐
│  PROBE_BW    │  Cycle pacing:   │ (10 RTT cycles)
│              │  0.75x, 1x, 1x,  │
│              │  1x, 1.25x       │
└──────────────┘  ─────────────────┘
       │
       ↓ (idle or RTT increases)
┌──────────────┐
│  PROBE_RTT   │  Reduce cwnd to 4 packets
│              │  Measure true RTprop
└──────────────┘
       │
       └────────────> Back to PROBE_BW
```

**Key data structures**:

```c
/* From net/ipv4/tcp_bbr.c */

/* BBR state */
struct bbr {
    u32  min_rtt_us;            /* Minimum RTT in this window */
    u32  min_rtt_stamp;         /* Timestamp of min_rtt_us */
    u32  next_rtt_delivered;    /* Delivered count at next RTT sample */
    u64  bw_lo;                 /* Lower bound on bottleneck bandwidth */
    u64  bw_hi;                 /* Upper bound on bottleneck bandwidth */
    u32  inflight_lo;           /* Lower bound on inflight */
    u32  inflight_hi;           /* Upper bound on inflight */
    u32  extra_acked_delivered; /* Delivered count for extra ACKs */
    u32  extra_acked_win_rtts;  /* Age of extra_acked */
    u32  extra_acked;           /* Max recent extra ACKed in epoch */
    u16  extra_acked_win_idx;   /* Current index in extra_acked */
    u16  ack_epoch_mstamp;      /* Timestamp of ack epoch */
    u16  ack_epoch_acked;       /* Bytes ACKed in ack epoch */
    u32  has_seen_rtt:1,        /* Have we seen an RTT sample? */
         unused_b:5,
         round_start:1,         /* Is this round-trip start? */
         idle_restart:1,        /* Restarting after idle? */
         probe_rtt_round_done:1,/* Finished PROBE_RTT round? */
         unused:15,
         lt_is_sampling:1,      /* Long-term sampling active? */
         lt_rtt_cnt:7,          /* Round trips in long-term sample */
         lt_use_bw:1;           /* Use long-term bw estimate? */
    u32  prior_cwnd;            /* Prior cwnd for undo */
    u32  full_bw;               /* Full bandwidth estimate */
    u32  full_bw_reached:1,     /* Reached full bandwidth? */
         full_bw_cnt:2,         /* Number of rounds without growth */
         cycle_mstamp:1,        /* Cycle timestamp */
         cycle_idx:3,           /* Current pacing gain cycle index */
         unused_c:25;
    u32  mode:3,                /* Current BBR mode (STARTUP, DRAIN, etc.) */
         prev_ca_state:3,       /* Previous congestion avoidance state */
         packet_conservation:1, /* In packet conservation mode? */
         restore_cwnd:1,        /* Restore cwnd after recovery? */
         round_start_bw:1,      /* Starting new bw round? */
         unused_d:23;
    u32  lt_epoch_start;        /* Long-term sampling epoch start */
    u32  lt_bw;                 /* Long-term bandwidth estimate */
    u32  pacing_gain:11,        /* Current pacing gain (1024 = 1.0x) */
         cwnd_gain:11,          /* Current cwnd gain */
         full_bw_cnt:3,
         startup_gain:11;       /* Gain in STARTUP mode */
    u32  target_cwnd;           /* Target cwnd based on BDP */
    u32  probe_rtt_done_stamp;  /* End time for PROBE_RTT */
    u32  probe_rtt_min_us;      /* Min RTT during PROBE_RTT */
    u32  probe_rtt_min_stamp;   /* Timestamp of probe_rtt_min_us */
    u32  prior_rcv_nxt;         /* Prior rcv_nxt for loss detection */
    u32  try_fast_path:1,       /* Can we use fast path? */
         unused_e:31;
};

static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
    .flags      = TCP_CONG_NON_RESTRICTED,
    .name       = "bbr",
    .owner      = THIS_MODULE,
    .init       = bbr_init,
    .cong_control = bbr_main,      /* Modern callback (not cong_avoid) */
    .sndbuf_expand = bbr_sndbuf_expand,
    .undo_cwnd  = bbr_undo_cwnd,
    .cwnd_event = bbr_cwnd_event,
    .ssthresh   = bbr_ssthresh,
    .min_tso_segs = bbr_min_tso_segs,
    .get_info   = bbr_get_info,
    .set_state  = bbr_set_state,
};
```

**BBR main logic**:

```c
/* From net/ipv4/tcp_bbr.c */

/* Main BBR congestion control (called on each ACK) */
static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bbr *bbr = inet_csk_ca(sk);
    u32 bw;
    
    /* Update model: bandwidth and RTT */
    bbr_update_bw(sk, rs);
    bbr_update_ack_aggregation(sk, rs);
    bbr_update_cycle_phase(sk, rs);
    bbr_check_full_bw_reached(sk, rs);
    bbr_check_drain(sk, rs);
    bbr_update_min_rtt(sk, rs);
    bbr_update_gains(sk);
    
    /* Set pacing rate: BtlBw × pacing_gain */
    bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);
    
    /* Set cwnd: BDP × cwnd_gain */
    bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

/* Update bottleneck bandwidth estimate */
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bbr *bbr = inet_csk_ca(sk);
    u64 bw;
    
    /* Skip if no delivery rate sample */
    if (rs->delivered < 0 || rs->interval_us <= 0)
        return;
    
    /* Calculate delivery rate: delivered / interval */
    bw = div64_long((u64)rs->delivered * BW_UNIT,
                    rs->interval_us);
    
    /* Keep max bandwidth over last 10 RTTs */
    if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
        /* Update bandwidth estimate (windowed max filter) */
        bbr_lt_bw_sampling(sk, rs);
        bbr->bw_hi[1] = bbr->bw_hi[0];
        bbr->bw_hi[0] = max(bw, bbr->bw_hi[0]);
    }
}

/* Update minimum RTT estimate */
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bbr *bbr = inet_csk_ca(sk);
    bool filter_expired;
    
    /* Track min RTT over 10 seconds */
    filter_expired = after(tcp_jiffies32,
                          bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);
    
    if (rs->rtt_us >= 0 &&
        (rs->rtt_us < bbr->min_rtt_us || filter_expired)) {
        bbr->min_rtt_us = rs->rtt_us;
        bbr->min_rtt_stamp = tcp_jiffies32;
    }
    
    /* Probe RTT if min RTT estimate is getting stale */
    if (filter_expired && !bbr->idle_restart &&
        bbr->mode != BBR_PROBE_RTT) {
        /* Enter PROBE_RTT mode */
        bbr->mode = BBR_PROBE_RTT;
        bbr->probe_rtt_done_stamp = 0;
        bbr_save_cwnd(sk);
    }
    
    if (bbr->mode == BBR_PROBE_RTT) {
        /* Sample minimum RTT with small inflight */
        if (bbr->probe_rtt_done_stamp == 0 &&
            tcp_packets_in_flight(tp) <= bbr_probe_rtt_cwnd(sk)) {
            /* Reached target cwnd: Start timing */
            bbr->probe_rtt_done_stamp = tcp_jiffies32 +
                                        msecs_to_jiffies(bbr_probe_rtt_mode_ms);
            bbr->probe_rtt_round_done = 0;
            bbr->next_rtt_delivered = tp->delivered;
        } else if (bbr->probe_rtt_done_stamp) {
            if (bbr->round_start)
                bbr->probe_rtt_round_done = 1;
            
            if (bbr->probe_rtt_round_done &&
                after(tcp_jiffies32, bbr->probe_rtt_done_stamp)) {
                /* PROBE_RTT done: Return to PROBE_BW */
                bbr->min_rtt_stamp = tcp_jiffies32;
                bbr->restore_cwnd = 1;
                bbr_reset_mode(sk);
            }
        }
    }
}

/* Set pacing rate based on BtlBw estimate */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, u32 gain)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bbr *bbr = inet_csk_ca(sk);
    u64 rate = bw;
    
    /* rate = BtlBw × gain */
    rate = bbr_bw_to_pacing_rate(sk, bw, gain);
    
    if (bbr->pacing_gain != BBR_UNIT)
        rate = bbr_rate_bytes_per_sec(sk, rate, gain);
    
    /* Apply rate */
    sk->sk_pacing_rate = min_t(u64, rate, sk->sk_max_pacing_rate);
}

/* Set cwnd based on BDP estimate */
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
                          u32 acked, u32 bw, u32 gain)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bbr *bbr = inet_csk_ca(sk);
    u32 cwnd, target_cwnd;
    
    /* Calculate BDP: BtlBw × RTprop */
    target_cwnd = bbr_bdp(sk, bw, gain);
    
    /* Add extra for aggregation */
    target_cwnd += bbr_extra_acked(sk);
    
    /* Clamp to reasonable range */
    target_cwnd = bbr_quantization_budget(sk, target_cwnd);
    
    /* Apply target */
    if (bbr_full_bw_reached(sk)) {
        /* Full bandwidth reached: Moderate cwnd growth */
        cwnd = min(target_cwnd, tp->snd_cwnd + acked);
    } else if (tp->snd_cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND) {
        /* Startup: Aggressive growth */
        cwnd = tp->snd_cwnd + acked;
    } else {
        cwnd = max(tp->snd_cwnd, target_cwnd);
    }
    
    tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
    
    /* Bound cwnd by ssthresh in loss recovery */
    if (in_loss_recovery)
        tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);
}
```

**BBR modes explained**:

```
1. STARTUP (Exponential search):
   - pacing_gain = 2.89x (≈ 2/ln(2), grow bandwidth estimate)
   - cwnd_gain = 2.0x
   - Double sending rate each RTT
   - Exit: Bandwidth estimate stops growing (3 rounds with < 25% growth)

2. DRAIN (Drain queue):
   - pacing_gain = 1/2.89x (inverse of STARTUP)
   - cwnd_gain = 2.0x
   - Drain packets queued during STARTUP
   - Exit: inflight ≤ BDP

3. PROBE_BW (Steady state, 5-phase cycle):
   - Phase 0: 1.25x (probe for more bandwidth)
   - Phase 1-3: 1.0x (cruise at BDP)
   - Phase 4: 0.75x (drain queue, refresh min RTT)
   - Each phase: 2-3 RTTs
   - Cycle repeats every 10 RTTs

4. PROBE_RTT (Refresh min RTT):
   - cwnd = 4 packets (minimum inflight)
   - Duration: 200ms
   - Triggered every 10 seconds if no RTT improvement
   - Ensures RTprop estimate stays accurate
```

**BBR advantages**:

- **Low latency**: Operates near minimum RTT (empty queues)
- **High throughput**: Utilizes full bottleneck bandwidth
- **Loss-insensitive**: Random loss doesn't reduce throughput
- **Works on bufferbloat networks**: Doesn't fill queues

**BBR disadvantages**:

- **Unfair to loss-based algorithms**: Can dominate CUBIC flows
- **Router complexity**: Assumes fair queuing (FQ) or pacing support
- **BBRv1 issues**: Aggressive in some scenarios (improved in BBRv2/v3)

---

### Algorithm Comparison

| Feature | Reno | CUBIC | BBR |
|---------|------|-------|-----|
| **Signal** | Loss | Loss | Bandwidth + RTT |
| **Growth** | Linear (AIMD) | Cubic function | Model-based |
| **RTT fairness** | Poor (long RTT → slower) | Good (RTT-independent) | Excellent |
| **High-speed networks** | Poor (slow growth) | Good (fast convergence) | Excellent |
| **Bufferbloat** | Fills buffers | Fills buffers | Avoids buffers |
| **Latency** | High (full queues) | High (full queues) | Low (empty queues) |
| **Random loss tolerance** | Poor (backs off) | Poor (backs off) | Excellent (ignores) |
| **Complexity** | Low | Medium | High |
| **Default since** | 1980s-2006 | 2006-present | Optional (4.9+) |

**Throughput comparison** (1 Gbps, 50ms RTT, 0.1% random loss):

```
Reno:   ~600 Mbps (loss limits throughput)
CUBIC:  ~850 Mbps (better loss recovery)
BBR:    ~980 Mbps (ignores random loss, bandwidth-limited)
```

**Latency comparison** (bufferbloat network):

```
Reno:   RTT = 250ms (fills 200ms buffer)
CUBIC:  RTT = 250ms (fills 200ms buffer)
BBR:    RTT = 52ms (keeps buffer nearly empty)
```

---


## Implementing Custom Congestion Control in C

Let's implement a complete custom congestion control algorithm in C as a kernel module. This example demonstrates all the required callbacks and best practices.

### Example: TCP AIMD (Simple Additive Increase, Multiplicative Decrease)

We'll implement a simplified congestion control algorithm similar to Reno but with custom parameters.

**File: `tcp_aimd.c`**

```c
/* tcp_aimd.c - Custom AIMD Congestion Control Module
 *
 * A simple example demonstrating custom TCP congestion control.
 * Based on additive increase, multiplicative decrease (AIMD).
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>

#define AIMD_ALPHA 1   /* Additive increase: +1 MSS per RTT */
#define AIMD_BETA  2   /* Multiplicative decrease: cwnd / 2 */
#define AIMD_INIT_CWND 10  /* Initial congestion window */

/* Per-connection state */
struct aimd {
    u32 prior_ssthresh;    /* Previous slow start threshold */
    u32 prior_cwnd;        /* Previous cwnd (for undo) */
    u32 last_ack;          /* Last ACK time */
    u32 min_rtt_us;        /* Minimum RTT observed (microseconds) */
    u32 rtt_sample_count;  /* Number of RTT samples */
};

/* Initialize congestion control state for new connection */
static void tcp_aimd_init(struct sock *sk)
{
    struct aimd *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    
    /* Initialize state */
    memset(ca, 0, sizeof(*ca));
    
    ca->prior_ssthresh = TCP_INFINITE_SSTHRESH;
    ca->prior_cwnd = 0;
    ca->min_rtt_us = 0x7fffffff;  /* Max u32 */
    ca->rtt_sample_count = 0;
    
    /* Set initial congestion window */
    tp->snd_cwnd = AIMD_INIT_CWND;
    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
    
    pr_debug("tcp_aimd: Connection initialized, cwnd=%u\n", tp->snd_cwnd);
}

/* Release congestion control state */
static void tcp_aimd_release(struct sock *sk)
{
    struct aimd *ca = inet_csk_ca(sk);
    
    pr_debug("tcp_aimd: Connection closed, min_rtt=%u us, samples=%u\n",
             ca->min_rtt_us, ca->rtt_sample_count);
}

/* Calculate slow start threshold when loss detected */
static u32 tcp_aimd_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct aimd *ca = inet_csk_ca(sk);
    u32 ssthresh;
    
    /* Save current cwnd for undo */
    ca->prior_cwnd = tp->snd_cwnd;
    ca->prior_ssthresh = tp->snd_ssthresh;
    
    /* Multiplicative decrease: cwnd / BETA */
    ssthresh = max(tp->snd_cwnd / AIMD_BETA, 2U);
    
    pr_debug("tcp_aimd: Loss detected, cwnd %u -> ssthresh %u\n",
             tp->snd_cwnd, ssthresh);
    
    return ssthresh;
}

/* Undo cwnd reduction (spurious timeout detected) */
static u32 tcp_aimd_undo_cwnd(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct aimd *ca = inet_csk_ca(sk);
    u32 cwnd;
    
    /* Restore previous cwnd */
    cwnd = max(tp->snd_cwnd, ca->prior_cwnd);
    
    pr_debug("tcp_aimd: Undo cwnd reduction, restored to %u\n", cwnd);
    
    return cwnd;
}

/* Congestion avoidance: Main algorithm logic */
static void tcp_aimd_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct aimd *ca = inet_csk_ca(sk);
    
    /* Don't increase cwnd if we're not sending */
    if (!tcp_is_cwnd_limited(sk))
        return;
    
    /* Slow start: Exponential growth */
    if (tcp_in_slow_start(tp)) {
        /* Increase cwnd by 1 for each ACK (doubles per RTT) */
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
        
        pr_debug("tcp_aimd: Slow start, cwnd=%u, ssthresh=%u\n",
                 tp->snd_cwnd, tp->snd_ssthresh);
    }
    
    /* Congestion avoidance: Additive increase */
    /* Increase cwnd by ALPHA/cwnd for each ACK (adds ALPHA per RTT) */
    tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
    
    pr_debug("tcp_aimd: Congestion avoidance, cwnd=%u\n", tp->snd_cwnd);
}

/* Handle state transitions */
static void tcp_aimd_set_state(struct sock *sk, u8 new_state)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct aimd *ca = inet_csk_ca(sk);
    
    pr_debug("tcp_aimd: State transition to %u, cwnd=%u\n",
             new_state, tp->snd_cwnd);
    
    if (new_state == TCP_CA_Loss) {
        /* Timeout: Reset to slow start */
        ca->prior_cwnd = tp->snd_cwnd;
    }
}

/* Called when packets are ACKed (update RTT estimate) */
static void tcp_aimd_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
    struct aimd *ca = inet_csk_ca(sk);
    u32 rtt_us = sample->rtt_us;
    
    if (rtt_us <= 0)
        return;
    
    /* Track minimum RTT */
    if (rtt_us < ca->min_rtt_us)
        ca->min_rtt_us = rtt_us;
    
    ca->rtt_sample_count++;
    ca->last_ack = tcp_jiffies32;
}

/* Handle congestion events (ECN, etc.) */
static void tcp_aimd_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct aimd *ca = inet_csk_ca(sk);
    
    switch (ev) {
    case CA_EVENT_CWND_RESTART:
        /* Connection was idle, restart slow start */
        pr_debug("tcp_aimd: Idle restart\n");
        break;
        
    case CA_EVENT_COMPLETE_CWR:
        /* Finished congestion window reduction */
        pr_debug("tcp_aimd: Completed CWR\n");
        break;
        
    case CA_EVENT_LOSS:
        /* Loss detected */
        pr_debug("tcp_aimd: Loss event, cwnd=%u\n", tp->snd_cwnd);
        break;
        
    case CA_EVENT_ECN_IS_CE:
        /* ECN: Congestion experienced */
        pr_debug("tcp_aimd: ECN CE received\n");
        break;
        
    case CA_EVENT_ECN_NO_CE:
        /* ECN: No congestion */
        break;
        
    default:
        break;
    }
}

/* Get algorithm-specific info for diagnostics */
static size_t tcp_aimd_get_info(struct sock *sk, u32 ext, int *attr,
                                 union tcp_cc_info *info)
{
    const struct aimd *ca = inet_csk_ca(sk);
    
    if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
        /* Reuse vegasinfo structure for our data */
        info->vegas.tcpv_enabled = 1;
        info->vegas.tcpv_rtt = ca->min_rtt_us;
        info->vegas.tcpv_minrtt = ca->min_rtt_us;
        info->vegas.tcpv_rttcnt = ca->rtt_sample_count;
        
        *attr = INET_DIAG_VEGASINFO;
        return sizeof(struct tcpvegas_info);
    }
    
    return 0;
}

/* Congestion control operations structure */
static struct tcp_congestion_ops tcp_aimd_ops __read_mostly = {
    .init       = tcp_aimd_init,
    .release    = tcp_aimd_release,
    .ssthresh   = tcp_aimd_ssthresh,
    .undo_cwnd  = tcp_aimd_undo_cwnd,
    .cong_avoid = tcp_aimd_cong_avoid,
    .set_state  = tcp_aimd_set_state,
    .pkts_acked = tcp_aimd_pkts_acked,
    .cwnd_event = tcp_aimd_cwnd_event,
    .get_info   = tcp_aimd_get_info,
    
    .owner      = THIS_MODULE,
    .name       = "aimd",
    .flags      = TCP_CONG_NON_RESTRICTED,  /* Available to unprivileged users */
};

/* Module initialization */
static int __init tcp_aimd_register(void)
{
    int ret;
    
    BUILD_BUG_ON(sizeof(struct aimd) > ICSK_CA_PRIV_SIZE);
    
    ret = tcp_register_congestion_control(&tcp_aimd_ops);
    if (ret)
        return ret;
    
    pr_info("TCP AIMD congestion control registered\n");
    return 0;
}

/* Module cleanup */
static void __exit tcp_aimd_unregister(void)
{
    tcp_unregister_congestion_control(&tcp_aimd_ops);
    pr_info("TCP AIMD congestion control unregistered\n");
}

module_init(tcp_aimd_register);
module_exit(tcp_aimd_unregister);

MODULE_AUTHOR("Your Name <your.email@example.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP AIMD Congestion Control");
MODULE_VERSION("1.0");
```

### Building the Module

**Makefile:**

```makefile
# Makefile for tcp_aimd kernel module

obj-m += tcp_aimd.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

load:
	sudo insmod tcp_aimd.ko

unload:
	sudo rmmod tcp_aimd

reload: unload load

.PHONY: all clean install load unload reload
```

### Building and Loading

```bash
# Build the module
make

# Load the module
sudo insmod tcp_aimd.ko

# Verify it's loaded
lsmod | grep tcp_aimd
sysctl net.ipv4.tcp_available_congestion_control
# Should show: reno cubic bbr aimd

# Make it available to non-root users
echo "aimd" | sudo tee -a /proc/sys/net/ipv4/tcp_allowed_congestion_control

# Set as default (optional)
sudo sysctl -w net.ipv4.tcp_congestion_control=aimd

# Or use per-socket:
# setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, "aimd", 4);
```

### Testing

**Test script (Python):**

```python
#!/usr/bin/env python3
import socket
import struct

# Create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set congestion control algorithm
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b'aimd')

# Verify it's set
algo = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16)
print(f"Congestion control: {algo.decode().rstrip(chr(0))}")

# Connect and transfer data
sock.connect(('example.com', 80))
sock.sendall(b'GET / HTTP/1.0\r\nHost: example.com\r\n\r\n')

# Get TCP_INFO
TCP_INFO = 11
info_struct = sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 192)

# Parse TCP_INFO (simplified, first few fields)
(state, ca_state, retransmits, probes, backoff,
 options, snd_wscale, rcv_wscale, rto, ato, snd_mss,
 rcv_mss, unacked, sacked, lost, retrans, fackets,
 last_data_sent, last_ack_sent, last_data_recv,
 last_ack_recv, pmtu, rcv_ssthresh, rtt, rttvar,
 snd_ssthresh, snd_cwnd) = struct.unpack('BBBBBBBBIIIIIIIIIIIIIIIIIII', info_struct[:104])

print(f"State: {state}, CA State: {ca_state}")
print(f"cwnd: {snd_cwnd}, ssthresh: {snd_ssthresh}")
print(f"RTT: {rtt} us, RTT variance: {rttvar} us")

sock.close()
```

**Run test:**

```bash
chmod +x test_aimd.py
./test_aimd.py

# Check kernel logs
sudo dmesg | tail -20
```

### Debugging

**Enable debug logging:**

```c
/* In tcp_aimd.c, add at top: */
#define DEBUG 1

/* Or dynamically: */
echo 8 > /proc/sys/kernel/printk  # Enable debug level
```

**Trace events:**

```bash
# Enable TCP tracepoints
echo 1 > /sys/kernel/debug/tracing/events/tcp/enable

# Monitor events
cat /sys/kernel/debug/tracing/trace_pipe | grep aimd

# Specific events
echo 1 > /sys/kernel/debug/tracing/events/tcp/tcp_probe/enable
cat /sys/kernel/debug/tracing/trace_pipe
```

**Monitor with ss:**

```bash
# Watch congestion window in real-time
watch -n 0.5 'ss -tin dst example.com | grep -A 1 ESTAB'

# Example output:
# ESTAB  0  0   10.0.0.1:54321  10.0.0.2:80
#  aimd wscale:7,7 rto:204 rtt:3.5/1.75 cwnd:42 ssthresh:30 bytes_acked:123456
```

---

## Advanced Custom Algorithm Example: Delay-Based Control

Let's implement a more sophisticated algorithm that uses delay as a congestion signal (similar to Vegas).

**File: `tcp_delay.c` (simplified, key parts shown):**

```c
/* tcp_delay.c - Delay-based Congestion Control
 *
 * Monitors RTT increase to detect queue buildup.
 * Reduces cwnd before packet loss occurs.
 */

#include <linux/module.h>
#include <net/tcp.h>

#define DELAY_ALPHA   2    /* Threshold: Allow 2 packets in queue */
#define DELAY_BETA    4    /* Threshold: Reduce if 4+ packets in queue */
#define DELAY_GAMMA   1    /* Linear increase per RTT */

struct delay {
    u32 base_rtt;          /* Minimum RTT seen (propagation delay) */
    u32 min_rtt;           /* Min RTT in current window */
    u32 cnt_rtt;           /* RTT sample count */
    u32 doing_delay_now;   /* Currently in delay-based mode? */
};

static void tcp_delay_init(struct sock *sk)
{
    struct delay *ca = inet_csk_ca(sk);
    
    ca->base_rtt = 0x7fffffff;
    ca->min_rtt = 0x7fffffff;
    ca->cnt_rtt = 0;
    ca->doing_delay_now = 1;
}

static void tcp_delay_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
    struct delay *ca = inet_csk_ca(sk);
    u32 rtt_us;
    
    rtt_us = sample->rtt_us;
    if (rtt_us <= 0)
        return;
    
    /* Update minimum RTT in current window */
    if (ca->min_rtt > rtt_us)
        ca->min_rtt = rtt_us;
    
    /* Update base RTT (lifetime minimum) */
    if (ca->base_rtt > rtt_us)
        ca->base_rtt = rtt_us;
    
    ca->cnt_rtt++;
}

static void tcp_delay_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct delay *ca = inet_csk_ca(sk);
    u32 target_cwnd;
    u32 diff;
    
    if (!tcp_is_cwnd_limited(sk))
        return;
    
    /* Slow start */
    if (tcp_in_slow_start(tp)) {
        tcp_slow_start(tp, acked);
        return;
    }
    
    /* Estimate queue length */
    /* expected_throughput = cwnd / base_rtt */
    /* actual_throughput = cwnd / current_rtt */
    /* queued_packets = (current_rtt - base_rtt) / base_rtt * cwnd */
    
    if (ca->min_rtt == 0x7fffffff || ca->base_rtt == 0)
        goto inc_cwnd;  /* No RTT samples yet */
    
    /* Calculate queued bytes */
    /* diff = (current_rtt - base_rtt) * cwnd / base_rtt */
    diff = ((ca->min_rtt - ca->base_rtt) * tp->snd_cwnd) / ca->base_rtt;
    
    /* Expected cwnd for current RTT */
    target_cwnd = (tp->snd_cwnd * ca->base_rtt) / ca->min_rtt;
    
    if (diff > DELAY_BETA) {
        /* Too much queuing: Reduce cwnd */
        tp->snd_cwnd = max(tp->snd_cwnd - 1, 2U);
        tp->snd_ssthresh = tp->snd_cwnd;
        
    } else if (diff > DELAY_ALPHA) {
        /* Moderate queuing: Hold cwnd */
        
    } else {
        /* Little/no queuing: Increase cwnd */
        tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
    }
    
    ca->min_rtt = 0x7fffffff;  /* Reset for next RTT */
    return;
    
inc_cwnd:
    /* Fallback to AIMD */
    tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

static struct tcp_congestion_ops tcp_delay_ops __read_mostly = {
    .init       = tcp_delay_init,
    .ssthresh   = tcp_reno_ssthresh,
    .cong_avoid = tcp_delay_cong_avoid,
    .pkts_acked = tcp_delay_pkts_acked,
    .undo_cwnd  = tcp_reno_undo_cwnd,
    
    .owner      = THIS_MODULE,
    .name       = "delay",
};

module_init(...);
module_exit(...);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Delay-based Congestion Control");
```

**Key concepts**:

- **Base RTT**: Minimum RTT ever seen (propagation delay, no queueing)
- **Current RTT**: Recent RTT measurement (includes queueing delay)
- **Queue estimate**: `(current_rtt - base_rtt) × cwnd / base_rtt`
- **Action**:
  - Queue small (< α): Increase cwnd
  - Queue moderate (α < queue < β): Hold cwnd
  - Queue large (> β): Decrease cwnd

**Advantages**:

- **Proactive**: Reduces cwnd before loss
- **Low latency**: Keeps queues small
- **Smooth**: Gradual adjustments

**Challenges**:

- **RTT measurement accuracy**: Needs precise timestamps
- **RTT variations**: Hard to distinguish queueing from path changes
- **Competing with loss-based**: Vegas loses to Reno/CUBIC (starved)

---


## Implementing Congestion Control with eBPF

Since Linux 5.6, you can implement TCP congestion control algorithms entirely in eBPF using `BPF_PROG_TYPE_STRUCT_OPS`. This allows dynamic loading without kernel modules.

### Prerequisites

```bash
# Check kernel version (need 5.6+)
uname -r

# Check if struct_ops supported
bpftool feature | grep struct_ops

# Install dependencies
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Complete eBPF Example: TCP AIMD

**File: `tcp_aimd_bpf.c`**

```c
/* tcp_aimd_bpf.c - TCP AIMD Congestion Control in eBPF
 *
 * Demonstrates BPF_PROG_TYPE_STRUCT_OPS for congestion control.
 * Compile with: clang -O2 -target bpf -c tcp_aimd_bpf.c -o tcp_aimd_bpf.o
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Kernel headers for TCP structures */
#include "vmlinux.h"  /* Generated from BTF */

#define AIMD_ALPHA 1
#define AIMD_BETA  2
#define AIMD_INIT_CWND 10

/* Per-connection state (stored in icsk_ca_priv) */
struct aimd_bpf {
    __u32 prior_ssthresh;
    __u32 prior_cwnd;
    __u32 last_ack;
    __u32 min_rtt_us;
    __u32 rtt_sample_count;
};

char _license[] SEC("license") = "GPL";

/* Helper to access tcp_sock from sock */
static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

/* Helper to access inet_connection_sock from sock */
static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
    return (struct inet_connection_sock *)sk;
}

/* Helper to get our private state */
static inline struct aimd_bpf *get_aimd(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    return (struct aimd_bpf *)icsk->icsk_ca_priv;
}

/* Initialize congestion control */
SEC("struct_ops/aimd_bpf_init")
void BPF_PROG(aimd_bpf_init, struct sock *sk)
{
    struct aimd_bpf *ca = get_aimd(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    
    if (!ca)
        return;
    
    /* Initialize state */
    ca->prior_ssthresh = 0x7fffffff;
    ca->prior_cwnd = 0;
    ca->min_rtt_us = 0x7fffffff;
    ca->rtt_sample_count = 0;
    
    /* Set initial cwnd */
    tp->snd_cwnd = AIMD_INIT_CWND;
    tp->snd_ssthresh = 0x7fffffff;
}

/* Release congestion control (optional, no action needed) */
SEC("struct_ops/aimd_bpf_release")
void BPF_PROG(aimd_bpf_release, struct sock *sk)
{
    /* Cleanup if needed */
}

/* Calculate slow start threshold on loss */
SEC("struct_ops/aimd_bpf_ssthresh")
__u32 BPF_PROG(aimd_bpf_ssthresh, struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct aimd_bpf *ca = get_aimd(sk);
    __u32 ssthresh;
    
    if (!ca)
        return 2;
    
    /* Save current state */
    ca->prior_cwnd = tp->snd_cwnd;
    ca->prior_ssthresh = tp->snd_ssthresh;
    
    /* Multiplicative decrease */
    ssthresh = tp->snd_cwnd / AIMD_BETA;
    if (ssthresh < 2)
        ssthresh = 2;
    
    return ssthresh;
}

/* Undo cwnd reduction */
SEC("struct_ops/aimd_bpf_undo_cwnd")
__u32 BPF_PROG(aimd_bpf_undo_cwnd, struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct aimd_bpf *ca = get_aimd(sk);
    __u32 cwnd;
    
    if (!ca)
        return tp->snd_cwnd;
    
    /* Restore previous cwnd */
    cwnd = tp->snd_cwnd;
    if (ca->prior_cwnd > cwnd)
        cwnd = ca->prior_cwnd;
    
    return cwnd;
}

/* Congestion avoidance logic */
SEC("struct_ops/aimd_bpf_cong_avoid")
void BPF_PROG(aimd_bpf_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    __u32 cwnd = tp->snd_cwnd;
    __u32 ssthresh = tp->snd_ssthresh;
    
    /* Check if we're limited by cwnd (not application or receiver) */
    /* Note: tcp_is_cwnd_limited() not available in BPF, approximate */
    if (tp->snd_cwnd_cnt >= cwnd)
        return;
    
    /* Slow start: exponential growth */
    if (cwnd < ssthresh) {
        /* Increase by 1 for each ACK */
        cwnd += acked;
        if (cwnd > ssthresh)
            cwnd = ssthresh;
        
        tp->snd_cwnd = cwnd;
        return;
    }
    
    /* Congestion avoidance: linear growth */
    /* Increase by 1/cwnd for each ACK (adds 1 per RTT) */
    tp->snd_cwnd_cnt += acked;
    
    if (tp->snd_cwnd_cnt >= cwnd) {
        __u32 delta = tp->snd_cwnd_cnt / cwnd;
        tp->snd_cwnd_cnt -= delta * cwnd;
        tp->snd_cwnd += delta;
    }
}

/* State transition handler */
SEC("struct_ops/aimd_bpf_set_state")
void BPF_PROG(aimd_bpf_set_state, struct sock *sk, __u8 new_state)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct aimd_bpf *ca = get_aimd(sk);
    
    if (!ca)
        return;
    
    /* Save state on loss */
    if (new_state == TCP_CA_Loss) {
        ca->prior_cwnd = tp->snd_cwnd;
    }
}

/* Packets ACKed callback (RTT measurement) */
SEC("struct_ops/aimd_bpf_pkts_acked")
void BPF_PROG(aimd_bpf_pkts_acked, struct sock *sk,
              const struct ack_sample *sample)
{
    struct aimd_bpf *ca = get_aimd(sk);
    __u32 rtt_us;
    
    if (!ca || !sample)
        return;
    
    rtt_us = sample->rtt_us;
    if (rtt_us == 0 || rtt_us == (__u32)-1)
        return;
    
    /* Track minimum RTT */
    if (rtt_us < ca->min_rtt_us)
        ca->min_rtt_us = rtt_us;
    
    ca->rtt_sample_count++;
}

/* Congestion event handler */
SEC("struct_ops/aimd_bpf_cwnd_event")
void BPF_PROG(aimd_bpf_cwnd_event, struct sock *sk, enum tcp_ca_event ev)
{
    /* Handle ECN, loss, etc. */
    /* For simplicity, we don't do anything special here */
}

/* Define the tcp_congestion_ops structure */
SEC(".struct_ops")
struct tcp_congestion_ops aimd_bpf = {
    .init           = (void *)aimd_bpf_init,
    .release        = (void *)aimd_bpf_release,
    .ssthresh       = (void *)aimd_bpf_ssthresh,
    .undo_cwnd      = (void *)aimd_bpf_undo_cwnd,
    .cong_avoid     = (void *)aimd_bpf_cong_avoid,
    .set_state      = (void *)aimd_bpf_set_state,
    .pkts_acked     = (void *)aimd_bpf_pkts_acked,
    .cwnd_event     = (void *)aimd_bpf_cwnd_event,
    .name           = "aimd_bpf",
};
```

### Generating vmlinux.h

```bash
# Generate BTF header with kernel type definitions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### Compiling

**Option 1: Direct clang**

```bash
clang -O2 -target bpf -D__TARGET_ARCH_x86 \
      -I/usr/include/$(uname -m)-linux-gnu \
      -c tcp_aimd_bpf.c -o tcp_aimd_bpf.o
```

**Option 2: Using libbpf-based Makefile**

```makefile
# Makefile for BPF congestion control

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

BPF_CFLAGS = -O2 -target bpf -D__TARGET_ARCH_x86
BPF_INCLUDES = -I/usr/include/$(shell uname -m)-linux-gnu

all: tcp_aimd_bpf.o loader

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tcp_aimd_bpf.o: tcp_aimd_bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

loader: loader.c
	gcc -o loader loader.c -lbpf

clean:
	rm -f *.o vmlinux.h loader

.PHONY: all clean
```

### Loading the eBPF Program

**File: `loader.c`**

```c
/* loader.c - Load eBPF congestion control program */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_link *link;
    int err;
    
    /* Open BPF object file */
    obj = bpf_object__open_file("tcp_aimd_bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", 
                strerror(errno));
        return 1;
    }
    
    /* Load BPF program into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n",
                strerror(-err));
        goto cleanup;
    }
    
    /* Attach struct_ops (registers congestion control algorithm) */
    link = bpf_map__attach_struct_ops(
        bpf_object__find_map_by_name(obj, ".struct_ops"));
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach struct_ops: %s\n",
                strerror(-libbpf_get_error(link)));
        goto cleanup;
    }
    
    printf("BPF congestion control 'aimd_bpf' loaded successfully!\n");
    printf("Press Ctrl+C to unload...\n");
    
    /* Keep running (congestion control stays loaded) */
    /* In production, you'd detach or pin the link */
    pause();
    
    /* Detach (unregister algorithm) */
    bpf_link__destroy(link);
    
cleanup:
    bpf_object__close(obj);
    return err ? 1 : 0;
}
```

**Compile and run loader:**

```bash
gcc -o loader loader.c -lbpf
sudo ./loader

# In another terminal:
sysctl net.ipv4.tcp_available_congestion_control
# Should show: ... aimd_bpf

# Test it:
python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b'aimd_bpf')
print('Using:', sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16))
"
```

### Alternative: Using bpftool directly

```bash
# Load and register
sudo bpftool struct_ops register tcp_aimd_bpf.o

# Verify
sysctl net.ipv4.tcp_available_congestion_control
bpftool struct_ops list

# Unregister
bpftool struct_ops unregister name aimd_bpf
```

### Advanced eBPF Example: BBR-like Algorithm

**File: `tcp_bbr_lite.c` (simplified BBR in eBPF):**

```c
/* tcp_bbr_lite.c - Simplified BBR in eBPF */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define BBR_UNIT 1024
#define BBR_SCALE 8
#define BBR_STARTUP_GAIN (2.89 * BBR_UNIT)  /* 2.89x */
#define BBR_DRAIN_GAIN (1.0 / 2.89 * BBR_UNIT)
#define BBR_CWND_GAIN (2 * BBR_UNIT)

enum bbr_mode {
    BBR_STARTUP,
    BBR_DRAIN,
    BBR_PROBE_BW,
    BBR_PROBE_RTT,
};

struct bbr_lite {
    __u32 min_rtt_us;
    __u32 min_rtt_stamp;
    __u64 max_bw;
    __u32 mode;
    __u32 round_start;
    __u32 next_round_delivered;
    __u32 pacing_gain;
    __u32 cwnd_gain;
    __u32 full_bw;
    __u32 full_bw_count;
};

char _license[] SEC("license") = "GPL";

static inline struct bbr_lite *get_bbr(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    return (struct bbr_lite *)icsk->icsk_ca_priv;
}

SEC("struct_ops/bbr_lite_init")
void BPF_PROG(bbr_lite_init, struct sock *sk)
{
    struct bbr_lite *bbr = get_bbr(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    
    if (!bbr)
        return;
    
    bbr->min_rtt_us = 0x7fffffff;
    bbr->min_rtt_stamp = tcp_jiffies32;
    bbr->max_bw = 0;
    bbr->mode = BBR_STARTUP;
    bbr->pacing_gain = BBR_STARTUP_GAIN;
    bbr->cwnd_gain = BBR_CWND_GAIN;
    bbr->full_bw = 0;
    bbr->full_bw_count = 0;
    bbr->round_start = 0;
    bbr->next_round_delivered = 0;
    
    tp->snd_cwnd = 10;
}

SEC("struct_ops/bbr_lite_ssthresh")
__u32 BPF_PROG(bbr_lite_ssthresh, struct sock *sk)
{
    /* BBR doesn't use ssthresh traditionally */
    return 0x7fffffff;
}

SEC("struct_ops/bbr_lite_cong_control")
void BPF_PROG(bbr_lite_cong_control, struct sock *sk,
              const struct rate_sample *rs)
{
    struct bbr_lite *bbr = get_bbr(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    __u64 bw;
    __u32 target_cwnd;
    
    if (!bbr || !rs)
        return;
    
    /* Update bandwidth estimate */
    if (rs->delivered > 0 && rs->interval_us > 0) {
        bw = (__u64)rs->delivered * 1000000 / rs->interval_us;
        if (bw > bbr->max_bw)
            bbr->max_bw = bw;
    }
    
    /* Update min RTT */
    if (rs->rtt_us > 0 && rs->rtt_us < bbr->min_rtt_us) {
        bbr->min_rtt_us = rs->rtt_us;
        bbr->min_rtt_stamp = tcp_jiffies32;
    }
    
    /* Check for full bandwidth reached */
    if (bbr->mode == BBR_STARTUP) {
        if (bbr->max_bw > 0 && bbr->full_bw > 0 &&
            bbr->max_bw < bbr->full_bw * 1.25) {
            bbr->full_bw_count++;
            if (bbr->full_bw_count >= 3) {
                /* Bandwidth plateau: Enter DRAIN */
                bbr->mode = BBR_DRAIN;
                bbr->pacing_gain = BBR_DRAIN_GAIN;
            }
        } else {
            bbr->full_bw = bbr->max_bw;
            bbr->full_bw_count = 0;
        }
    }
    
    /* Check drain completion */
    if (bbr->mode == BBR_DRAIN) {
        /* Simplified: check if inflight <= BDP */
        __u32 bdp = (bbr->max_bw * bbr->min_rtt_us) / 1000000;
        if (tp->packets_out <= bdp) {
            bbr->mode = BBR_PROBE_BW;
            bbr->pacing_gain = BBR_UNIT;  /* 1.0x */
            bbr->cwnd_gain = BBR_CWND_GAIN;
        }
    }
    
    /* Set target cwnd (BDP × cwnd_gain) */
    if (bbr->max_bw > 0 && bbr->min_rtt_us > 0) {
        target_cwnd = (bbr->max_bw * bbr->min_rtt_us * bbr->cwnd_gain) /
                      (1000000 * BBR_UNIT);
        if (target_cwnd < 4)
            target_cwnd = 4;
        
        tp->snd_cwnd = target_cwnd;
    }
    
    /* Set pacing rate */
    if (bbr->max_bw > 0) {
        __u64 rate = bbr->max_bw * bbr->pacing_gain / BBR_UNIT;
        sk->sk_pacing_rate = rate;
    }
}

SEC("struct_ops/bbr_lite_undo_cwnd")
__u32 BPF_PROG(bbr_lite_undo_cwnd, struct sock *sk)
{
    return tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops bbr_lite = {
    .init           = (void *)bbr_lite_init,
    .ssthresh       = (void *)bbr_lite_ssthresh,
    .cong_control   = (void *)bbr_lite_cong_control,
    .undo_cwnd      = (void *)bbr_lite_undo_cwnd,
    .name           = "bbr_lite",
};
```

### eBPF Advantages

✅ **No kernel rebuild**: Load/unload dynamically
✅ **Safe**: BPF verifier ensures safety
✅ **Fast iteration**: Develop and test quickly
✅ **Portable**: Works across kernel versions (with BTF)
✅ **Debugging**: Use bpf_printk() for tracing

### eBPF Limitations

❌ **Limited helpers**: Not all kernel functions available
❌ **Complexity restrictions**: BPF verifier limits
❌ **Performance**: Slightly slower than native C (JIT overhead)
❌ **Kernel 5.6+**: Requires recent kernel

### Debugging eBPF Programs

```bash
# Enable BPF tracing
echo 1 > /sys/kernel/debug/tracing/events/bpf_trace/enable

# Add debug prints in BPF code:
bpf_printk("cwnd=%u, ssthresh=%u\n", tp->snd_cwnd, tp->snd_ssthresh);

# View trace output:
cat /sys/kernel/debug/tracing/trace_pipe

# Use bpftool for inspection:
bpftool prog list
bpftool map list
bpftool struct_ops dump name aimd_bpf
```

---


## Congestion Events and State Interactions

Congestion control doesn't operate in isolation. It interacts with many other TCP mechanisms.

### Congestion Events

```c
/* From include/uapi/linux/tcp.h */

enum tcp_ca_event {
    CA_EVENT_TX_START,      /* First transmission */
    CA_EVENT_CWND_RESTART,  /* Congestion window restart after idle */
    CA_EVENT_COMPLETE_CWR,  /* Completed cwnd reduction */
    CA_EVENT_LOSS,          /* Loss detected */
    CA_EVENT_ECN_NO_CE,     /* ECN: No congestion */
    CA_EVENT_ECN_IS_CE,     /* ECN: Congestion experienced */
};
```

**Event triggers**:

```c
/* From net/ipv4/tcp_input.c */

/* Loss detection */
static void tcp_enter_loss(struct sock *sk)
{
    const struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    
    /* Notify congestion control */
    tcp_ca_event(sk, CA_EVENT_LOSS);
    
    /* Reduce cwnd to 1 (severe congestion) */
    tp->snd_cwnd = 1;
    tp->snd_cwnd_cnt = 0;
    tp->snd_cwnd_stamp = tcp_jiffies32;
    
    /* Set ssthresh */
    tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
    
    /* Clear undo state */
    tcp_clear_retrans(tp);
}

/* ECN congestion notification */
static void tcp_ecn_rcv_ce(struct tcp_sock *tp, const struct sk_buff *skb)
{
    if (tp->ecn_flags & TCP_ECN_OK) {
        /* ECN-capable: Mark congestion */
        tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
        
        /* Notify congestion control */
        tcp_ca_event(sk, CA_EVENT_ECN_IS_CE);
        
        /* Enter CWR (congestion window reduced) state */
        tcp_enter_cwr(sk);
    }
}

/* Idle restart */
static void tcp_cwnd_restart(struct sock *sk, s32 delta)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u32 restart_cwnd = tcp_init_cwnd(tp, __sk_dst_get(sk));
    u32 cwnd = tp->snd_cwnd;
    
    /* Connection was idle: restart slow start */
    tcp_ca_event(sk, CA_EVENT_CWND_RESTART);
    
    tp->snd_ssthresh = tcp_current_ssthresh(sk);
    restart_cwnd = min(restart_cwnd, cwnd);
    
    while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
        cwnd >>= 1;
    tp->snd_cwnd = max(cwnd, restart_cwnd);
    tp->snd_cwnd_stamp = tcp_jiffies32;
    tp->snd_cwnd_used = 0;
}
```

### ECN (Explicit Congestion Notification)

ECN allows routers to signal congestion without dropping packets:

```
IP header ECN bits:
  00: Not-ECT (ECN Capable Transport)
  01: ECT(0) - ECN Capable Transport
  10: ECT(1) - ECN Capable Transport
  11: CE (Congestion Experienced)

TCP header flags:
  ECE (ECN-Echo): Receiver signals congestion to sender
  CWR (Congestion Window Reduced): Sender acknowledges ECN
```

**ECN handshake**:

```
Client → Server: SYN, ECE+CWR (ECN capable)
Server → Client: SYN+ACK, ECE (ECN confirmed)
Client → Server: ACK (ECN enabled)

During transfer:
Router marks packet: IP ECN = CE
Server → Client: ACK with ECE flag
Client: Reduce cwnd, send packet with CWR flag
Server receives CWR: Stop sending ECE
```

**ECN in kernel**:

```c
/* From net/ipv4/tcp_input.c */

static void tcp_ecn_rcv(struct tcp_sock *tp, const struct tcphdr *th,
                         const struct sk_buff *skb)
{
    if (tp->ecn_flags & TCP_ECN_OK) {
        /* Check for CE marking in IP header */
        if (INET_ECN_is_ce(TCP_SKB_CB(skb)->ip_dsfield)) {
            /* Congestion experienced */
            tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
            tcp_ca_event(sk, CA_EVENT_ECN_IS_CE);
        }
        
        /* Check for ECE flag in TCP header */
        if (th->ece)
            tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
        else if (th->cwr)
            tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
    }
}
```

**Enable ECN**:

```bash
# Enable ECN system-wide
sysctl -w net.ipv4.tcp_ecn=1

# Values:
# 0 = Disabled
# 1 = Enable for incoming connections
# 2 = Enable for both incoming and outgoing (aggressive)

# Per-socket:
setsockopt(sockfd, IPPROTO_TCP, TCP_ECN, &val, sizeof(val));
```

---

## Performance Considerations

### Pacing vs Burst

**Bursty transmission** (traditional TCP):

```
Time:  0ms      10ms     20ms     30ms
Send:  [======] ........  [======] ........
       10 pkts           10 pkts
       (instant burst)   (instant burst)

Problem: Bursts cause queue buildup, bufferbloat
```

**Paced transmission** (BBR, modern TCP):

```
Time:  0ms      10ms     20ms     30ms
Send:  [==][==] [==][==] [==][==] [==][==]
       2   2    2   2    2   2    2   2

Benefit: Smooth transmission, lower latency, less loss
```

**Pacing implementation**:

```c
/* From net/core/sock.c */

/* Set pacing rate */
void sk_pacing_rate_set(struct sock *sk, u64 rate)
{
    sk->sk_pacing_rate = rate;
    sk->sk_pacing_status = SK_PACING_NEEDED;
}

/* From net/sched/sch_fq.c (Fair Queue scheduler) */

/* FQ scheduler enforces pacing */
static struct sk_buff *fq_dequeue(struct Qdisc *sch)
{
    struct fq_sched_data *q = qdisc_priv(sch);
    u64 now = ktime_get_ns();
    struct sk_buff *skb;
    struct fq_flow *f;
    
    /* Find flow ready to send (pacing time elapsed) */
    f = fq_flow_dequeue(q, now);
    if (!f)
        return NULL;
    
    skb = f->head;
    f->head = skb->next;
    
    /* Update next pacing time */
    if (skb->sk && skb->sk->sk_pacing_rate) {
        u64 len_ns = (u64)skb->len * NSEC_PER_SEC /
                     skb->sk->sk_pacing_rate;
        f->time_next_packet = now + len_ns;
    }
    
    return skb;
}
```

**Enable pacing**:

```bash
# Use FQ (Fair Queue) qdisc for pacing support
tc qdisc replace dev eth0 root fq

# Pacing happens automatically with BBR
# CUBIC can also use pacing if enabled:
sysctl -w net.ipv4.tcp_pacing_ss_ratio=200  # Slow start pacing (2x)
sysctl -w net.ipv4.tcp_pacing_ca_ratio=120  # Congestion avoidance (1.2x)
```

### TSO/GSO (TCP/Generic Segmentation Offload)

Modern NICs can segment large buffers:

```
Without TSO:
  TCP creates: [1460] [1460] [1460] ... (many small packets)
  CPU overhead: High (per-packet processing)

With TSO:
  TCP creates: [64KB super-packet]
  NIC segments: [1460] [1460] [1460] ... (hardware does it)
  CPU overhead: Low (single large buffer)
```

**Interaction with congestion control**:

```c
/* From net/ipv4/tcp_output.c */

static unsigned int tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
                                         int large_allowed)
{
    struct tcp_sock *tp = tcp_sk(sk);
    u32 new_size_goal, size_goal;
    
    if (!large_allowed)
        return mss_now;
    
    /* TSO: Build larger segments */
    /* Limited by: cwnd, GSO max size, pacing */
    size_goal = tp->gso_segs * mss_now;
    
    /* Pacing limit */
    if (sk->sk_pacing_rate != ~0UL) {
        u64 val = sk->sk_pacing_rate;
        val *= tcp_mstamp_delta(sk);
        do_div(val, NSEC_PER_SEC);
        size_goal = min_t(u32, size_goal, val);
    }
    
    /* Clamp to cwnd */
    new_size_goal = min(size_goal, tcp_cwnd_test(tp, skb));
    
    return max(new_size_goal, mss_now);
}
```

### PRR (Proportional Rate Reduction)

Improves loss recovery by sending smoothly:

```c
/* From net/ipv4/tcp_input.c */

/* Send during fast recovery (after loss) */
void tcp_cwnd_reduction(struct sock *sk, int newly_acked_sacked, int flag)
{
    struct tcp_sock *tp = tcp_sk(sk);
    int sndcnt = 0;
    int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);
    
    if (newly_acked_sacked <= 0 || WARN_ON_ONCE(!tp->prior_cwnd))
        return;
    
    /* PRR: Send proportional to ACKs received */
    /* sndcnt = delivered * ssthresh / prior_cwnd */
    sndcnt = DIV_ROUND_UP((u64)tp->prr_delivered * tp->snd_ssthresh,
                          tp->prior_cwnd);
    sndcnt -= tp->prr_out;
    
    if (delta > 0)
        sndcnt = max(sndcnt, (newly_acked_sacked > delta) ?
                             newly_acked_sacked - delta : 1);
    
    tp->snd_cwnd = tcp_packets_in_flight(tp) + sndcnt;
}
```

---

## Advanced Topics

### HyStart++ (Hybrid Slow Start)

Exits slow start earlier to avoid overshoot:

```c
/* From net/ipv4/tcp_cubic.c */

/* Detect when to exit slow start (before loss) */
static void hystart_update(struct sock *sk, u32 delay)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);
    
    if (!tcp_in_slow_start(tp))
        return;
    
    /* Monitor RTT increase */
    if (ca->curr_rtt == 0)
        ca->curr_rtt = delay;
    
    /* RTT increased by > 12.5%: Exit slow start */
    if (delay > ca->curr_rtt + (ca->curr_rtt >> 3)) {
        tp->snd_ssthresh = tp->snd_cwnd;
    }
}
```

### TCP Timestamps and RTT Measurement

```c
/* From net/ipv4/tcp_input.c */

/* Use timestamps for accurate RTT */
static void tcp_ack_update_rtt(struct sock *sk, const int flag,
                                 long seq_rtt_us)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    
    /* Prefer timestamp-based RTT (more accurate) */
    if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr) {
        u32 delta = tcp_time_stamp(tp) - tp->rx_opt.rcv_tsecr;
        seq_rtt_us = delta * (USEC_PER_SEC / TCP_TS_HZ);
    }
    
    /* Update RTT estimate */
    tcp_rtt_estimator(sk, seq_rtt_us);
    tcp_set_rto(sk);
}
```

### Fair Queuing and AQM (Active Queue Management)

Modern routers use intelligent queue management:

**FQ_CoDel (Fair Queue + Controlled Delay)**:

```bash
# Set on router/gateway
tc qdisc add dev eth0 root fq_codel

# Provides:
# - Per-flow queuing (fairness)
# - CoDel AQM (drop before buffer full)
# - ECN marking (instead of dropping)
```

**Benefits**:

- **Fairness**: Each flow gets equal share
- **Low latency**: CoDel keeps queues short
- **Bufferbloat mitigation**: Dynamic queue management

### BBR v2 and v3 Improvements

**BBRv2** (Linux 5.16+):

- **Congestion response**: Better coexistence with loss-based algorithms
- **ECN support**: Respects ECN signals
- **Improved fairness**: Doesn't dominate CUBIC

**BBRv3** (experimental):

- **Faster convergence**: Reaches optimal rate quicker
- **Better handling of complex networks**: Multiple bottlenecks

### Multipath TCP (MPTCP) and Congestion Control

MPTCP uses multiple paths simultaneously:

```
Path 1: WiFi (10 Mbps, 20ms RTT)
Path 2: LTE (5 Mbps, 50ms RTT)

Coupled congestion control:
  - Each path has own cwnd
  - Coordinated to prevent overload
  - Shift traffic to less congested path
```

**MPTCP congestion control** (coupled):

```c
/* Simplified MPTCP congestion control coordination */

static void mptcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct mptcp_sock *msk = mptcp_sk(sk);
    u32 total_cwnd = 0;
    struct sock *subsk;
    
    /* Sum cwnd across all subflows */
    mptcp_for_each_subflow(msk, subsk) {
        total_cwnd += tcp_sk(subsk)->snd_cwnd;
    }
    
    /* Increase conservatively to be fair to single-path TCP */
    /* Increase rate: min(cwnd_i / RTT_i^2 / sum(cwnd_j / RTT_j)) */
    tcp_cong_avoid_ai(tcp_sk(sk), total_cwnd, acked);
}
```

---

## Tuning and Best Practices

### System-wide Tuning

```bash
# Set default congestion control
sysctl -w net.ipv4.tcp_congestion_control=bbr

# Allow non-root to use advanced algorithms
sysctl -w net.ipv4.tcp_allowed_congestion_control="reno cubic bbr"

# Enable ECN
sysctl -w net.ipv4.tcp_ecn=1

# Pacing parameters
sysctl -w net.ipv4.tcp_pacing_ss_ratio=200
sysctl -w net.ipv4.tcp_pacing_ca_ratio=120

# Fair queuing (required for BBR pacing)
tc qdisc replace dev eth0 root fq

# Or use fq_codel for routers
tc qdisc replace dev eth0 root fq_codel
```

### Application-level Tuning

```c
/* Per-connection congestion control selection */

int sockfd = socket(AF_INET, SOCK_STREAM, 0);

/* Set congestion control algorithm */
const char *algo = "bbr";
if (setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION,
               algo, strlen(algo)) < 0) {
    perror("setsockopt TCP_CONGESTION");
}

/* Query current algorithm */
char buf[16];
socklen_t len = sizeof(buf);
getsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, buf, &len);
printf("Using: %s\n", buf);

/* Get detailed TCP_INFO */
struct tcp_info info;
len = sizeof(info);
getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &info, &len);

printf("cwnd: %u\n", info.tcpi_snd_cwnd);
printf("ssthresh: %u\n", info.tcpi_snd_ssthresh);
printf("rtt: %u us\n", info.tcpi_rtt);
printf("mss: %u\n", info.tcpi_snd_mss);
printf("delivery_rate: %llu bps\n", info.tcpi_delivery_rate);
```

### Algorithm Selection Guide

| Scenario | Recommended | Reason |
|----------|-------------|--------|
| **General purpose** | CUBIC | Balanced, proven, default |
| **High-bandwidth, high-latency** | BBR | Maximizes throughput, low latency |
| **Lossy networks (wireless)** | BBR | Doesn't react to random loss |
| **Data center (low RTT)** | DCTCP | Optimized for DC networks |
| **Satellite (very high RTT)** | BBR or Hybla | Handles long RTT well |
| **Interactive (gaming, VoIP)** | BBR | Low latency, small queues |
| **Bulk transfer** | CUBIC or BBR | High throughput |
| **Competing with many flows** | CUBIC | Better fairness than BBR |

### Monitoring and Debugging

```bash
# Real-time connection monitoring
ss -tinom dst <IP>

# Example output:
# cubic wscale:7,7 rto:204 rtt:3.5/1.75 ato:40 mss:1448
# cwnd:10 ssthresh:7 bytes_acked:12345 segs_out:100
# pacing_rate 33.1Mbps delivery_rate 28.8Mbps

# TCP statistics
nstat -az | grep Tcp

# Congestion control module info
cat /proc/net/tcp_metrics

# Trace congestion events
perf trace -e tcp:tcp_cong_state_set

# BPF tracing
bpftrace -e 'kprobe:tcp_ack { @cwnd = hist(((struct tcp_sock *)arg0)->snd_cwnd); }'
```

---

## Summary

TCP congestion control is a sophisticated mechanism that:

1. **Prevents network collapse**: Backs off when detecting congestion
2. **Maximizes throughput**: Probes for available bandwidth
3. **Ensures fairness**: Shares bandwidth among flows
4. **Adapts to conditions**: Different algorithms for different scenarios

**Evolution**:
- **1980s**: No congestion control → Internet congestion collapse
- **1988**: Reno (slow start, AIMD) → Internet stability
- **2006**: CUBIC → Better for high-speed networks
- **2016**: BBR → Low latency, model-based control
- **2020+**: eBPF → User-space programmable congestion control

**Key takeaways**:
- **Pluggable framework**: Multiple algorithms coexist
- **C modules**: Full control, kernel rebuild
- **eBPF**: Dynamic loading, safe, portable (5.6+)
- **Tuning**: Per-system, per-route, per-socket
- **Monitoring**: ss, netstat, TCP_INFO, eBPF tracing

The congestion control landscape continues to evolve, with ongoing research into better fairness, lower latency, and adaptation to diverse network conditions.

---

## Further Reading

**RFCs**:
- **RFC 5681**: TCP Congestion Control
- **RFC 8312**: CUBIC Congestion Control
- **RFC 3168**: ECN (Explicit Congestion Notification)
- **RFC 8985**: BBR Congestion Control

**Papers**:
- "Congestion Avoidance and Control" (Jacobson, 1988)
- "CUBIC: A New TCP-Friendly High-Speed TCP Variant" (Ha et al., 2008)
- "BBR: Congestion-Based Congestion Control" (Cardwell et al., 2016)

**Kernel Documentation**:
- `Documentation/networking/ip-sysctl.txt` - TCP sysctls
- `net/ipv4/tcp_*.c` - Congestion control implementations
- `samples/bpf/` - BPF examples

**Tools**:
- `ss` - Socket statistics
- `nstat` - Network statistics
- `tc` - Traffic control (qdisc management)
- `bpftool` - BPF program management
- `bpftrace` - Dynamic tracing

