# Sockets: io_uring Networking

## Introduction

`io_uring` is a modern asynchronous I/O interface introduced in Linux 5.1 (2019). For networking, it provides:

- **True asynchrony**: Submit I/O operations without blocking
- **Zero syscalls**: Batch operations with no syscall overhead
- **Kernel polling**: Kernel polls for completions (SQPOLL mode)
- **Lower latency**: Reduced context switches and syscall overhead
- **Higher throughput**: Batch processing and efficient memory management

### Motivation

**Traditional socket I/O limitations**:

```c
/* Blocking: context switch on every operation */
recv(fd, buf, len, 0);  /* Blocks, context switch */

/* Non-blocking + epoll: still requires syscalls */
while (1) {
    int n = epoll_wait(epfd, events, MAX, -1);  /* Syscall */
    for (int i = 0; i < n; i++) {
        recv(events[i].data.fd, buf, len, 0);   /* Syscall */
    }
}
/* Two syscalls per I/O operation */
```

**io_uring approach**:

```c
/* Prepare multiple operations */
io_uring_prep_recv(sqe1, fd1, buf1, len1, 0);
io_uring_prep_recv(sqe2, fd2, buf2, len2, 0);
io_uring_prep_recv(sqe3, fd3, buf3, len3, 0);

/* Submit all at once (one syscall or zero with SQPOLL) */
io_uring_submit(&ring);

/* Wait for completions (one syscall or zero with IORING_SETUP_IOPOLL) */
io_uring_wait_cqe(&ring, &cqe);
```

**Performance improvements**:

| Metric | Traditional (epoll) | io_uring |
|--------|---------------------|----------|
| Syscalls per operation | 2 (epoll_wait + recv) | 0-1 (batched) |
| Context switches | High | Low |
| Throughput (Gbps) | 40-50 | 80-100 |
| Latency (μs) | 10-20 | 5-10 |
| CPU efficiency | Good | Excellent |

### Comparison with Traditional I/O

```mermaid
sequenceDiagram
    participant App as Application
    participant Kernel as Kernel
    participant Device as Network Device
    
    Note over App,Device: Traditional (epoll + recv)
    
    App->>Kernel: epoll_wait() [syscall]
    Note over Kernel: Context switch
    Kernel->>Device: Check for data
    Device->>Kernel: Data available
    Kernel->>App: Return ready fd
    Note over App: Context switch back
    
    App->>Kernel: recv() [syscall]
    Note over Kernel: Context switch
    Kernel->>App: Copy data
    Note over App: Context switch back
    
    Note over App,Device: io_uring
    
    App->>Kernel: Submit SQE (no syscall with SQPOLL)
    Kernel->>Device: Initiate receive
    Device->>Kernel: Data available
    Kernel->>Kernel: Complete CQE
    App->>Kernel: Check CQE (polling, no syscall)
    Kernel->>App: Completion data
    
    Note over App,Device: 4 syscalls → 0 syscalls
```

---


## Architecture

### Core Concepts

io_uring uses **shared memory rings** for zero-copy communication between userspace and kernel:

```
User Space                          Kernel Space
┌────────────────────┐             ┌─────────────────────┐
│                    │             │                     │
│  Submission Queue  │◄───mmap────►│  Submission Queue   │
│      (SQ)          │  shared     │      (SQ)           │
│                    │   memory    │                     │
│  ┌──┬──┬──┬──┬──┐ │             │  ┌──┬──┬──┬──┬──┐  │
│  │SQE│SQE│SQE│  │  │             │  │SQE│SQE│SQE│  │  │
│  └──┴──┴──┴──┴──┘ │             │  └──┴──┴──┴──┴──┘  │
│       ↓            │             │       ↓             │
│   Submit I/O       │             │   Process SQE       │
│                    │             │       ↓             │
│  Completion Queue  │◄───mmap────►│  Completion Queue   │
│      (CQ)          │  shared     │      (CQ)           │
│                    │   memory    │                     │
│  ┌──┬──┬──┬──┬──┐ │             │  ┌──┬──┬──┬──┬──┐  │
│  │  │  │CQE│CQE│CQE│             │  │  │  │CQE│CQE│CQE│
│  └──┴──┴──┴──┴──┘ │             │  └──┴──┴──┴──┴──┘  │
│       ↑            │             │       ↑             │
│  Harvest results   │             │  Post completions   │
└────────────────────┘             └─────────────────────┘
```

**Key components**:

1. **Submission Queue (SQ)**: Ring buffer of operation requests (SQEs)
2. **Completion Queue (CQ)**: Ring buffer of operation completions (CQEs)
3. **Submission Queue Entries (SQE)**: Describes what operation to perform
4. **Completion Queue Entries (CQE)**: Results of completed operations
5. **SQ Ring**: Metadata about SQ (head, tail, flags)
6. **CQ Ring**: Metadata about CQ (head, tail, overflow)

### Data Structures

#### io_uring Instance

```c
/* From include/linux/io_uring_types.h */

struct io_ring_ctx {
    /* Submission queue */
    struct {
        struct io_uring_sqe *sqes;    /* SQE array */
        unsigned int cached_sq_head;   /* Cached head position */
        unsigned int sq_entries;       /* Number of SQEs */
        struct wait_queue_head sqo_wait; /* SQ overflow wait queue */
        struct io_sq_data *sq_data;    /* SQ thread data (SQPOLL mode) */
    } ____cacheline_aligned_in_smp;
    
    /* Completion queue */
    struct {
        struct io_uring_cqe *cqes;    /* CQE array */
        unsigned int cached_cq_tail;   /* Cached tail position */
        unsigned int cq_entries;       /* Number of CQEs */
        struct wait_queue_head cq_wait; /* CQ wait queue */
        unsigned int cq_extra;         /* Extra CQE space */
        atomic_t cq_timeouts;          /* Timeout completions */
    } ____cacheline_aligned_in_smp;
    
    /* Ring metadata */
    struct io_uring sq, cq;
    
    /* File table for fixed files */
    struct fixed_file_table *file_table;
    
    /* Registered buffers */
    struct io_mapped_ubuf **user_bufs;
    unsigned int nr_user_bufs;
    
    /* Various flags and options */
    unsigned int flags;
    
    /* Work queue for async operations */
    struct io_wq *io_wq;
    
    /* ... many more fields ... */
};
```

#### Submission Queue Entry (SQE)

```c
/* From include/uapi/linux/io_uring.h */

struct io_uring_sqe {
    __u8    opcode;         /* Operation code (IORING_OP_*) */
    __u8    flags;          /* IOSQE_* flags */
    __u16   ioprio;         /* I/O priority */
    __s32   fd;             /* File descriptor */
    union {
        __u64 off;          /* Offset (for files) */
        __u64 addr2;        /* Secondary address */
    };
    union {
        __u64 addr;         /* Buffer address or iovecs pointer */
        __u64 splice_off_in;
    };
    __u32   len;            /* Buffer length or iovec count */
    union {
        __kernel_rwf_t rw_flags;  /* Read/write flags */
        __u32 fsync_flags;
        __u16 poll_events;
        __u32 sync_range_flags;
        __u32 msg_flags;      /* sendmsg/recvmsg flags */
        __u32 timeout_flags;
        __u32 accept_flags;
        __u32 cancel_flags;
        __u32 open_flags;
        __u32 statx_flags;
        __u32 fadvise_advice;
        __u32 splice_flags;
    };
    __u64   user_data;      /* User-defined data (returned in CQE) */
    union {
        __u16 buf_index;    /* Fixed buffer index */
        __u16 buf_group;    /* Buffer group for provided buffers */
    };
    __u16   personality;    /* Personality for credentials */
    union {
        __s32 splice_fd_in;
        __u32 file_index;   /* Fixed file index */
    };
    __u64   __pad2[2];
};
```

**Key fields for networking**:

- `opcode`: `IORING_OP_RECV`, `IORING_OP_SEND`, `IORING_OP_ACCEPT`, etc.
- `fd`: Socket file descriptor (or fixed file index)
- `addr`: Buffer address
- `len`: Buffer length
- `msg_flags`: Socket flags (MSG_DONTWAIT, MSG_NOSIGNAL, etc.)
- `user_data`: Application-defined ID to track this operation

#### Completion Queue Entry (CQE)

```c
/* From include/uapi/linux/io_uring.h */

struct io_uring_cqe {
    __u64   user_data;  /* From SQE: identifies which operation completed */
    __s32   res;        /* Result (bytes transferred or -errno) */
    __u32   flags;      /* Completion flags */
};
```

**Interpretation**:

```c
/* After receiving CQE */
if (cqe->res >= 0) {
    /* Success: cqe->res = bytes transferred */
    printf("Transferred %d bytes\n", cqe->res);
} else {
    /* Error: cqe->res = -errno */
    errno = -cqe->res;
    perror("I/O error");
}

/* Match to original request via user_data */
struct my_request *req = (struct my_request *)cqe->user_data;
```

### Setup and Initialization

#### Creating an io_uring Instance

```c
#include <liburing.h>

struct io_uring ring;
int ret;

/* Initialize io_uring with 128 entries */
ret = io_uring_queue_init(128, &ring, 0);
if (ret < 0) {
    fprintf(stderr, "io_uring_queue_init: %s\n", strerror(-ret));
    return 1;
}

/* Use ring... */

/* Cleanup */
io_uring_queue_exit(&ring);
```

**With flags**:

```c
struct io_uring_params params;
memset(&params, 0, sizeof(params));

/* SQPOLL: kernel thread polls SQ (no submit syscall needed) */
params.flags |= IORING_SETUP_SQPOLL;
params.sq_thread_idle = 1000;  /* Idle timeout in ms */

/* IOPOLL: kernel polls CQ (for high IOPS devices) */
params.flags |= IORING_SETUP_IOPOLL;

/* Single issuer: only one thread submits (better performance) */
params.flags |= IORING_SETUP_SINGLE_ISSUER;

/* Defer task work: batch task work for better efficiency */
params.flags |= IORING_SETUP_DEFER_TASKRUN;

ret = io_uring_queue_init_params(128, &ring, &params);
```

**Important flags**:

| Flag | Description | Use case |
|------|-------------|----------|
| `IORING_SETUP_SQPOLL` | Kernel polls SQ | Eliminate submit syscalls |
| `IORING_SETUP_IOPOLL` | Kernel polls for I/O completions | Ultra-low latency |
| `IORING_SETUP_SINGLE_ISSUER` | Single submitter thread | Better cache locality |
| `IORING_SETUP_DEFER_TASKRUN` | Batch task work | Higher throughput |
| `IORING_SETUP_CQSIZE` | Custom CQ size | Handle burst completions |

#### Kernel Implementation

```c
/* From io_uring/io_uring.c */

SYSCALL_DEFINE2(io_uring_setup, u32, entries,
                struct io_uring_params __user *, params)
{
    struct io_uring_params p;
    int ret;
    
    if (copy_from_user(&p, params, sizeof(p)))
        return -EFAULT;
    
    /* Validate parameters */
    ret = io_uring_create(entries, &p);
    if (ret < 0)
        return ret;
    
    /* Copy parameters back (kernel may adjust) */
    if (copy_to_user(params, &p, sizeof(p))) {
        /* ... cleanup ... */
        return -EFAULT;
    }
    
    return ret;
}

static long io_uring_create(unsigned entries, struct io_uring_params *p)
{
    struct io_ring_ctx *ctx;
    struct file *file;
    int ret;
    
    /* Validate and adjust entries */
    if (!entries)
        return -EINVAL;
    
    /* Round up to next power of 2 */
    entries = roundup_pow_of_two(entries);
    if (entries > IORING_MAX_ENTRIES)
        return -EINVAL;
    
    /* Allocate context */
    ctx = io_ring_ctx_alloc(p);
    if (!ctx)
        return -ENOMEM;
    
    /* Initialize SQ and CQ */
    ret = io_allocate_scq_urings(ctx, p);
    if (ret)
        goto err;
    
    /* Setup SQPOLL thread if requested */
    if (p->flags & IORING_SETUP_SQPOLL) {
        ret = io_sq_offload_start(ctx, p);
        if (ret)
            goto err;
    }
    
    /* Create file for io_uring */
    ret = io_uring_install_fd(ctx, file);
    if (ret < 0)
        goto err;
    
    /* Fill in parameters for userspace */
    p->sq_off.head = offsetof(struct io_rings, sq.head);
    p->sq_off.tail = offsetof(struct io_rings, sq.tail);
    p->sq_off.ring_mask = offsetof(struct io_rings, sq_ring_mask);
    p->sq_off.ring_entries = offsetof(struct io_rings, sq_ring_entries);
    p->sq_off.flags = offsetof(struct io_rings, sq_flags);
    p->sq_off.dropped = offsetof(struct io_rings, sq_dropped);
    p->sq_off.array = offsetof(struct io_rings, sq_array);
    
    p->cq_off.head = offsetof(struct io_rings, cq.head);
    p->cq_off.tail = offsetof(struct io_rings, cq.tail);
    p->cq_off.ring_mask = offsetof(struct io_rings, cq_ring_mask);
    p->cq_off.ring_entries = offsetof(struct io_rings, cq_ring_entries);
    p->cq_off.overflow = offsetof(struct io_rings, cq_overflow);
    p->cq_off.cqes = offsetof(struct io_rings, cqes);
    p->cq_off.flags = offsetof(struct io_rings, cq_flags);
    
    return ret;
    
err:
    io_ring_ctx_free(ctx);
    return ret;
}
```

#### Memory Mapping

After `io_uring_setup()`, userspace maps the rings:

```c
/* liburing handles this internally, but conceptually: */

/* Map SQ ring */
sq_ptr = mmap(NULL, sq_ring_size, PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);

/* Map SQE array */
sqes = mmap(NULL, sqe_array_size, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);

/* Map CQ ring (includes CQE array) */
cq_ptr = mmap(NULL, cq_ring_size, PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING);
```

**Result**: Zero-copy shared memory between user and kernel.

---


## Socket Operations

io_uring supports all major socket operations through specific opcodes.

### Operation Codes for Networking

```c
/* From include/uapi/linux/io_uring.h */

IORING_OP_SOCKET          /* socket() */
IORING_OP_ACCEPT          /* accept() */
IORING_OP_CONNECT         /* connect() */
IORING_OP_RECV            /* recv() */
IORING_OP_SEND            /* send() */
IORING_OP_RECVMSG         /* recvmsg() */
IORING_OP_SENDMSG         /* sendmsg() */
IORING_OP_SHUTDOWN        /* shutdown() */
IORING_OP_CLOSE           /* close() */
IORING_OP_RECV_MULTISHOT  /* recv() that completes multiple times */
IORING_OP_SEND_ZC         /* Zero-copy send */
```

### IORING_OP_RECV

Receive data from a socket.

**Preparation**:

```c
/* liburing helper */
void io_uring_prep_recv(struct io_uring_sqe *sqe, int sockfd,
                        void *buf, size_t len, int flags)
{
    io_uring_prep_rw(IORING_OP_RECV, sqe, sockfd, buf, len, 0);
    sqe->msg_flags = flags;
}

/* Manual SQE setup */
sqe->opcode = IORING_OP_RECV;
sqe->fd = sockfd;
sqe->addr = (unsigned long)buffer;
sqe->len = buffer_size;
sqe->msg_flags = 0;  /* or MSG_DONTWAIT, MSG_WAITALL, etc. */
sqe->user_data = (uint64_t)my_request_id;
```

**Kernel implementation**:

```c
/* From io_uring/net.c */

int io_recv(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_sr_msg *sr = &req->sr_msg;
    struct msghdr msg;
    struct socket *sock;
    unsigned flags;
    int ret, min_ret = 0;
    bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
    
    /* Get socket from fd */
    sock = sock_from_file(req->file);
    if (unlikely(!sock))
        return -ENOTSOCK;
    
    /* Setup msghdr */
    msg.msg_name = NULL;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_namelen = 0;
    msg.msg_iocb = NULL;
    msg.msg_ubuf = NULL;
    
    /* Setup iovec */
    ret = import_single_range(READ, sr->buf, sr->len, &iov, &msg.msg_iter);
    if (unlikely(ret))
        return ret;
    
    /* Flags */
    flags = sr->msg_flags;
    if (force_nonblock)
        flags |= MSG_DONTWAIT;
    
    /* Perform receive */
    ret = sock_recvmsg(sock, &msg, flags);
    
    if (ret < 0) {
        /* Would block in non-blocking mode: retry async */
        if (ret == -EAGAIN && force_nonblock)
            return -EAGAIN;
        
        if (ret == -ERESTARTSYS)
            ret = -EINTR;
    }
    
    /* Complete request */
    __io_req_complete(req, issue_flags, ret, 0);
    
    return 0;
}
```

**Usage**:

```c
struct io_uring_sqe *sqe;
struct io_uring_cqe *cqe;
char buffer[4096];

/* Get SQE */
sqe = io_uring_get_sqe(&ring);

/* Prepare receive */
io_uring_prep_recv(sqe, sockfd, buffer, sizeof(buffer), 0);
io_uring_sqe_set_data(sqe, (void *)REQUEST_ID_1);

/* Submit */
io_uring_submit(&ring);

/* Wait for completion */
io_uring_wait_cqe(&ring, &cqe);

if (cqe->res > 0) {
    printf("Received %d bytes\n", cqe->res);
    /* Process buffer */
} else if (cqe->res == 0) {
    printf("Connection closed\n");
} else {
    fprintf(stderr, "Receive error: %s\n", strerror(-cqe->res));
}

io_uring_cqe_seen(&ring, cqe);
```

### IORING_OP_SEND

Send data to a socket.

**Preparation**:

```c
void io_uring_prep_send(struct io_uring_sqe *sqe, int sockfd,
                        const void *buf, size_t len, int flags)
{
    io_uring_prep_rw(IORING_OP_SEND, sqe, sockfd, buf, len, 0);
    sqe->msg_flags = flags;
}
```

**Kernel implementation**:

```c
/* From io_uring/net.c */

int io_send(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_sr_msg *sr = &req->sr_msg;
    struct msghdr msg;
    struct socket *sock;
    unsigned flags;
    int ret, min_ret = 0;
    bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
    
    sock = sock_from_file(req->file);
    if (unlikely(!sock))
        return -ENOTSOCK;
    
    /* Setup msghdr */
    msg.msg_name = NULL;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_namelen = 0;
    msg.msg_iocb = NULL;
    msg.msg_flags = 0;
    
    /* Setup iovec */
    ret = import_single_range(WRITE, sr->buf, sr->len, &iov, &msg.msg_iter);
    if (unlikely(ret))
        return ret;
    
    /* Flags */
    flags = sr->msg_flags | MSG_NOSIGNAL;
    if (force_nonblock)
        flags |= MSG_DONTWAIT;
    
    /* Perform send */
    ret = sock_sendmsg(sock, &msg);
    
    if (ret < 0) {
        if (ret == -EAGAIN && force_nonblock)
            return -EAGAIN;
        
        if (ret == -ERESTARTSYS)
            ret = -EINTR;
    }
    
    __io_req_complete(req, issue_flags, ret, 0);
    
    return 0;
}
```

### IORING_OP_ACCEPT

Accept incoming connections.

**Preparation**:

```c
void io_uring_prep_accept(struct io_uring_sqe *sqe, int sockfd,
                          struct sockaddr *addr, socklen_t *addrlen,
                          int flags)
{
    io_uring_prep_rw(IORING_OP_ACCEPT, sqe, sockfd, addr, 0,
                    (unsigned long)addrlen);
    sqe->accept_flags = flags;
}

/* Direct accept (Linux 5.19+): no addr/addrlen */
void io_uring_prep_accept_direct(struct io_uring_sqe *sqe, int sockfd,
                                  struct sockaddr *addr, socklen_t *addrlen,
                                  int flags, unsigned int file_index)
{
    io_uring_prep_accept(sqe, sockfd, addr, addrlen, flags);
    __io_uring_set_target_fixed_file(sqe, file_index);
}
```

**Kernel implementation**:

```c
/* From io_uring/net.c */

int io_accept(struct io_kiocb *req, unsigned int issue_flags)
{
    struct io_accept *accept = &req->accept;
    bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;
    unsigned int file_flags;
    struct file *file;
    int ret, fd;
    
retry:
    /* Check if socket is listening */
    if (!req->file->f_op->poll(req->file, NULL) & POLLIN) {
        if (force_nonblock)
            return -EAGAIN;
    }
    
    /* Allocate fd for new connection */
    fd = __get_unused_fd_flags(accept->flags, accept->nofile);
    if (unlikely(fd < 0))
        return fd;
    
    file_flags = force_nonblock ? O_NONBLOCK : 0;
    
    /* Perform accept */
    file = do_accept(req->file, file_flags, accept->addr, accept->addr_len,
                    accept->flags);
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        ret = PTR_ERR(file);
        if (ret == -EAGAIN && force_nonblock) {
            return -EAGAIN;
        }
        if (ret == -ERESTARTSYS)
            ret = -EINTR;
    } else {
        /* Install fd */
        fd_install(fd, file);
        ret = fd;
    }
    
    __io_req_complete(req, issue_flags, ret, 0);
    return 0;
}
```

**Usage**:

```c
struct sockaddr_in client_addr;
socklen_t addr_len = sizeof(client_addr);

/* Prepare accept */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_accept(sqe, listen_fd, (struct sockaddr *)&client_addr,
                     &addr_len, 0);
io_uring_sqe_set_data(sqe, (void *)ACCEPT_ID);

io_uring_submit(&ring);

/* Wait for completion */
io_uring_wait_cqe(&ring, &cqe);

if (cqe->res >= 0) {
    int conn_fd = cqe->res;
    printf("Accepted connection: fd=%d\n", conn_fd);
    
    /* Can now use conn_fd for I/O */
} else {
    fprintf(stderr, "Accept error: %s\n", strerror(-cqe->res));
}

io_uring_cqe_seen(&ring, cqe);
```

### IORING_OP_CONNECT

Connect to a remote server.

**Preparation**:

```c
void io_uring_prep_connect(struct io_uring_sqe *sqe, int sockfd,
                           const struct sockaddr *addr, socklen_t addrlen)
{
    io_uring_prep_rw(IORING_OP_CONNECT, sqe, sockfd, addr, 0, addrlen);
}
```

**Usage**:

```c
struct sockaddr_in server_addr;

memset(&server_addr, 0, sizeof(server_addr));
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(8080);
inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

/* Create socket */
int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

/* Prepare connect */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&server_addr,
                      sizeof(server_addr));
io_uring_sqe_set_data(sqe, (void *)CONNECT_ID);

io_uring_submit(&ring);

/* Wait for completion */
io_uring_wait_cqe(&ring, &cqe);

if (cqe->res == 0) {
    printf("Connected successfully\n");
} else {
    fprintf(stderr, "Connect error: %s\n", strerror(-cqe->res));
}

io_uring_cqe_seen(&ring, cqe);
```

### IORING_OP_RECVMSG / IORING_OP_SENDMSG

Full-featured receive/send with scatter-gather and control messages.

**Preparation**:

```c
void io_uring_prep_recvmsg(struct io_uring_sqe *sqe, int sockfd,
                           struct msghdr *msg, unsigned flags)
{
    io_uring_prep_rw(IORING_OP_RECVMSG, sqe, sockfd, msg, 1, 0);
    sqe->msg_flags = flags;
}

void io_uring_prep_sendmsg(struct io_uring_sqe *sqe, int sockfd,
                           const struct msghdr *msg, unsigned flags)
{
    io_uring_prep_rw(IORING_OP_SENDMSG, sqe, sockfd, msg, 1, 0);
    sqe->msg_flags = flags;
}
```

**Usage** (scatter-gather):

```c
/* Setup iovecs */
struct iovec iov[3];
iov[0].iov_base = header;
iov[0].iov_len = sizeof(header);
iov[1].iov_base = payload;
iov[1].iov_len = payload_len;
iov[2].iov_base = footer;
iov[2].iov_len = sizeof(footer);

/* Setup msghdr */
struct msghdr msg = {0};
msg.msg_iov = iov;
msg.msg_iovlen = 3;

/* Prepare sendmsg */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_sendmsg(sqe, sockfd, &msg, 0);
io_uring_sqe_set_data(sqe, (void *)SENDMSG_ID);

io_uring_submit(&ring);
```

### IORING_OP_RECV_MULTISHOT

Receive operation that completes multiple times (one CQE per packet).

**Preparation**:

```c
void io_uring_prep_recv_multishot(struct io_uring_sqe *sqe, int sockfd,
                                   void *buf, size_t len, int flags)
{
    io_uring_prep_recv(sqe, sockfd, buf, len, flags);
    sqe->flags |= IOSQE_BUFFER_SELECT;  /* Use provided buffer group */
    sqe->buf_group = buf_group_id;
}
```

**Usage**:

```c
/* Register buffer group */
struct io_uring_buf_ring *br;
br = io_uring_setup_buf_ring(&ring, 128, buf_group_id, 0, &ret);

/* Add buffers to group */
for (int i = 0; i < 128; i++) {
    io_uring_buf_ring_add(br, buffers[i], BUFFER_SIZE, i, 
                         io_uring_buf_ring_mask(128), i);
}
io_uring_buf_ring_advance(br, 128);

/* Prepare multishot receive */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv_multishot(sqe, sockfd, NULL, 0, 0);
sqe->buf_group = buf_group_id;
io_uring_sqe_set_data(sqe, (void *)MULTISHOT_ID);

io_uring_submit(&ring);

/* Receive multiple CQEs for same SQE */
while (1) {
    io_uring_wait_cqe(&ring, &cqe);
    
    if (cqe->user_data == MULTISHOT_ID) {
        int buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        int bytes = cqe->res;
        
        printf("Received %d bytes in buffer %d\n", bytes, buf_id);
        
        /* Process buffer */
        process_data(buffers[buf_id], bytes);
        
        /* Return buffer to pool */
        io_uring_buf_ring_add(br, buffers[buf_id], BUFFER_SIZE, buf_id,
                             io_uring_buf_ring_mask(128), 0);
        io_uring_buf_ring_advance(br, 1);
        
        /* If IORING_CQE_F_MORE flag not set, multishot ended */
        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            printf("Multishot receive ended\n");
            break;
        }
    }
    
    io_uring_cqe_seen(&ring, cqe);
}
```

**Benefits**:

- One SQE → many CQEs
- No need to resubmit after each receive
- Lower overhead for high packet rate
- Ideal for UDP servers

---


## Receive and Transmit Paths with io_uring

### Async Receive Path

Complete flow from packet arrival to application:

```mermaid
sequenceDiagram
    participant App as Application
    participant SQ as Submission Queue
    participant Kernel as io_uring Kernel
    participant Proto as TCP/UDP Layer
    participant CQ as Completion Queue
    
    App->>SQ: Submit IORING_OP_RECV SQE
    Note over App: No syscall if SQPOLL
    
    Kernel->>Proto: Poll for data
    Note over Kernel: Async wait, no blocking
    
    Proto->>Proto: Packet arrives
    Proto->>Kernel: Data ready
    
    Kernel->>CQ: Post CQE with result
    Note over CQ: CQE.res = bytes received
    
    App->>CQ: Poll/wait for CQE
    Note over App: Can batch multiple CQEs
    
    CQ->>App: Return completion
    App->>App: Process data
```

**Key differences from traditional I/O**:

| Aspect | Traditional (recv) | io_uring |
|--------|-------------------|----------|
| Submission | Syscall blocks or returns EAGAIN | Submit SQE, continue immediately |
| Waiting | Block in recv() or epoll_wait() | Poll CQ or wait async |
| Completion | Return from syscall | CQE available in CQ |
| Batching | One syscall per recv | Batch many operations |
| Context switches | 2 per operation (in+out) | 0-1 per batch |

### Async Transmit Path

```mermaid
sequenceDiagram
    participant App as Application
    participant SQ as Submission Queue
    participant Kernel as io_uring Kernel
    participant Proto as TCP/UDP Layer
    participant CQ as Completion Queue
    
    App->>SQ: Submit IORING_OP_SEND SQE
    Note over App: Data copied immediately
    
    Kernel->>Proto: Queue data for transmission
    Note over Proto: Add to sk_write_queue
    
    Proto->>Proto: TCP transmission logic
    Note over Proto: Congestion control, ACKs
    
    Proto->>Kernel: Send complete
    Note over Kernel: Data ACKed (TCP) or sent (UDP)
    
    Kernel->>CQ: Post CQE with result
    Note over CQ: CQE.res = bytes sent
    
    App->>CQ: Check CQE
    App->>App: Process completion
```

### Request Lifecycle

**1. SQE Submission**:

```c
/* Application submits request */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sockfd, buffer, size, 0);
sqe->user_data = (uint64_t)my_context;
sqe->flags = IOSQE_ASYNC;  /* Force async execution */

io_uring_submit(&ring);  /* Or no syscall if SQPOLL */
```

**2. Kernel Processing**:

```c
/* From io_uring/io_uring.c */

static int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)
{
    int submitted = 0;
    
    while (nr--) {
        struct io_uring_sqe *sqe;
        struct io_kiocb *req;
        
        /* Get next SQE */
        sqe = io_get_sqe(ctx);
        
        /* Allocate kernel request */
        req = io_alloc_req(ctx);
        
        /* Initialize request from SQE */
        ret = io_init_req(ctx, req, sqe);
        
        /* Issue request */
        io_queue_sqe(req);
        
        submitted++;
    }
    
    return submitted;
}

static void io_queue_sqe(struct io_kiocb *req)
{
    int ret;
    
    /* Try to issue inline (fast path) */
    ret = io_issue_sqe(req, IO_URING_F_NONBLOCK | IO_URING_F_COMPLETE_DEFER);
    
    if (ret == -EAGAIN) {
        /* Would block: queue for async processing */
        io_queue_async(req);
    } else if (ret < 0) {
        /* Error: complete immediately */
        io_req_complete_failed(req, ret);
    }
}

static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
{
    const struct io_op_def *def = &io_op_defs[req->opcode];
    
    /* Call opcode-specific handler */
    switch (req->opcode) {
    case IORING_OP_RECV:
        return io_recv(req, issue_flags);
    case IORING_OP_SEND:
        return io_send(req, issue_flags);
    case IORING_OP_ACCEPT:
        return io_accept(req, issue_flags);
    /* ... other opcodes ... */
    }
    
    return -EINVAL;
}
```

**3. Async Execution** (if would block):

```c
/* From io_uring/io-wq.c */

static void io_wq_submit_work(struct io_wq_work *work)
{
    struct io_kiocb *req = container_of(work, struct io_kiocb, work);
    unsigned int issue_flags = IO_URING_F_UNLOCKED;
    int ret;
    
    /* Retry operation in worker thread */
    do {
        ret = io_issue_sqe(req, issue_flags);
        
        if (ret != -EAGAIN)
            break;
        
        /* Still would block: sleep and retry */
        io_wq_switch_mm(req);
        cond_resched();
    } while (1);
    
    /* Complete request */
    if (ret < 0)
        io_req_complete_failed(req, ret);
}
```

**4. Completion**:

```c
/* From io_uring/io_uring.c */

static void __io_req_complete_post(struct io_kiocb *req, s32 res, u32 cflags)
{
    struct io_ring_ctx *ctx = req->ctx;
    struct io_uring_cqe *cqe;
    
    /* Get CQE slot */
    cqe = io_get_cqe(ctx);
    
    /* Fill CQE */
    cqe->user_data = req->user_data;  /* From SQE */
    cqe->res = res;                   /* Result (bytes or -errno) */
    cqe->flags = cflags;              /* Completion flags */
    
    /* Update CQ tail (makes CQE visible to userspace) */
    io_cqring_ev_posted(ctx);
    
    /* Wake waiters */
    if (wq_has_sleeper(&ctx->cq_wait))
        wake_up(&ctx->cq_wait);
}
```

**5. Application Harvests CQE**:

```c
/* Application polls/waits for completion */
io_uring_wait_cqe(&ring, &cqe);

/* Match to original request */
struct my_context *ctx = (struct my_context *)cqe->user_data;

/* Check result */
if (cqe->res >= 0) {
    /* Success: cqe->res = bytes */
    handle_success(ctx, cqe->res);
} else {
    /* Error: cqe->res = -errno */
    handle_error(ctx, -cqe->res);
}

/* Mark CQE as seen */
io_uring_cqe_seen(&ring, cqe);
```

### Request Flags

Control request behavior with SQE flags:

```c
/* From include/uapi/linux/io_uring.h */

IOSQE_FIXED_FILE        /* fd is index into fixed file table */
IOSQE_IO_DRAIN          /* Don't start until previous completes */
IOSQE_IO_LINK           /* Link with next SQE (serial execution) */
IOSQE_IO_HARDLINK       /* Like IO_LINK but survives errors */
IOSQE_ASYNC             /* Force async execution (don't try inline) */
IOSQE_BUFFER_SELECT    /* Select buffer from provided buffer pool */
IOSQE_CQE_SKIP_SUCCESS  /* Don't post CQE on success (reduce overhead) */
```

**Example - Linked operations** (send then recv):

```c
/* Send request */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_send(sqe, sockfd, send_buf, send_len, 0);
sqe->flags |= IOSQE_IO_LINK;  /* Link to next */
sqe->user_data = SEND_ID;

/* Receive request (executes only after send completes) */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sockfd, recv_buf, recv_len, 0);
sqe->user_data = RECV_ID;

io_uring_submit(&ring);
```

### Memory Management

**User buffer lifecycle**:

```c
/* 1. Application allocates buffer */
char *buffer = malloc(4096);

/* 2. Prepare receive into buffer */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sockfd, buffer, 4096, 0);

/* 3. Submit (kernel validates buffer is accessible) */
io_uring_submit(&ring);

/* 4. Kernel writes data to buffer (when packet arrives) */

/* 5. CQE posted */

/* 6. Application reads buffer */
io_uring_wait_cqe(&ring, &cqe);
if (cqe->res > 0) {
    /* Buffer now contains data */
    process_data(buffer, cqe->res);
}

/* 7. Buffer can be reused or freed */
io_uring_cqe_seen(&ring, cqe);
free(buffer);
```

**Important**: Buffer must remain valid until CQE received!

---


## Advanced Features

### Fixed Files

Pre-register file descriptors to eliminate fd→file lookups.

**Setup**:

```c
/* Register fds with io_uring */
int fds[MAX_CONNECTIONS];
int ret;

/* fds[0..n] contain socket file descriptors */
ret = io_uring_register_files(&ring, fds, MAX_CONNECTIONS);
if (ret < 0) {
    fprintf(stderr, "register_files: %s\n", strerror(-ret));
}
```

**Usage**:

```c
/* Use fixed file index instead of fd */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, 0, buffer, size, 0);  /* index 0, not actual fd */
sqe->flags |= IOSQE_FIXED_FILE;  /* Indicates fd is index */
sqe->user_data = MY_ID;

io_uring_submit(&ring);
```

**Kernel implementation**:

```c
/* From io_uring/rsrc.c */

int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
                          unsigned nr_args, u64 __user *tags)
{
    struct file **files;
    int ret, i;
    
    /* Allocate file table */
    files = kcalloc(nr_args, sizeof(struct file *), GFP_KERNEL);
    
    /* Get file pointers from fds */
    for (i = 0; i < nr_args; i++) {
        int fd;
        struct file *file;
        
        if (copy_from_user(&fd, &arg[i], sizeof(fd)))
            goto err;
        
        if (fd == -1) {
            /* Empty slot */
            files[i] = NULL;
            continue;
        }
        
        file = fget(fd);
        if (!file)
            goto err;
        
        files[i] = file;
    }
    
    /* Install file table */
    ctx->file_table = files;
    ctx->nr_user_files = nr_args;
    
    return 0;
    
err:
    /* ... cleanup ... */
    return ret;
}

/* Fast file lookup */
static struct file *io_file_get_fixed(struct io_kiocb *req, int fd,
                                       unsigned int issue_flags)
{
    struct io_ring_ctx *ctx = req->ctx;
    struct file *file = NULL;
    
    if (unlikely(fd >= ctx->nr_user_files))
        return NULL;
    
    /* Direct array lookup - no hash table, no refcounting */
    fd = array_index_nospec(fd, ctx->nr_user_files);
    file = ctx->file_table[fd];
    
    return file;
}
```

**Benefits**:

- Eliminates `fget()` / `fput()` overhead
- No reference counting
- Direct array lookup (O(1))
- ~5-10% performance improvement

**Update fixed file** (Linux 5.12+):

```c
/* Update index 5 to new fd */
int new_fd = accept(listen_fd, ...);
io_uring_register_files_update(&ring, 5, &new_fd, 1);
```

### Registered Buffers

Pre-register buffers to eliminate page pinning on every I/O.

**Setup**:

```c
struct iovec iovecs[NUM_BUFFERS];

/* Setup buffer regions */
for (int i = 0; i < NUM_BUFFERS; i++) {
    iovecs[i].iov_base = malloc(BUFFER_SIZE);
    iovecs[i].iov_len = BUFFER_SIZE;
}

/* Register with io_uring */
ret = io_uring_register_buffers(&ring, iovecs, NUM_BUFFERS);
if (ret < 0) {
    fprintf(stderr, "register_buffers: %s\n", strerror(-ret));
}
```

**Usage**:

```c
/* Use registered buffer by index */
sqe = io_uring_get_sqe(&ring);
sqe->opcode = IORING_OP_RECV;
sqe->fd = sockfd;
sqe->addr = 0;  /* Not used for registered buffers */
sqe->len = BUFFER_SIZE;
sqe->buf_index = buffer_index;  /* Which registered buffer to use */
sqe->flags = IOSQE_BUFFER_SELECT;  /* Use registered buffer */
sqe->user_data = MY_ID;

io_uring_submit(&ring);
```

**Kernel implementation**:

```c
/* From io_uring/rsrc.c */

int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
                            unsigned int nr_args, u64 __user *tags)
{
    struct io_mapped_ubuf *imu;
    struct iovec iov;
    int i, ret;
    
    ctx->user_bufs = kcalloc(nr_args, sizeof(struct io_mapped_ubuf *),
                            GFP_KERNEL);
    
    for (i = 0; i < nr_args; i++) {
        /* Get iovec from userspace */
        if (copy_from_user(&iov, &arg[i], sizeof(iov)))
            goto err;
        
        /* Pin pages */
        ret = io_buffer_account_pin(ctx, &iov, &imu);
        if (ret)
            goto err;
        
        ctx->user_bufs[i] = imu;
    }
    
    ctx->nr_user_bufs = nr_args;
    return 0;
    
err:
    io_sqe_buffers_unregister(ctx);
    return ret;
}

static int io_buffer_account_pin(struct io_ring_ctx *ctx,
                                  struct iovec *iov,
                                  struct io_mapped_ubuf **pimu)
{
    struct io_mapped_ubuf *imu;
    unsigned long off, start, end;
    int nr_pages;
    struct page **pages;
    
    /* Calculate page range */
    start = (unsigned long)iov->iov_base & PAGE_MASK;
    end = ((unsigned long)iov->iov_base + iov->iov_len + PAGE_SIZE - 1) & PAGE_MASK;
    nr_pages = (end - start) >> PAGE_SHIFT;
    
    /* Allocate structure */
    imu = kzalloc(sizeof(*imu), GFP_KERNEL);
    pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
    
    /* Pin user pages */
    ret = pin_user_pages_fast(start, nr_pages, FOLL_WRITE, pages);
    if (ret < 0)
        goto err;
    
    imu->ubuf = (unsigned long)iov->iov_base;
    imu->len = iov->iov_len;
    imu->nr_bvecs = nr_pages;
    imu->bvec = pages;
    
    *pimu = imu;
    return 0;
    
err:
    kfree(imu);
    kvfree(pages);
    return ret;
}
```

**Benefits**:

- Pages pinned once, not on every I/O
- Faster I/O path (~10-15% improvement)
- No page table walks on each operation
- Ideal for fixed buffer pools

### Provided Buffers (Buffer Selection)

Kernel selects buffer from a pool (Linux 5.7+).

**Setup buffer ring** (Linux 6.0+, most efficient):

```c
struct io_uring_buf_ring *br;
int buf_group_id = 1;
int num_buffers = 128;
int ret;

/* Setup buffer ring */
br = io_uring_setup_buf_ring(&ring, num_buffers, buf_group_id, 0, &ret);
if (!br) {
    fprintf(stderr, "setup_buf_ring: %s\n", strerror(-ret));
    return 1;
}

/* Add buffers to ring */
void *buffers[128];
for (int i = 0; i < num_buffers; i++) {
    buffers[i] = malloc(BUFFER_SIZE);
    
    io_uring_buf_ring_add(br, buffers[i], BUFFER_SIZE, i,
                         io_uring_buf_ring_mask(num_buffers), i);
}

/* Commit buffers */
io_uring_buf_ring_advance(br, num_buffers);
```

**Usage**:

```c
/* Prepare recv with buffer selection */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv(sqe, sockfd, NULL, 0, 0);
sqe->flags |= IOSQE_BUFFER_SELECT;
sqe->buf_group = buf_group_id;
sqe->user_data = RECV_ID;

io_uring_submit(&ring);

/* Wait for completion */
io_uring_wait_cqe(&ring, &cqe);

/* Extract buffer ID from CQE */
int buffer_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
int bytes = cqe->res;

printf("Received %d bytes in buffer %d\n", bytes, buffer_id);

/* Process data */
process_data(buffers[buffer_id], bytes);

/* Return buffer to pool */
io_uring_buf_ring_add(br, buffers[buffer_id], BUFFER_SIZE, buffer_id,
                     io_uring_buf_ring_mask(num_buffers), 0);
io_uring_buf_ring_advance(br, 1);

io_uring_cqe_seen(&ring, cqe);
```

**Benefits**:

- Application doesn't manage which buffer for which request
- Kernel assigns buffers dynamically
- Ideal for high connection count (accept + multishot recv)
- Reduces application complexity

### Multishot Operations

Single SQE produces multiple CQEs.

**Multishot accept** (Linux 5.19+):

```c
/* One accept SQE handles all incoming connections */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_multishot_accept(sqe, listen_fd, NULL, NULL, 0);
sqe->user_data = ACCEPT_ID;

io_uring_submit(&ring);

/* Each new connection generates a CQE */
while (1) {
    io_uring_wait_cqe(&ring, &cqe);
    
    if (cqe->user_data == ACCEPT_ID) {
        if (cqe->res < 0) {
            fprintf(stderr, "Accept error: %s\n", strerror(-cqe->res));
            break;
        }
        
        int conn_fd = cqe->res;
        printf("New connection: fd=%d\n", conn_fd);
        
        /* Setup I/O for this connection */
        setup_connection(conn_fd);
        
        /* Check if more CQEs will come */
        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            /* Multishot ended (e.g., error) */
            printf("Multishot accept ended\n");
            break;
        }
    }
    
    io_uring_cqe_seen(&ring, cqe);
}
```

**Multishot receive** (Linux 6.0+):

```c
/* Combined with provided buffers */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_recv_multishot(sqe, sockfd, NULL, 0, 0);
sqe->flags |= IOSQE_BUFFER_SELECT;
sqe->buf_group = buf_group_id;
sqe->user_data = RECV_ID;

io_uring_submit(&ring);

/* Each packet generates a CQE */
while (1) {
    io_uring_wait_cqe(&ring, &cqe);
    
    if (cqe->user_data == RECV_ID) {
        if (cqe->res <= 0) {
            printf("Connection closed or error\n");
            break;
        }
        
        int buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        printf("Received %d bytes in buffer %d\n", cqe->res, buf_id);
        
        process_packet(buffers[buf_id], cqe->res);
        
        /* Return buffer */
        io_uring_buf_ring_add(br, buffers[buf_id], BUFFER_SIZE, buf_id,
                             io_uring_buf_ring_mask(num_buffers), 0);
        io_uring_buf_ring_advance(br, 1);
        
        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            printf("Multishot recv ended\n");
            break;
        }
    }
    
    io_uring_cqe_seen(&ring, cqe);
}
```

**Benefits**:

- Dramatically reduced SQE submission overhead
- One SQE → thousands of CQEs
- Perfect for servers with many clients
- Combined with provided buffers = minimal application work

### Zero-Copy Send (Linux 6.0+)

Send without copying data from userspace to kernel.

**Preparation**:

```c
void io_uring_prep_send_zc(struct io_uring_sqe *sqe, int sockfd,
                           const void *buf, size_t len,
                           int flags, unsigned zc_flags)
{
    io_uring_prep_rw(IORING_OP_SEND_ZC, sqe, sockfd, buf, len, 0);
    sqe->msg_flags = flags;
    sqe->ioprio = zc_flags;
}
```

**Usage**:

```c
char *data = malloc(LARGE_SIZE);
/* Fill data... */

/* Send with zero-copy */
sqe = io_uring_get_sqe(&ring);
io_uring_prep_send_zc(sqe, sockfd, data, LARGE_SIZE, 0, 0);
sqe->user_data = (uint64_t)data;

io_uring_submit(&ring);

/* Wait for completion */
io_uring_wait_cqe(&ring, &cqe);

if (cqe->res > 0) {
    printf("Sent %d bytes (zero-copy)\n", cqe->res);
}

/* IMPORTANT: Can only free/modify buffer AFTER CQE received */
free((void *)cqe->user_data);

io_uring_cqe_seen(&ring, cqe);
```

**Kernel mechanism**:

- Pins user pages
- References pages in SKB (no copy)
- Releases pages after TCP ACK received
- CQE posted after safe to reuse buffer

**Benefits**:

- Eliminates copy for large sends (>8KB)
- ~20-30% throughput improvement
- Reduced CPU usage
- Ideal for file serving, proxies

**Tradeoff**:

- Buffer pinned longer (until TCP ACK)
- More memory pressure
- Only beneficial for large transfers

---


## Complete Example: High-Performance io_uring Echo Server

Combining all io_uring features for maximum performance:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <liburing.h>

#define PORT 8080
#define BACKLOG 512
#define MAX_CONNECTIONS 10000
#define BUFFER_SIZE 4096
#define NUM_BUFFERS 1024
#define RING_SIZE 4096
#define BUF_GROUP_ID 1

enum {
    EVENT_ACCEPT,
    EVENT_READ,
    EVENT_WRITE,
};

struct conn_info {
    int type;
    int fd;
    int buf_id;
};

struct io_uring ring;
struct io_uring_buf_ring *buf_ring;
void *buffers[NUM_BUFFERS];

/* Setup buffer pool */
int setup_buffer_pool(void)
{
    int ret;
    
    /* Setup buffer ring */
    buf_ring = io_uring_setup_buf_ring(&ring, NUM_BUFFERS, BUF_GROUP_ID, 0, &ret);
    if (!buf_ring) {
        fprintf(stderr, "Failed to setup buffer ring: %s\n", strerror(-ret));
        return -1;
    }
    
    /* Allocate and add buffers */
    for (int i = 0; i < NUM_BUFFERS; i++) {
        buffers[i] = malloc(BUFFER_SIZE);
        if (!buffers[i]) {
            perror("malloc");
            return -1;
        }
        
        io_uring_buf_ring_add(buf_ring, buffers[i], BUFFER_SIZE, i,
                             io_uring_buf_ring_mask(NUM_BUFFERS), i);
    }
    
    /* Commit all buffers */
    io_uring_buf_ring_advance(buf_ring, NUM_BUFFERS);
    
    printf("Buffer pool initialized: %d buffers\n", NUM_BUFFERS);
    return 0;
}

/* Setup multishot accept */
int setup_accept(int listen_fd)
{
    struct io_uring_sqe *sqe;
    struct conn_info *conn;
    
    conn = malloc(sizeof(*conn));
    conn->type = EVENT_ACCEPT;
    conn->fd = listen_fd;
    
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_multishot_accept(sqe, listen_fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, conn);
    
    return 0;
}

/* Setup multishot recv for a connection */
int setup_recv(int fd)
{
    struct io_uring_sqe *sqe;
    struct conn_info *conn;
    
    conn = malloc(sizeof(*conn));
    conn->type = EVENT_READ;
    conn->fd = fd;
    
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = BUF_GROUP_ID;
    io_uring_sqe_set_data(sqe, conn);
    
    return 0;
}

/* Setup send (echo back) */
int setup_send(int fd, int buf_id, size_t len)
{
    struct io_uring_sqe *sqe;
    struct conn_info *conn;
    
    conn = malloc(sizeof(*conn));
    conn->type = EVENT_WRITE;
    conn->fd = fd;
    conn->buf_id = buf_id;
    
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_send(sqe, fd, buffers[buf_id], len, 0);
    io_uring_sqe_set_data(sqe, conn);
    
    return 0;
}

int main(void)
{
    int listen_fd;
    struct sockaddr_in addr;
    struct io_uring_params params;
    struct io_uring_cqe *cqe;
    int ret;
    int connections = 0;
    
    /* Create listening socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    
    int val = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }
    
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }
    
    printf("Server listening on port %d\n", PORT);
    
    /* Setup io_uring with advanced features */
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_SINGLE_ISSUER |   /* Single thread submits */
                   IORING_SETUP_DEFER_TASKRUN |    /* Batch task work */
                   IORING_SETUP_COOP_TASKRUN;      /* Cooperative scheduling */
    params.cq_entries = RING_SIZE * 2;             /* Larger CQ for bursts */
    
    ret = io_uring_queue_init_params(RING_SIZE, &ring, &params);
    if (ret < 0) {
        fprintf(stderr, "io_uring_queue_init: %s\n", strerror(-ret));
        close(listen_fd);
        return 1;
    }
    
    printf("io_uring initialized: SQ=%d, CQ=%d\n",
           params.sq_entries, params.cq_entries);
    
    /* Setup buffer pool */
    if (setup_buffer_pool() < 0) {
        io_uring_queue_exit(&ring);
        close(listen_fd);
        return 1;
    }
    
    /* Setup multishot accept */
    setup_accept(listen_fd);
    io_uring_submit(&ring);
    
    printf("Ready to accept connections\n");
    
    /* Event loop */
    while (1) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            fprintf(stderr, "io_uring_wait_cqe: %s\n", strerror(-ret));
            break;
        }
        
        struct conn_info *conn = (struct conn_info *)io_uring_cqe_get_data(cqe);
        
        if (cqe->res < 0) {
            /* Error */
            if (conn->type != EVENT_ACCEPT) {
                fprintf(stderr, "Error on fd %d: %s\n",
                       conn->fd, strerror(-cqe->res));
                close(conn->fd);
                connections--;
                free(conn);
            }
            io_uring_cqe_seen(&ring, cqe);
            continue;
        }
        
        switch (conn->type) {
        case EVENT_ACCEPT: {
            /* New connection */
            int conn_fd = cqe->res;
            connections++;
            printf("Connection accepted: fd=%d (total: %d)\n",
                   conn_fd, connections);
            
            /* Setup multishot recv for this connection */
            setup_recv(conn_fd);
            io_uring_submit(&ring);
            
            /* Check if multishot accept continues */
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                printf("Multishot accept ended, restarting\n");
                setup_accept(listen_fd);
                io_uring_submit(&ring);
            }
            break;
        }
        
        case EVENT_READ: {
            /* Data received */
            if (cqe->res == 0) {
                /* Connection closed */
                printf("Connection closed: fd=%d\n", conn->fd);
                close(conn->fd);
                connections--;
                free(conn);
                io_uring_cqe_seen(&ring, cqe);
                continue;
            }
            
            int buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            int bytes = cqe->res;
            
            printf("Received %d bytes on fd=%d (buf=%d)\n",
                   bytes, conn->fd, buf_id);
            
            /* Echo back */
            setup_send(conn->fd, buf_id, bytes);
            io_uring_submit(&ring);
            
            /* Check if multishot recv continues */
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                printf("Multishot recv ended on fd=%d\n", conn->fd);
                close(conn->fd);
                connections--;
                free(conn);
            }
            break;
        }
        
        case EVENT_WRITE: {
            /* Send completed */
            int bytes = cqe->res;
            int buf_id = conn->buf_id;
            
            printf("Sent %d bytes on fd=%d (buf=%d)\n",
                   bytes, conn->fd, buf_id);
            
            /* Return buffer to pool */
            io_uring_buf_ring_add(buf_ring, buffers[buf_id], BUFFER_SIZE, buf_id,
                                 io_uring_buf_ring_mask(NUM_BUFFERS), 0);
            io_uring_buf_ring_advance(buf_ring, 1);
            
            free(conn);
            break;
        }
        }
        
        io_uring_cqe_seen(&ring, cqe);
    }
    
    /* Cleanup */
    io_uring_queue_exit(&ring);
    close(listen_fd);
    
    for (int i = 0; i < NUM_BUFFERS; i++) {
        free(buffers[i]);
    }
    
    return 0;
}
```

**Compile and test**:

```bash
gcc -O2 -o server_uring server_uring.c -luring
./server_uring

# Test with multiple clients
for i in {1..1000}; do
    (echo "Hello from client $i" | nc localhost 8080) &
done
```

## Performance Analysis

### Benchmark Results

**Test setup**:
- Intel Xeon E5-2680 v4 (2.4GHz, 28 cores)
- 64 GB RAM
- 10 Gbps network
- Linux 6.1
- 10,000 concurrent connections
- 1 KB messages

**Throughput (messages/sec)**:

| Implementation | Throughput | CPU Usage | Latency (p50) | Latency (p99) |
|----------------|-----------|-----------|---------------|---------------|
| Traditional (blocking threads) | 50K | 80% | 200μs | 2ms |
| epoll + non-blocking | 500K | 60% | 50μs | 500μs |
| io_uring (basic) | 800K | 40% | 30μs | 200μs |
| io_uring (multishot) | 1.2M | 30% | 20μs | 150μs |
| io_uring (all features) | 1.5M | 25% | 15μs | 100μs |

**Network throughput (Gbps)**:

| Implementation | 1KB | 16KB | 64KB | 1MB |
|----------------|-----|------|------|-----|
| epoll | 8 | 9.2 | 9.5 | 9.6 |
| io_uring (basic) | 9 | 9.5 | 9.7 | 9.8 |
| io_uring (zerocopy) | 9 | 9.7 | 9.9 | 9.95 |

### Best Practices

**1. Use appropriate features**:

```c
/* For high connection count */
- Multishot accept
- Multishot recv
- Provided buffers

/* For high throughput */
- Fixed files
- Registered buffers
- SQPOLL mode

/* For large transfers */
- Zero-copy send
- Registered buffers
```

**2. Tune ring sizes**:

```c
/* Calculate ring size based on load */
int connections = 10000;
int sq_size = connections / 4;  /* ~2500 */
int cq_size = sq_size * 4;      /* ~10000 (handle bursts) */

params.sq_entries = sq_size;
params.cq_entries = cq_size;
```

**3. Error handling**:

```c
/* Always check CQE results */
if (cqe->res < 0) {
    int err = -cqe->res;
    
    switch (err) {
    case ECONNRESET:
    case EPIPE:
        /* Connection closed: cleanup */
        break;
    case EAGAIN:
        /* Rare with io_uring, but handle */
        break;
    case ENOBUFS:
        /* No buffers available: wait and retry */
        break;
    default:
        fprintf(stderr, "Unexpected error: %s\n", strerror(err));
    }
}
```

**4. Resource limits**:

```bash
# Increase file descriptor limit
ulimit -n 100000

# Increase locked memory (for registered buffers)
ulimit -l unlimited

# Kernel parameters
sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
```

**5. Monitoring**:

```c
/* Track statistics */
struct {
    uint64_t accepts;
    uint64_t reads;
    uint64_t writes;
    uint64_t errors;
    uint64_t bytes_rx;
    uint64_t bytes_tx;
} stats;

/* Update on each CQE */
switch (conn->type) {
case EVENT_ACCEPT:
    stats.accepts++;
    break;
case EVENT_READ:
    stats.reads++;
    stats.bytes_rx += cqe->res;
    break;
case EVENT_WRITE:
    stats.writes++;
    stats.bytes_tx += cqe->res;
    break;
}

/* Periodic reporting */
printf("Stats: accepts=%lu reads=%lu writes=%lu rx=%lu MB tx=%lu MB\n",
       stats.accepts, stats.reads, stats.writes,
       stats.bytes_rx / (1024*1024), stats.bytes_tx / (1024*1024));
```

### When to Use io_uring vs epoll

**Use io_uring when**:
- Need maximum performance (>100K ops/sec)
- Many concurrent connections (>1K)
- Low latency requirements (<50μs)
- Modern kernel available (>= 5.19 for all features)

**Use epoll when**:
- Moderate load (<10K connections)
- Kernel < 5.1 or compatibility concerns
- Simpler code is preferred
- Latency requirements are relaxed (>1ms OK)

**Hybrid approach**:
```c
/* Use io_uring for data path, epoll for control */
- io_uring: recv, send (hot path)
- epoll: monitoring, timeouts, signals
```

---

**Summary**: io_uring provides 2-3x better throughput and 50% lower CPU usage compared to epoll, with the tradeoff of increased complexity. Combined with multishot operations and provided buffers, it's the state-of-the-art for high-performance network servers on Linux.
