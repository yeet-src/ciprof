// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

enum event_type {
    EV_EXEC    = 1,
    EV_EXIT    = 2,
    EV_CONNECT = 3,
    EV_CLOSE   = 4,
    EV_UNLINK  = 5,
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    char  comm[16];
    char  argv[128];
    __u8  src_addr[16];
    __u8  dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  is_ipv6;
    __u8  pad[3];
    __u64 bytes_sent;
    __u64 bytes_received;
    __s32 exit_code;
    __u32 _pad2;
    __u64 ino;
};

// Forces struct event into BTF for yeet's decoder.
struct event __event_dummy __attribute__((section("dummy"), unused)) = {};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

// Track active TCP connections: cookie -> {src, dst, sport, dport, pid, is_ipv6}
struct conn_info {
    __u8  src_addr[16];
    __u8  dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u32 pid;
    __u8  is_ipv6;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct conn_info);
} active_conns SEC(".maps");

static __always_inline struct event *reserve(void)
{
    return bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
}

static __always_inline void fill_addr_v4(struct sock *sk, __u8 *src, __u8 *dst,
                                          __u16 *sport, __u16 *dport)
{
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __builtin_memcpy(src, &saddr, 4);
    __builtin_memcpy(dst, &daddr, 4);
    *sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void fill_addr_v6(struct sock *sk, __u8 *src, __u8 *dst,
                                          __u16 *sport, __u16 *dport)
{
    BPF_CORE_READ_INTO(src, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(dst, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    *sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// ─── exec ────────────────────────────────────────────────────────────────────

#ifdef USE_TP_BTF_EXEC
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm)
{
    struct event *e = reserve();
    if (!e) return 0;
    e->type = EV_EXEC;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(p, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct mm_struct *mm = BPF_CORE_READ(p, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        bpf_probe_read_user(e->argv, sizeof(e->argv), (void *)arg_start);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#else
SEC("fentry/do_execveat_common")
int BPF_PROG(on_exec)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event *e = reserve();
    if (!e) return 0;
    e->type = EV_EXEC;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        bpf_probe_read_user(e->argv, sizeof(e->argv), (void *)arg_start);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif

// ─── exit ────────────────────────────────────────────────────────────────────

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
    pid_t pid = BPF_CORE_READ(p, tgid);
    pid_t tid = BPF_CORE_READ(p, pid);
    // Only report thread-group leaders (pid == tid for the main thread)
    if (pid != tid) return 0;

    struct event *e = reserve();
    if (!e) return 0;
    e->type = EV_EXIT;
    e->pid  = pid;
    e->exit_code = (BPF_CORE_READ(p, exit_code) >> 8) & 0xff;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── tcp connect ─────────────────────────────────────────────────────────────

SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8 is_ipv6 = (family == 10); // AF_INET6

    struct conn_info ci = {};
    ci.pid = pid;
    ci.is_ipv6 = is_ipv6;

    if (is_ipv6)
        fill_addr_v6(sk, ci.src_addr, ci.dst_addr, &ci.src_port, &ci.dst_port);
    else
        fill_addr_v4(sk, ci.src_addr, ci.dst_addr, &ci.src_port, &ci.dst_port);

    __u64 cookie = bpf_get_socket_cookie(sk);
    bpf_map_update_elem(&active_conns, &cookie, &ci, BPF_ANY);

    struct event *e = reserve();
    if (!e) return 0;
    e->type    = EV_CONNECT;
    e->pid     = pid;
    e->is_ipv6 = is_ipv6;
    __builtin_memcpy(e->src_addr, ci.src_addr, 16);
    __builtin_memcpy(e->dst_addr, ci.dst_addr, 16);
    e->src_port = ci.src_port;
    e->dst_port = ci.dst_port;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── tcp close ───────────────────────────────────────────────────────────────

SEC("fentry/tcp_close")
int BPF_PROG(on_tcp_close, struct sock *sk, long timeout)
{
    __u64 cookie = bpf_get_socket_cookie(sk);
    struct conn_info *ci = bpf_map_lookup_elem(&active_conns, &cookie);

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u8 is_ipv6 = (family == 10);

    struct event *e = reserve();
    if (!e) {
        if (ci) bpf_map_delete_elem(&active_conns, &cookie);
        return 0;
    }
    e->type = EV_CLOSE;

    if (ci) {
        e->pid     = ci->pid;
        e->is_ipv6 = ci->is_ipv6;
        __builtin_memcpy(e->src_addr, ci->src_addr, 16);
        __builtin_memcpy(e->dst_addr, ci->dst_addr, 16);
        e->src_port = ci->src_port;
        e->dst_port = ci->dst_port;
        bpf_map_delete_elem(&active_conns, &cookie);
    } else {
        e->pid     = bpf_get_current_pid_tgid() >> 32;
        e->is_ipv6 = is_ipv6;
        if (is_ipv6)
            fill_addr_v6(sk, e->src_addr, e->dst_addr, &e->src_port, &e->dst_port);
        else
            fill_addr_v4(sk, e->src_addr, e->dst_addr, &e->src_port, &e->dst_port);
    }

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    e->bytes_sent     = BPF_CORE_READ(tp, bytes_sent);
    e->bytes_received = BPF_CORE_READ(tp, bytes_received);

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── sentinel unlink ─────────────────────────────────────────────────────────
// security_inode_unlink has a stable (dir, dentry) signature across all kernel
// versions — unlike vfs_unlink, which gained a mnt_userns/mnt_idmap arg in 5.12
// and 6.3 respectively.

SEC("fentry/security_inode_unlink")
int BPF_PROG(on_unlink, struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) return 0;

    struct event *e = reserve();
    if (!e) return 0;
    e->type = EV_UNLINK;
    e->ino  = BPF_CORE_READ(inode, i_ino);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
