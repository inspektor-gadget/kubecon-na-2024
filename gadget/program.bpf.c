/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

/* Taken from kernel include/linux/socket.h. */
#define AF_INET 2   /* Internet IP Protocol 	*/

struct key_t {
  gadget_pid pid;
  gadget_tid tid;
  gadget_comm comm[TASK_COMM_LEN];
  gadget_mntns_id mntns_id;

  struct gadget_l4endpoint_t src;
  struct gadget_l4endpoint_t dst;
};

struct value_t {
  size_t sent;
  size_t received;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct key_t);
  __type(value, struct value_t);
} stats SEC(".maps");

GADGET_MAPITER(tcp, stats);

static int probe_ip(bool receiving, struct sock *sk, size_t size) {
  struct key_t key = {};
  __u16 family;
  __u64 mntns_id, pid_tgid;
  __u32 pid, tid;

  /* Filter by container using gadget helpers */
  mntns_id = gadget_get_mntns_id();
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  /* Support only IPv4 */
  family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET)
    return 0;

  /* Set known values: We are tracing only IPv4 + TCP */
  key.src.version = key.dst.version = 4;
  key.src.proto_raw = key.dst.proto_raw = IPPROTO_TCP;

  /* Get address and port information from socket */
  key.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
  key.dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  bpf_probe_read_kernel(&key.src.addr_raw.v4,
                        sizeof(sk->__sk_common.skc_rcv_saddr),
                        &sk->__sk_common.skc_rcv_saddr);
  bpf_probe_read_kernel(&key.dst.addr_raw.v4,
                        sizeof(sk->__sk_common.skc_daddr),
                        &sk->__sk_common.skc_daddr);

  /* Use bpf helpers to get process information */
  pid_tgid = bpf_get_current_pid_tgid();
  key.pid = pid_tgid >> 32;
  key.tid = pid_tgid;
  bpf_get_current_comm(&key.comm, sizeof(key.comm));
  key.mntns_id = mntns_id;

  /* TODO: Add code for adding these new values to the map */

  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ig_tcp_send, struct sock *sk, struct msghdr *msg,
               size_t size) {
  return probe_ip(false, sk, size);
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_tcp_recv, struct sock *sk, int copied) {
  if (copied <= 0)
    return 0;

  return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
