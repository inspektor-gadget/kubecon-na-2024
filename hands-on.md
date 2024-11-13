# Hands-on: Collect statistics about TCP connections with a gadget

In this hands-on session, you will learn how to write a gadget that collects
statistics about TCP connections. In particular, the gadget should keep track of
the number of bytes sent and received by each TCP container.

For time constraints, we will provide you with a gadget that is almost complete
and your task is to have fun completing it!

## Environment setup

We prepared a set of virtual machines with all the dependencies ready for this
contribfest. We'll give you instruction on the section to connect to them.

The environment has:
- A running minikube cluster deployed
- `ig` and `kubectl gadget` binaries installed to handle gadgets
- Inspektor Gadget deployed to the cluster
- Prometheus and Grafana deployed to the cluster

## Walking through the eBPF code

The eBPF code is available in the `task/program.bpf.c` file. Let's walk
through it to understand what it does:

- [Data source and map definition](#data-source-and-map-definition)
- [Hooks](#hooks)
- [Programs](#programs)

### Data source and map definition

When computing statistics, we don't want to generate a stream of events every
time a TCP connection sends or receives data. Instead, it's more efficient to
keep statistics on kernel side and only copy them to user space periodically. To
achieve that, we define a
[Map Iterator data source](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-intro#map-iterators)
to make Inspektor Gadget pull periodically those values:

```c
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct key_t);
  __type(value, struct value_t);
} stats SEC(".maps");

GADGET_MAPITER(tcp, stats);
```

Now, let's see what information the [key](#map-key) and [value](#map-value)
structs contain.

### Map key

Given a TCP connection is identified by the tuple: source address, source port,
destination address and destination port; those are the obvious values to use as
a key. However, users may be also interested in having those statistics per
process or container. So, we will include also that information in the key:

```c
struct key_t {
  gadget_pid pid;
  gadget_tid tid;
  gadget_comm comm[TASK_COMM_LEN];

  gadget_mntns_id mntns_id;

  struct gadget_l4endpoint_t src;
  struct gadget_l4endpoint_t dst;
};
```

Let's see some of the benefits of using `gadget_*` types:

- In case the process sending/receiving TCP traffic is running within a
  container, adding the mount namespace ID to the key, with type
  [gadget_mntns_id](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-ebpf-api#gadget_mntns_id-and-gadget_netns_id),
  will make Inspektor Gadget to automatically enrich those statistics
  with the corresponding container metadata.
- Using
  [struct gadget_l4endpoint_t](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-ebpf-api#struct-gadget_l4endpoint_t)
  will improve the way this information is displayed in the CLI and, in
  case we run the gadget in Kubernetes and the address correspond to a
  pod or service, Inspektor Gadget will show the pod/service name instead
  of the raw address.
- In general, using `gadget_*` types will improve the UX and provide several
  features for free, see [Enriched types](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-ebpf-api#enriched-types)
  for further information.

### Map value

The value struct contains the statistics we are collecting, in this case the
number of bytes sent and received:

```c
struct value_t {
  size_t sent;
  size_t received;
};
```

### Hooks

Given that we want to compute sent and receive bytes statistics per TCP
connections, these are the hooks the gadget will use:

- [kprobe/tcp_sendmsg](https://github.com/torvalds/linux/blob/14b6320953a3f856a3f93bf9a0e423395baa593d/net/ipv4/tcp.c#L1352):
  Function in charge of sending TCP data. It receives the following parameters:
  - [struct sock *sk](https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html#the-struct-sock-structure): The network layer representation of the socket.
  - `struct msghdr *msg`: The message to send.
  - `size_t size`: The number of bytes to send.
- [kprobe/tcp_cleanup_rbuf](https://github.com/torvalds/linux/blob/14b6320953a3f856a3f93bf9a0e423395baa593d/net/ipv4/tcp.c#L1508):
  Function in charge of cleaning up the receive buffer for full TCP frames taken
  by the user. It receives the following parameters:
  - [struct sock *sk](https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html#the-struct-sock-structure): The network layer representation of the socket.
  - `int copied`: The number of bytes copied to the user.

  Notice that we are not using `tcp_recvmsg` to track received bytes for two
  reasons:
  - We would need to trace both entry and return, to have both sock struct and size.
  - We would miss traffic sent with
    [tcp_read_sock()](https://github.com/torvalds/linux/blob/14b6320953a3f856a3f93bf9a0e423395baa593d/net/ipv4/tcp.c#L1556-L1567),
    which offers significant performance benefits to applications such as `ftp`
    and web servers that need to efficiently transfer files.

### Programs

To have the context of when the programs are executed and what they should do,
let's see the interaction between a process sending and receiving TCP traffic,
the hooks, the programs and the map:

```mermaid
sequenceDiagram
    participant Process
    participant Kernel
    participant ig_tcp_send
    participant ig_tcp_send
    participant BPF Map
    participant Inspektor Gadget
    participant User

    activate Inspektor Gadget
    Inspektor Gadget ->> BPF Map: 
    Note left of Inspektor Gadget: Get stats 
    BPF Map ->> Inspektor Gadget: 
    Inspektor Gadget ->> User: 
    Note over User: Empty stats

    activate Process
    Process ->> Kernel: send()
    Kernel ->> Kernel: tcp_sendmsg()
    Note over Kernel: Hook is reached:<br/>kprobe/tcp_sendmsg
    Kernel ->> ig_tcp_send: 
    rect rgba(0, 0, 255, .1)
        Note over ig_tcp_send: Collect sent bytes and<br/>TCP and process info
        ig_tcp_send ->> BPF Map: 
        Note right of ig_tcp_send: Task: Update stats
        BPF Map ->> ig_tcp_send: 
    end

    ig_tcp_send ->> Kernel: 
    Note over Kernel: Resume execution of tcp_sendmsg<br/>and send TCP data
    Kernel ->> Process: 
    deactivate Process

    Inspektor Gadget ->> BPF Map: 
    Note left of Inspektor Gadget: Get stats
    BPF Map ->> Inspektor Gadget: 
    Inspektor Gadget ->> User: 
    Note over User: Sent stats available
```

The goal of those two programs is to get the TCP and process information and
store the statistics in the map. We already provide you with the code that get
the TCP and process information, so you only need to complete the code that
stores the bytes sent or received in the map. To do that, you can use the bpf
helper functions:

- [`bpf_map_lookup_elem`](https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/): Perform a lookup in map for an entry associated to key.
- [`bpf_map_update_elem`](https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/): Update values in a map.

Let's code!

## Generating an UUID for our gadget

We'll using ttl.sh to push our gadget to a container registry. Let's generate an
uuid for our gadget to avoid colliding with other folks.

:alert:

This is only needed because we're using ttl.sh to ease this contribfest. If you
are pushing to your own registry you won't need it.

UUID=$(uuidgen)

## Building your gadget

To test your code, you can build the gadget by running this command:

```bash
sudo -E ig image build . -t ttl.sh/$UUID/tcp-gadget:latest
```

For your information,
[here](https://www.inspektor-gadget.io/docs/latest/gadget-devel/building) the full
documentation on how to build a gadget.

## Running your gadget in Kubernetes

In order to be able to run your gadget in Kubernetes, you need to push it to a
container registry. You can do that by pushing the image to the ttl.sh registry
which doesn't require authentication:

```bash
sudo -E ig image push ttl.sh/$UUID/tcp-gadget:latest
```

TODO: Let people know that they need to use an unique ID.

You can run your gadget by running:

```bash
kubectl gadget run ttl.sh/$UUID/tcp-gadget:latest
```

As you can see, the gadget is not complete yet as it's not printing any output.
Your task is to fix the `/* TODO: Add code for adding these new values to the
map */` in the gadget.

Check our official documentation for further information about
[running](https://www.inspektor-gadget.io/docs/latest/reference/run) gadgets in
Kubernetes.

## Solution

For the solution, you should have considered two cases when storing the
statistics in the map:

- It's the first time we store statistics for a given key.
- We already have some statistics for that key. In the first case we add a new
  entry to the map, while in the second we just need to increase the counter for
  that key.

The code to complete the gadget could look like this:

```c
  struct value_t *trafficp = bpf_map_lookup_elem(&stats, &key);
  if (!trafficp) {
    struct value_t zero;

    if (receiving) {
      zero.sent = 0;
      zero.received = size;
    } else {
      zero.sent = size;
      zero.received = 0;
    }

    bpf_map_update_elem(&stats, &key, &zero, BPF_NOEXIST);
  } else {
    if (receiving)
      trafficp->received += size;
    else
      trafficp->sent += size;

    bpf_map_update_elem(&stats, &key, trafficp, BPF_EXIST);
  }
```

Run the gadget again and check the output:

```bash
TODO: Add output
```

## Bringing home your work

If you have a Linux host, you want to keep a copy of the gadget you created by running:

```bash
TODO:  scp IP@user:/blah/blah /local/destination/path
```
