# Hands-on: Collect statistics about TCP connections with a gadget

In this hands-on session, you will learn how to write a gadget that collects
statistics about TCP connections. In particular, the gadget should keep track of
the number of bytes sent and received by each TCP connection.

For time constraints, we will provide you with a gadget that is almost complete
and your task is to have fun completing it!

## Environment setup

TODO: Add instructions to set up the environment.

## Walking through the eBPF code

The eBPF code is available in the `task/program.bfp.c` file. Let's walk
through it to understand what it does:

- [Data source and map definition](#data-source-and-map-definition)
- [Hooks](#hooks)
- [Programs](#programs)

### Data source and map definition

When computing statistics, we don't want to generate a stream of events every
time a TCP connection sends or receives data. Instead, it's more efficient to
keep statistics on kernel side and only copy them to user space periodically. To
achieve that, we define a Map Iterator data source (TODO: LINK) to make
Inspektor Gadget pull periodically those values:

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
  `gadget_mntns_id`, will make Inspektor Gadget to automatically enrich those
  statistics with the corresponding container metadata. (TODO: LINK):

  TODO: Add how it looks

- Using struct `gadget_l4endpoint_t` will improve the way this information is
  displayed in the CLI and, in case we run the gadget in Kubernetes and the
  address correspond to a pod or service, Inspektor Gadget will show the
  pod/service name instead of the raw address, see (TODO: LINK):

  TODO: Add how it looks

- In general, using `gadget_*` types will improve the UX and provide several
  features for free, see (TODO: LINK).

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

- `kprobe/tcp_sendmsg`: TODO: Explain parameters and add a link to documentation
- `kprobe/tcp_cleanup_rbuf`: TODO: Explain parameters and add a link to
  documentation. Note that `tcp_recvmsg` would be obvious to trace, but is less
  suitable because:
  - We'd need to trace both entry and return, to have both sock and size.
  - Misses tcp_read_sock() traffic.

### Programs

To have the context of when the programs are executed and what they should do,
let's see the interaction between a process sending and receiving TCP traffic,
the hooks, the programs and the map:

TODO: Add mermaid diagram with interaction between tracee, hook, programs and
maps and Inspektor Gadget iterating over maps.

The goal of those two programs is to get the TCP and process information and
store the statistics in the map. We already provide you with the code that get
the TCP and process information, so you only need to complete the code that
stores the bytes sent or received in the map. To do that, you can use the bpf
helper functions:

- `bpf_map_lookup_elem`: (TODO: Link to documentation)
- `bpf_map_update_elem`: (TODO: Link to documentation)
- TODO: Others?

Let's code!

## Building your gadget

To test your code, you can build the gadget by running this command:

```bash
ig image build -t tcp:latest .
```

For your information,
[here](https://www.inspektor-gadget.io/docs/latest/gadget-devel/building) the full
documentation on how to build a gadget.

## Running your gadget

You can your gadget by running:

```bash
TODO: Add command
```

For your information, [here](https://www.inspektor-gadget.io/docs/latest/reference/run) the full documentation on how to run a gadget.

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