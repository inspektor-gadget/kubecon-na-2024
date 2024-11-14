# Using Gadgets

This guide will teach you how to run some Gadgets from Inspektor Gadget. 

## trace_exec

The `trace_exec` gadget allows you to trace the execution of a command in a
container.

Run the gadget: 

```bash 
kubectl gadget run trace_exec:latest 
```

Create a pod to trace: 

```bash
kubectl run -ti mypod --rm --image=busybox -- /bin/sh
# execute commands here 
```

Play around with different output options from the gadget:

```bash 
kubectl gadget run trace_exec:latest -o json 
```

Play around with different filtering options:

```bash 
kubectl gadget run trace_exec:latest --containername mypod 
```

```bash 
kubectl gadget run trace_exec:latest -A
```

```bash 
kubectl gadget run trace_exec:latest --filter proc.comm=sh 
```

More information on
https://www.inspektor-gadget.io/docs/latest/gadgets/trace_exec


## trace_dns 

This gadget shows the different DNS queries made by a container.

```bash 
kubectl gadget run trace_dns:latest
```

Create a pod to trace: 

```bash
kubectl run -ti mypod --rm --image=busybox -- /bin/sh
# execute commands here
# nslookup inspektor-gadget.io
```

More information on
https://www.inspektor-gadget.io/docs/latest/gadgets/trace_dns

## snapshot_process

This gadget shows the processes running in the cluster.

```bash
kubectl gadget run snapshot_process:latest
```

```bash
kubectl gadget run snapshot_process:latest -A
```

More information on
https://www.inspektor-gadget.io/docs/latest/gadgets/snapshot_process

## Other Gadgets 

Check other gadgets we have available at
https://www.inspektor-gadget.io/docs/latest/gadgets/ and try to run some of
them.

## Metrics 

On this part of the document, we'll show how to use gadgets to collect metrics. 


### Implicit Counter

This guide shows how to collect metrics from tracer gadgets.

```bash
kubectl gadget run -f 1-alerts/alert-bad-process.yaml --detach 
```

Go to http://YOUR_VM_IP:9090 and look for the shell_executions process.

### Network latency 

Let's use the tcp_rtt gadget to collect network latency metrics.

```bash
kubectl gadget run -f 2-latency/network-latency.yaml --detach
```

Go to grafana at http://YOUR_VM_IP:3000 and create a dashboard as explained on
the presentation.  
