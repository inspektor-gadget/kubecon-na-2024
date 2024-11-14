#! /bin/bash

set -ex

kubectl gadget run profile_tcprtt:latest --name network-latency --detach \
    --annotate tcprtt:metrics.collect=true --otel-metrics-name=tcprtt:tcprtt
