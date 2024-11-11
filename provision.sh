#!/bin/bash

set -eoux pipefail

IG_VERSION=v0.33.0
IG_ARCH=amd64

# update and install all dependencies
sudo apt-get update && sudo apt-get install docker docker-compose -y

# prepull builder image
sudo docker pull ghcr.io/inspektor-gadget/ebpf-builder:${IG_VERSION}

# install ig binary
curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${IG_ARCH}-${IG_VERSION}.tar.gz | sudo tar -C /usr/local/bin -xzf - ig

# copy other help files
cp -r /vagrant/help $HOME/
