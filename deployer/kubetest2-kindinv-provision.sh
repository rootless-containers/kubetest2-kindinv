#!/bin/bash
# The provisioning script for kubetest2-kindinv.
# Expected to be used with Ubuntu 22.04.
# TODO: support non-Ubuntu too
set -eux -o pipefail

# Install dependencies (apt-get)
# - make:   for `kind build node-image`
# - uidmap: for rootless
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y make uidmap

# Install dependencies (snap)
for f in go kubectl; do
  snap install "$f" --classic
done

# Set up cgroup v2 delegation: https://rootlesscontaine.rs/getting-started/common/cgroup2/
mkdir -p "/etc/systemd/system/user@.service.d"
cat >"/etc/systemd/system/user@.service.d/rootless.conf" <<EOF
[Service]
Delegate=yes
EOF
systemctl daemon-reload

# Install Docker
curl -fsSL https://get.docker.com | sh

# Install kind
#
# > Kubernetes @ HEAD typically requires KIND @ HEAD
# https://github.com/kubernetes-sigs/kind/pull/3487#issuecomment-1908753591
GOBIN=/usr/local/bin go install sigs.k8s.io/kind@main
