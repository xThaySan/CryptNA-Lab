#!/usr/bin/env bash
set -euo pipefail

RESULT_DIR="experiments/results"
OUT="$RESULT_DIR/environment.txt"
mkdir -p "$RESULT_DIR"

{
  date --iso-8601=seconds
  git rev-parse HEAD
  echo "vmware_workstation=${VMWARE_WORKSTATION_VERSION:-17.6.4 build-24832109}"
  uname -a
  cat /etc/os-release
  lscpu
  free -h
  vmware-toolbox-cmd -v || true
  docker version
  docker compose version
  docker info --format 'OS={{.OperatingSystem}} Kernel={{.KernelVersion}} Arch={{.Architecture}} CPUs={{.NCPU}} Memory={{.MemTotal}} Cgroup={{.CgroupVersion}}'
  go version
  python3 --version
  ip -Version
} 2>&1 | tee "$OUT"

echo "environment=$OUT"
