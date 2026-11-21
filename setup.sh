#!/usr/bin/env bash
# Installs everything needed for the persistence-detection project.
# Tested on Ubuntu 24.04. Run with: bash setup.sh
set -e

sudo apt update
sudo apt install -y auditd inotify-tools python3 python3-pip git \
  sysstat build-essential cron openssh-server

sudo systemctl enable --now cron auditd
loginctl enable-linger "$USER"

mkdir -p implants detectors experiments analysis results

echo "Setup done. Quick checks:"
command -v inotifywait pidstat auditctl python3 gcc
sudo systemctl is-active cron auditd
