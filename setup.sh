#!/usr/bin/env bash
# Installs everything needed for the persistence-detection project.
# Target: Ubuntu 24.04 VM (see docs/VM_SETUP.md).
# Run as your normal user (NOT with sudo) from the repo root:  bash setup.sh
# Safe to re-run.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m[fail] %s\033[0m\n' "$*"; exit 1; }

# --- Preflight -------------------------------------------------------------
[[ $EUID -eq 0 ]] && fail "Run as your normal user, not root/sudo. The script calls sudo itself."
command -v sudo >/dev/null || fail "sudo is not installed."

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
    warn "Expected Ubuntu 24.04, found ${PRETTY_NAME:-unknown}. Continuing anyway."
  fi
fi

say "Asking for sudo once up front"
sudo -v

# --- Packages --------------------------------------------------------------
say "Installing packages"
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git curl build-essential \
  python3 python3-pip python3-venv \
  python3-pandas python3-matplotlib \
  auditd audispd-plugins \
  inotify-tools \
  sysstat \
  cron \
  openssh-server \
  jq bc

# --- Services --------------------------------------------------------------
say "Enabling services (cron, auditd, ssh)"
sudo systemctl enable --now cron auditd ssh

# Let systemd --user units keep running after logout (needed for the
# systemd-user-unit implant and for running user-level detectors).
loginctl enable-linger "$USER"

# inotify: raise the watch limit so recursive watches on $HOME don't run out.
say "Raising inotify watch limit"
echo 'fs.inotify.max_user_watches=524288' | sudo tee /etc/sysctl.d/99-persistence-detection.conf >/dev/null
sudo sysctl --system >/dev/null

# Make sure the per-user persistence locations exist so detectors can watch them.
mkdir -p "$HOME/.config/systemd/user" "$HOME/.config/autostart" "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"

# Add the user to the adm group so they can read /var/log/audit without sudo
# after the next login.
sudo usermod -aG adm "$USER"

mkdir -p implants detectors experiments analysis results

# --- Record the environment (proposal section 4.1) -------------------------
say "Recording system info to results/system_info.txt"
{
  echo "recorded_at: $(date -Is)"
  echo "hostname:    $(hostname)"
  echo "os:          $(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "kernel:      $(uname -r)"
  echo "arch:        $(uname -m)"
  echo "cpus:        $(nproc)"
  echo "ram:         $(free -h | awk '/^Mem:/ {print $2}')"
  echo "disk_free:   $(df -h / | awk 'NR==2 {print $4}')"
  echo "virt:        $(systemd-detect-virt 2>/dev/null || echo unknown)"
} > "results/system_info_$(hostname).txt"
cat "results/system_info_$(hostname).txt"

# --- Checks ----------------------------------------------------------------
say "Checks"
ok=1
for cmd in inotifywait pidstat auditctl ausearch python3 gcc crontab jq bc; do
  if command -v "$cmd" >/dev/null; then echo "  ok   $cmd"; else echo "  MISSING $cmd"; ok=0; fi
done
for svc in cron auditd ssh; do
  state=$(systemctl is-active "$svc" || true)
  echo "  $svc: $state"; [[ "$state" == active ]] || ok=0
done
python3 -c 'import pandas, matplotlib' 2>/dev/null && echo "  ok   python pandas/matplotlib" || { echo "  MISSING python pandas/matplotlib"; ok=0; }
echo "  date +%s.%N -> $(date +%s.%N)"

if [[ $ok -eq 1 ]]; then
  say "Setup done. Log out and back in once (for the adm group), then take a VM snapshot named 'clean'."
else
  fail "Some checks failed, see above."
fi
