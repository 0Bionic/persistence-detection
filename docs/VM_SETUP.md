# VM Setup Guide

How to build the test VM for the **Detecting Linux Persistence Techniques** project. We should both use the same setup so our results can be compared.

## 1. VM specs

| Setting | Value | Notes |
|---|---|---|
| OS | **Ubuntu 24.04 LTS Desktop** (64-bit) | Use Desktop, not Server. The XDG autostart implant only fires on a graphical login. |
| Hypervisor | VirtualBox 7.x (Windows/Linux host) or UTM (Mac) | On Apple Silicon use the **ARM64** Ubuntu 24.04 image. On Intel/AMD use **amd64**. |
| CPUs | **2 vCPUs** | Keep this the same on both machines. CPU numbers in Experiment C depend on it. |
| RAM | **4 GB** (minimum 3 GB) | |
| Disk | **30 GB** dynamically allocated | auditd logs can grow during experiments. |
| Network | NAT, plus a port forward for SSH (below) | Needed for `apt` and for the SSH login false-positive test. |
| User | A normal user with sudo, e.g. `student` | Run everything as this user, not as root. |
| Guest additions | Optional | Only for clipboard and screen resizing. Install them **before** the clean snapshot. |

> **Note:** if our CPU architectures differ (one ARM Mac, one x86 PC), that's fine, but the report must say which results came from which machine. `setup.sh` writes this to `results/system_info_<hostname>.txt`.

### SSH port forward (VirtualBox)
Settings → Network → Adapter 1 (NAT) → Advanced → Port Forwarding:

| Name | Protocol | Host Port | Guest Port |
|---|---|---|---|
| ssh | TCP | 2222 | 22 |

Then from the host: `ssh -p 2222 student@127.0.0.1`

In UTM, use "Shared Network" and SSH to the VM's IP (`ip -4 addr` inside the VM).

## 2. Install Ubuntu

1. Download the Ubuntu 24.04 Desktop ISO from ubuntu.com (or the ARM64 build for Apple Silicon).
2. Create the VM with the specs above and install Ubuntu. Choose the **minimal installation**.
3. After the first boot, run:
   ```bash
   sudo apt update && sudo apt full-upgrade -y
   sudo reboot
   ```

## 3. Get the project

```bash
sudo apt install -y git
git clone https://github.com/0Bionic/persistence-detection.git
cd persistence-detection
```

(Ask Hamza to add you as a collaborator on the GitHub repo so you can push.)

## 4. Run the setup script

```bash
bash setup.sh        # run as your normal user, NOT with sudo
```

What the script does:
- Installs `auditd`, `inotify-tools`, `sysstat` (`pidstat`), `cron`, `openssh-server`, `build-essential` (`gcc`, needed for the LD_PRELOAD library), Python 3 with pandas and matplotlib, plus `jq` and `bc`.
- Enables `cron`, `auditd` and `ssh`, and turns on systemd linger for your user so user units keep running after logout.
- Raises the inotify watch limit to 524288.
- Creates `~/.config/systemd/user`, `~/.config/autostart` and `~/.ssh/authorized_keys` so the detectors have paths to watch.
- Adds you to the `adm` group so you can read audit logs.
- Writes your VM's specs to `results/system_info_<hostname>.txt`.
- Runs checks and prints `Setup done` if everything is working.

After it finishes, **log out and log back in** (needed for the `adm` group).

## 5. Take the clean snapshot

This step matters. Every experiment run has to start from the same state (proposal §4.1).

1. Shut down the VM (`sudo poweroff`). A powered-off snapshot is more reliable than a live one.
2. Take a snapshot named **`clean`**.
   - VirtualBox: Machine → Snapshots → Take
   - UTM: right-click the VM → Snapshots (or clone the VM if your UTM version has no snapshots)
3. Revert to `clean` before each experiment run, and **always** before testing the LD_PRELOAD implant. A broken `/etc/ld.so.preload` can stop every program from starting, including the shell.

## 6. Quick sanity check

```bash
inotifywait --help | head -1
sudo auditctl -s | head -3
pidstat 1 1
systemctl --user status        # should not error
date +%s.%N                    # shared clock used for all timings
```

## 7. Ground rules

- Only run the implants **inside the VM**, never on your host machine.
- Don't commit anything from `~/.ssh` or real private keys. The SSH implant uses a throwaway test key.
- Put raw experiment output in `results/` and commit it. That data is what the analysis uses.
- If something in the VM gets messed up, revert to `clean`. Don't try to repair it by hand.

## Folder layout

| Folder | Contents | Owner (proposal §7) |
|---|---|---|
| `implants/` | The six harmless persistence implants | Student 1 |
| `experiments/` | Experiment runner + false-positive scenarios | Student 1 |
| `detectors/` | Diffing, inotify and auditd detectors | Student 2 |
| `analysis/` | Resource measurements, analysis and plots | Student 2 |
| `results/` | Raw data and system info | Both |
| `proposal/` | Project proposal PDF | Both |
| `docs/` | Setup docs like this one | Both |
