#!/usr/bin/env python3
"""Register a local agent for machine-internal tribe communication.

Usage:
  python3 scripts/register_local.py codex@legion
  python3 scripts/register_local.py claude@localhost --key ~/.ssh/codex_local

Creates an SSH keypair for the agent (if not provided) and adds it to
~/.tribe-bridge/local_allowed_signers. Local agents can then communicate
with the local CompAII (Hermes) LCM, but not with the wider tribe.
"""
import subprocess, sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/register_local.py <agent@host> [--key <path>]", file=sys.stderr)
        sys.exit(1)

    agent_name = sys.argv[1]
    key_path = None
    if "--key" in sys.argv:
        idx = sys.argv.index("--key")
        key_path = Path(sys.argv[idx + 1]).expanduser()

    bridge_dir = Path.home() / ".tribe-bridge"
    bridge_dir.mkdir(parents=True, exist_ok=True)

    local_file = bridge_dir / "local_allowed_signers"

    if key_path and key_path.exists():
        pubkey = key_path.read_text().strip()
    else:
        # Generate a new key for the agent
        key_dir = bridge_dir / "keys"
        key_dir.mkdir(exist_ok=True)
        agent_key = key_dir / agent_name.replace("@", "_")
        if not agent_key.exists():
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(agent_key), "-q",
                           "-C", agent_name], check=True)
            print(f"Key generated: {agent_key} (.pub)")
        pubkey = agent_key.with_suffix(".pub").read_text().strip()

    # Check if already registered
    existing = local_file.read_text() if local_file.exists() else ""
    if agent_name in existing:
        print(f"{agent_name} already registered.")
    else:
        with open(local_file, "a") as f:
            f.write(f"{agent_name} {pubkey}\n")
        print(f"Registered: {agent_name}")

    print(f"  {agent_name} can now send/receive messages to/from the local LCM.")
    print(f"  {agent_name} CANNOT communicate with the tribe (not in allowed_signers).")

if __name__ == "__main__":
    main()
