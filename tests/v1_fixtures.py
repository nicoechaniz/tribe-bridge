import base64
import copy
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

import tribe_directory_v1 as directory_module
import tribe_protocol_v1 as protocol


NOW = 1_735_689_600_000


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signing_key(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def encryption_key(seed):
    return x25519.X25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public_key_record(kid, epoch, public_key):
    return {
        "kid": kid,
        "epoch": epoch,
        "public_key": b64url(public_key.public_bytes_raw()),
        "status": "active",
        "not_before_ms": NOW - 86_400_000,
        "not_after_ms": NOW + 10 * 86_400_000,
    }


def make_material(root: Path):
    governance_private = signing_key(1)
    agents = {}
    for index, agent_id in enumerate(
        ("alice", "codex@localhost", "mirror"), start=2
    ):
        signing = signing_key(index)
        encryption = encryption_key(index + 20)
        agents[agent_id] = {
            "signing": signing,
            "encryption": encryption,
            "signing_kid": f"{agent_id}/sig/1",
            "encryption_kid": f"{agent_id}/enc/1",
        }

    snapshot = {
        "schema": "tribe-directory/v1",
        "directory_epoch": 1,
        "issued_at_ms": NOW - 1_000,
        "expires_at_ms": NOW + 7 * 86_400_000,
        "previous_sha256": None,
        "agents": [
            {
                "id": agent_id,
                "status": "active",
                "signing_keys": [
                    public_key_record(
                        value["signing_kid"],
                        1,
                        value["signing"].public_key(),
                    )
                ],
                "encryption_keys": [
                    public_key_record(
                        value["encryption_kid"],
                        1,
                        value["encryption"].public_key(),
                    )
                ],
            }
            for agent_id, value in agents.items()
        ],
        "audiences": [
            {
                "type": "direct",
                "id": "codex@localhost",
                "epoch": 1,
                "status": "active",
                "members": ["codex@localhost"],
                "allowed_senders": ["alice"],
            },
            {
                "type": "direct",
                "id": "alice",
                "epoch": 1,
                "status": "active",
                "members": ["alice"],
                "allowed_senders": ["codex@localhost"],
            },
            {
                "type": "group",
                "id": "public-agents",
                "epoch": 1,
                "status": "active",
                "members": ["codex@localhost", "mirror"],
                "allowed_senders": ["alice", "codex@localhost"],
            },
        ],
        "governance": {"threshold": 1, "signatures": []},
    }
    signature = governance_private.sign(
        directory_module.directory_preimage(snapshot)
    )
    snapshot["governance"]["signatures"] = [
        {
            "kid": "governance/root/1",
            "alg": "Ed25519",
            "value": b64url(signature),
        }
    ]
    roots = {
        "schema": "tribe-governance-roots/v1",
        "threshold": 1,
        "keys": {
            "governance/root/1": b64url(
                governance_private.public_key().public_bytes_raw()
            )
        },
    }
    root.mkdir(parents=True, exist_ok=True)
    directory_path = root / "directory.json"
    roots_path = root / "roots.json"
    state_path = root / "directory-state.json"
    directory_path.write_text(json.dumps(snapshot))
    roots_path.write_text(json.dumps(roots))
    bundles = {}
    for agent_id, value in agents.items():
        bundle = {
            "schema": "tribe-key-bundle/v1",
            "agent_id": agent_id,
            "signing": {
                "kid": value["signing_kid"],
                "private_key": b64url(
                    value["signing"].private_bytes_raw()
                ),
            },
            "encryption": [
                {
                    "kid": value["encryption_kid"],
                    "private_key": b64url(
                        value["encryption"].private_bytes_raw()
                    ),
                }
            ],
        }
        path = root / f"{agent_id.replace('@', '_')}.keys.json"
        path.write_text(json.dumps(bundle))
        os.chmod(path, 0o600)
        bundles[agent_id] = path
    return {
        "snapshot": snapshot,
        "roots": roots,
        "directory_path": directory_path,
        "roots_path": roots_path,
        "state_path": state_path,
        "bundles": bundles,
        "agents": agents,
    }


def resign_directory(snapshot, governance_private):
    value = copy.deepcopy(snapshot)
    value["governance"]["signatures"] = []
    value["governance"]["signatures"] = [
        {
            "kid": "governance/root/1",
            "alg": "Ed25519",
            "value": b64url(
                governance_private.sign(
                    directory_module.directory_preimage(value)
                )
            ),
        }
    ]
    return value
