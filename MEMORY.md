# Historical project note — non-canonical

This file described the bootstrap design on 2026-07-29. It is retained only
to identify stale references and must not be used for operations or security
decisions.

Material corrections:

- The system was deployed after this note was written.
- Writes use SSH signatures, not a shared HMAC secret.
- The Telegram mirror is bidirectional, not read-only.
- The topology and agent table in the old note were aspirational.
- v0 AES-GCM uses a key derived from the public signer roster and therefore
  provides no confidentiality.
- v0 inbox history has no preservation or migration requirement.

Use `README.md`, the current source, tested systemd units, and linked GitHub
issues/PRs as the operational record.
