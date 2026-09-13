# openpass

A completely local password manager. No sync, no accounts, no network.

A daemon (`openpassd`) owns an encrypted vault file and exposes a JSON-RPC API over a Unix socket. A CLI (`openpass`) and a browser extension are both just clients of that API.

**Status:** design phase. Nothing is implemented yet.

## Docs

- [docs/DESIGN.md](docs/DESIGN.md) — threat model, crypto, vault format, daemon, repo layout, milestones
- [docs/API.md](docs/API.md) — the daemon's RPC API

## The shape of it

```
openpass get github          →  openpassd  →  vault.opv
browser extension            ↗   (holds the key in memory while unlocked)
```

- **Argon2id** derives a key-encryption key from your master password; that unwraps a random data key which encrypts the vault body with **XChaCha20-Poly1305**.
- The whole vault is one authenticated ciphertext, so the file leaks no entry names, usernames, or URLs.
- The daemon starts locked, auto-locks on idle, and requires out-of-band approval before a new client (like the browser extension) can read a secret.

## Building

Nothing to build yet — see the milestones in [DESIGN.md](docs/DESIGN.md#12-milestones). Milestone 1 is `internal/crypto` + `internal/vault`.
