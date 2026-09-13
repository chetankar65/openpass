# openpass-core — Design Document

**Status:** draft v0.1
**Date:** 2026-09-12
**Scope:** the local vault format, crypto, daemon, IPC API, and CLI. The browser extension is designed for here (so we don't paint ourselves into a corner) but built in a later phase.

---

## 1. What we're building

openpass is a password manager that never talks to the network. A long-lived local daemon (`openpassd`) owns an encrypted vault file. It exposes a JSON-RPC API over a Unix domain socket. A CLI (`openpass`) and, later, a browser extension (via a native-messaging bridge) are clients of that API.

```
                    ┌──────────────────────────────┐
   ┌── CLI ─────────┤                              │
   │  openpass get  │         openpassd            │
   └────────────────┤                              │
                    │  ┌────────────────────────┐  │      ┌──────────────┐
   ┌── Bridge ──────┤  │ session: DEK in memory │  ├──────┤  vault.opv   │
   │ openpass-bridge│  │ autolock timer         │  │ AEAD │  (encrypted) │
   └───────┬────────┤  │ client policy/approval │  │      └──────────────┘
           │        │  └────────────────────────┘  │
      stdio│(native │                              │
           │ msging)└──────────────────────────────┘
    ┌──────┴──────┐          UNIX socket, 0600
    │  extension  │          $HOME/.openpass/run/openpassd.sock
    └─────────────┘
```

### Goals

1. **Local only.** No sync, no telemetry, no network sockets in any binary. A build-time check should fail if `net.Dial` is reachable from the daemon's call graph (we allow `net` only for the Unix listener).
2. **Encrypted at rest, always.** The vault file is a single authenticated ciphertext. Entry names, usernames, and URLs are *not* visible to someone holding the file.
3. **One API, many clients.** The CLI has no privileged path. Whatever the CLI can do, the API can do — that keeps the API honest and testable.
4. **Boring, auditable crypto.** Standard primitives from `golang.org/x/crypto`. No custom constructions.
5. **Small dependency surface.** A password manager's supply chain is its weakest link. Target: fewer than 8 direct dependencies, all pinned, vendored before v1.

### Non-goals (v1)

- Multi-device sync, cloud backup, sharing.
- Multi-user vaults / team features.
- Mobile.
- A GUI. (The API makes one possible later.)
- Hardware token unlock (YubiKey, Secure Enclave, Touch ID). Designed around, not built — see §11.

---

## 2. Threat model

Being explicit here, because it determines almost every other decision.

### In scope — attacks we defend against

| Threat | Defense |
|---|---|
| Attacker steals the vault file (backup, stolen laptop, cloud-synced folder) | Argon2id + XChaCha20-Poly1305. Offline brute force is the only path, and it's expensive by design. |
| Attacker tampers with the vault file or its header (e.g. downgrading KDF cost to make cracking cheap) | Header is bound as AAD to both the DEK wrap and the body ciphertext. Any edit fails authentication. |
| Attacker reads process memory after the daemon has auto-locked | Keys and plaintext are zeroed on lock; `mlock` on key pages to keep them out of swap. |
| Malicious website tries to phish a credential via the extension | Domain matching on eTLD+1 with the public suffix list; never fill on a mismatch; never fill cross-origin iframes without explicit user action. |
| A random process on the machine connects to the socket | Socket dir is `0700`, socket `0600`, peer UID checked on accept; unknown clients must be approved by the user before they can read secrets. |
| Vault corruption from a crash mid-write | Atomic write (tmp + fsync + rename + dir fsync), plus a one-generation `.bak`. |

### Out of scope — attacks we do NOT defend against

State these plainly rather than pretending otherwise:

- **Malware running as your user while the vault is unlocked.** It can read daemon memory, keylog the master password, or ptrace the process. On a single-user OS, same-UID processes are largely equivalent in trust. Client approval (§7.4) raises the bar against *casual* abuse; it is not a security boundary against a determined local attacker.
- **A compromised browser.** If the browser is owned, anything the extension can see is gone.
- **Kernel/firmware compromise, evil maid, cold boot.**
- **Rubber-hose / coercion.** No duress vault in v1.

### The uncomfortable one

Anything connecting to the socket runs as the same user as the daemon. UID checks prove "same user," not "the client I meant." Real-world managers (KeePassXC, 1Password) solve this with client registration plus a user-visible approval prompt, and so do we — but it's a usability mitigation, not a cryptographic one, and the doc should keep saying so.

---

## 3. Cryptography

### 3.1 Key hierarchy (envelope encryption)

```
master password ──Argon2id(salt, m=64MiB, t=3, p=4)──▶ KEK (32B)
                                                        │
                                        unwraps ────────┘
                                                        ▼
random DEK (32B, crypto/rand) ──XChaCha20-Poly1305──▶ vault body
```

Terms:
1. KEK - Key Encryption Key, the master key which encrypts the other keys
2. DEK - Data Encryption Key, which encrypts each data object. Makes KEK rotation super fast
3. KDF - Key derivation function, which derives the KEK

Two levels, not one, for three reasons:

- **Password change is cheap.** Re-wrap the DEK. The body is untouched; no window where the whole vault is re-encrypted and a crash could lose it.
- **KDF params can be upgraded** as hardware improves, again without touching the body.
- **Future unlock methods** (Touch ID, YubiKey, a recovery key) become *additional wrappings of the same DEK* rather than a redesign. The header holds a list of wraps.

### 3.2 Primitives

| Purpose | Choice | Why |
|---|---|---|
| KDF | Argon2id, m=64 MiB, t=3, p=4, 16B salt | Memory-hard; the OWASP/RFC 9106 second recommended profile. Tuned at `init` time to ~500ms on the local machine, floored at these values and stored in the header. |
| AEAD | XChaCha20-Poly1305 (24-byte nonce) | Random nonces are safe at 192 bits — no counter state to persist or corrupt. Constant-time in software, no AES-NI dependence. |
| RNG | `crypto/rand` only | Never `math/rand`, enforced by lint. |
| IDs | UUIDv4 | |
| Domain matching | `golang.org/x/net/publicsuffix` | eTLD+1 is the only correct way to compare "same site". |

We deliberately do *not* use AES-GCM: its 96-bit nonce makes random-nonce reuse a real risk over a file rewritten on every edit, and dodging that requires a persisted counter, which is exactly the kind of state that breaks after a crash.

### 3.3 Vault file format (`vault.opv`)

```
 offset  size   field
 ------  -----  -------------------------------------------------
      0      8  magic        "OPENPASS"
      8      1  format_ver   0x01
      9      4  header_len   uint32 big-endian
     13      N  header       canonical JSON, UTF-8
   13+N      *  body         XChaCha20-Poly1305 ciphertext || tag
```

Header (plaintext, but authenticated):

```json
{
  "v": 1,
  "cipher": "xchacha20poly1305",
  "kdf": { "alg": "argon2id", "salt": "<b64>", "m_kib": 65536, "t": 3, "p": 4 },
  "wraps": [
    { "id": "master", "kind": "password", "nonce": "<b64>", "ct": "<b64>" }
  ],
  "body_nonce": "<b64>",
  "created_at": "2026-09-12T10:00:00Z",
  "updated_at": "2026-09-12T10:31:00Z",
  "rev": 42
}
```

**AAD binding.** Let `H` be the canonical header bytes with every `wraps[].ct` set to `""`. Then:

- each wrap is `AEAD(KEK_i, wraps[i].nonce, DEK, aad = H || wraps[i].id)`
- the body is `AEAD(DEK, body_nonce, plaintext, aad = H)`

So flipping `m_kib` from 65536 to 8, or deleting a wrap, or replaying an old header against a new body — all fail to authenticate. `rev` is included, which also makes silent rollback to an older body detectable when paired with the header.

Canonical JSON means: sorted keys, no insignificant whitespace, no floats. We write our own tiny canonicalizer rather than trusting `encoding/json` field ordering to stay stable across Go versions.

### 3.4 Body plaintext

Plain JSON, the whole vault as one document:

```json
{ "v": 1, "entries": [ ... ], "settings": { ... } }
```

**Decision: one ciphertext for the entire vault, not per-entry.**

- Hides metadata — an attacker with the file learns the approximate size and nothing else. Per-entry encryption leaks entry count, and typically entry names or URLs if you want to search without full decryption.
- Simpler: one nonce, one tag, one code path. In a security product, fewer code paths is a feature.
- Cost is irrelevant at our scale. A 5,000-entry vault is well under a megabyte; encrypt + write is sub-millisecond.

The tradeoff we accept: the entire plaintext is in daemon memory while unlocked, and every edit rewrites the whole file. Both are fine. If a vault ever grows past ~10 MB (attachments, say), revisit with per-entry encryption under the same DEK — the format version byte exists for that.

### 3.5 Memory handling

Go's GC makes true secret-scrubbing impossible to guarantee: values get copied during heap growth and there's no pinning. We do best-effort and document the limit rather than claiming safety we don't have.

- Secrets live in `[]byte`, never `string`, everywhere we control. `string` is immutable and uncontrollably copied.
- `crypto.Secret` wrapper: allocates page-aligned memory, calls `unix.Mlock` (keeps it out of swap), zeroes on `Close()`, and has a finalizer that panics in debug builds if it was never closed.
- On lock: zero the DEK, zero the decrypted body, drop the entry slice, then `debug.FreeOSMemory()`.
- Disable core dumps at daemon start (`setrlimit(RLIMIT_CORE, 0)`).
- Never log a secret. A `String()` method on every secret-bearing type returns `[redacted]`, and a lint rule bans `%v` on the vault types.

---

## 4. Data model

```go
type Entry struct {
    ID        string    // uuidv4, stable
    Name      string    // "GitHub", user-facing label
    Username  string
    Secret    Secret    // the password itself
    URLs      []string  // full URLs; matching is on eTLD+1
    Notes     string
    Tags      []string
    TOTP      *TOTPConfig  // v1.1
    Custom    map[string]Secret // arbitrary extra fields
    CreatedAt time.Time
    UpdatedAt time.Time
    History   []HistoricSecret  // last N previous secrets, capped at 10
}

type HistoricSecret struct {
    Secret    Secret
    ReplacedAt time.Time
}
```

Notes:

- **`Name` is not an identifier.** The CLI resolves a user-typed name to an ID with a prefix/fuzzy match and errors on ambiguity rather than guessing. Guessing wrong in a password manager means pasting the wrong credential into a login form.
- **History is kept** because "I changed it and the site didn't save it" is a real recovery scenario. Capped, and excluded from export by default.
- **`Custom`** covers security questions, PINs, recovery codes — all treated as secrets, all encrypted the same way (which is free; the whole body is encrypted).

---

## 5. Storage layer

Single-writer, whole-file rewrite on every mutation.

**Write path:**
1. Take an exclusive `flock` on `vault.opv.lock` (held for the process lifetime by the daemon — also how we prevent two daemons).
2. Serialize + encrypt in memory.
3. Write `vault.opv.tmp` (mode 0600), `fsync` it.
4. `rename()` the existing `vault.opv` → `vault.opv.bak`, then `rename()` tmp → `vault.opv`.
5. `fsync` the containing directory so the renames are durable.

**Read path:** try `vault.opv`; on magic/auth failure, report it and offer `vault.opv.bak` explicitly — never fall back silently. A silent fallback after a tampering attempt is how you lose the last N edits without noticing.

**Locations** (via `internal/config`, XDG-aware with macOS defaults):

```
~/.openpass/
├── vault.opv           0600  the encrypted vault
├── vault.opv.bak       0600  previous generation
├── config.toml         0600  non-secret settings (autolock, generator defaults)
├── clients.json        0600  approved API clients + their public keys
└── run/                0700
    ├── openpassd.sock  0600
    └── openpassd.pid
```

`~/.openpass` itself is `0700`. The daemon refuses to start if permissions are looser and tells you how to fix it.

---

## 6. The API

Full method reference lives in [API.md](./API.md). The shape:

- **Transport:** Unix domain stream socket, newline-delimited JSON-RPC 2.0. One request per line, one response per line, no framing cleverness.
- **Why JSON-RPC:** every language the extension bridge or a future GUI might be written in can speak it in ten lines. No codegen, no protobuf toolchain, trivially inspectable with `nc` during development.
- **Why a socket, not HTTP on localhost:** any process, and any web page via a fetch to `127.0.0.1`, can reach a localhost port. A Unix socket gets filesystem permissions and peer credentials for free.

Method groups:

| Group | Methods |
|---|---|
| session | `status`, `unlock`, `lock` |
| vault | `vault.list`, `vault.get`, `vault.match`, `vault.add`, `vault.update`, `vault.delete` |
| client | `client.pair`, `client.list`, `client.revoke` |
| util | `generate.password`, `vault.export` |

Two deliberate API decisions:

1. **`vault.list` never returns secrets.** It returns entries with the secret field omitted. Revealing requires `vault.get` with `reveal: true`, which is the call that triggers policy checks and, for non-CLI clients, a user prompt. This means a browser extension can show "you have a saved login for this site" without ever holding the password until the user acts.
2. **`vault.match` takes a URL, not a query string.** The daemon does the public-suffix parsing and match logic. Clients don't get to invent their own matching — that's where phishing bugs come from.

---

## 7. The daemon

### 7.1 Lifecycle

Starts locked. Always. There is no "start unlocked" mode and no way to pass the master password on the command line (it would land in shell history and `ps` output).

The CLI auto-spawns the daemon if the socket is absent, then retries once. A macOS `launchd` plist (`LaunchAgents`, `KeepAlive` on) ships as the supported install path.

### 7.2 Unlock

`unlock` takes the master password, runs Argon2id (~500ms — deliberately slow, and this is the moment to show a spinner), unwraps the DEK, decrypts and parses the body, and holds it in memory. A failed unlock gets a small increasing delay (100ms × consecutive failures, capped at 5s) purely to make socket-level guessing tedious; Argon2id is the actual defense.

### 7.3 Auto-lock

Locking zeroes the DEK and the plaintext. Triggers:

- Idle timeout since the last *successful authenticated request*, default 15 minutes, configurable.
- Explicit `lock`.
- SIGTERM/SIGINT (lock, then exit).
- macOS: screen lock / sleep notifications, if we can observe them without a cgo dependency — investigate `IOKit` notifications vs. polling `pmset`. Nice-to-have, not v1-blocking.

Open question: whether a long-running `vault.match` from the extension should count as activity for the idle timer. Leaning no — passive page loads shouldn't hold the vault open indefinitely. Only explicit reveals reset the timer.

### 7.4 Client identity and authorization

On `accept()`:

1. Read peer credentials. Linux: `SO_PEERCRED` (uid, gid, pid). macOS: `LOCAL_PEERCRED` via `unix.GetsockoptXucred` gives uid/gid; the PID is available via `LOCAL_PEERPID` but is best-effort and racy, so we use it for display only, never for authorization.
2. Reject if `uid != daemon uid`. Hard failure, no prompt.
3. The client sends `client.pair` (first run) with a name and an Ed25519 public key it generated locally. The daemon stores it in `clients.json` only after the user approves out-of-band — `openpass client approve <code>` in a terminal, matching a short code shown to both sides.
4. Thereafter each request carries a signature over `(method, params, nonce, timestamp)`. Replay window 30s, nonce cache.

Per-client policy, stored alongside the key:

```
reveal: always | prompt | never    (default: prompt for non-CLI clients)
allowed_domains: [...]             (optional narrowing)
```

The local CLI is a special case: it's paired automatically on first run because it shares the config directory and has already proven it can read `clients.json` — i.e. it's already game over if it's hostile. Say that in the code comment so nobody later "fixes" it into a false sense of security.

---

## 8. CLI

```
openpass init                          create the vault, tune KDF params
openpass unlock                        prompt for master password (never a flag)
openpass lock
openpass status

openpass add <name> [--user U] [--url URL] [--gen] [--len 24]
openpass get <name> [--field password|username|totp] [--clip]
openpass ls [--tag T] [--url URL]
openpass edit <name>
openpass rm <name>

openpass gen [--len 24] [--no-symbols] [--words 6]
openpass export --format json --out - --yes-i-know
openpass client ls | approve <code> | revoke <id>
openpass daemon [--foreground]
```

Behaviors worth deciding now:

- **`get` writes the secret to stdout only when stdout is not a TTY.** Interactive use goes to the clipboard with a 30-second auto-clear; piping (`openpass get gh | ...`) gets the raw value. This makes the safe thing the default without breaking scripting.
- **Passwords are read with `golang.org/x/term.ReadPassword`**, never from a flag or env var.
- **Exit codes are meaningful:** `0` ok, `1` general error, `2` vault locked, `3` not found, `4` ambiguous name. Scripts need to distinguish "locked" from "no such entry."

### Password generator

`crypto/rand` with rejection sampling (not modulo — it biases the distribution). Two modes: character classes with configurable length (default 24, all classes, ambiguous characters excluded on request), and EFF-wordlist passphrases (default 6 words). Embedded wordlist, no download.

---

## 9. Browser extension (phase 2, designed now)

Browser extensions cannot open Unix sockets. The standard bridge is a **native messaging host**: the browser launches `openpass-bridge` as a subprocess and speaks 4-byte-length-prefixed JSON over its stdin/stdout. The bridge is a dumb relay to the socket — no crypto, no policy, no state. Every security decision stays in the daemon.

```
page ⇄ content script ⇄ background SW ⇄ native msg ⇄ openpass-bridge ⇄ socket ⇄ openpassd
```

Flow for autofill:

1. Background worker sees a navigation, calls `vault.match` with the page URL.
2. Daemon parses to eTLD+1, returns matching entries **without secrets** — id, name, username only.
3. Extension decorates the login field with an openpass icon. No secret has left the daemon yet.
4. User clicks. Extension calls `vault.get(id, reveal: true)`. Daemon applies policy — prompt if configured — and returns the secret.
5. Content script fills the field and drops its reference.

Anti-phishing rules, enforced daemon-side where possible:

- Match on eTLD+1 via the public suffix list. `paypal.com.evil.com` does not match `paypal.com`.
- HTTPS-only by default; HTTP fill requires per-entry opt-in.
- Never fill a cross-origin iframe without an explicit click on that iframe.
- Never auto-submit the form.

---

## 10. Repository structure

```
openpass/
├── cmd/
│   ├── openpass/            CLI entrypoint (thin: flags → internal/cli)
│   ├── openpassd/           daemon entrypoint
│   └── openpass-bridge/     native messaging relay (phase 2)
│
├── internal/
│   ├── config/              paths, config.toml, permission checks
│   ├── crypto/
│   │   ├── kdf.go           argon2id + param tuning
│   │   ├── aead.go          xchacha20poly1305 seal/open
│   │   ├── secret.go        Secret type: mlock, zeroize, redacted String()
│   │   └── random.go        crypto/rand helpers, unbiased sampling
│   ├── vault/
│   │   ├── model.go         Entry, Vault, validation
│   │   ├── format.go        header canonicalization, AAD construction
│   │   ├── codec.go         encode/decode vault.opv
│   │   ├── store.go         atomic write, flock, backup rotation
│   │   └── match.go         URL → eTLD+1 matching
│   ├── protocol/            wire types + method names (shared client/server)
│   ├── ipc/
│   │   ├── listen.go        socket setup, permissions
│   │   ├── peercred_darwin.go
│   │   ├── peercred_linux.go
│   │   └── conn.go          NDJSON framing
│   ├── daemon/
│   │   ├── server.go        dispatch
│   │   ├── session.go       unlocked state, DEK lifetime
│   │   ├── autolock.go      idle timer
│   │   ├── clients.go       pairing, signature verification, policy
│   │   └── handlers_*.go    one file per method group
│   ├── client/              Go client for the API (used by CLI + tests)
│   ├── cli/                 cobra commands, prompts, clipboard
│   └── generate/            password + passphrase generation, EFF wordlist
│
├── docs/
│   ├── DESIGN.md            this file
│   └── API.md               RPC method reference
│
├── test/
│   ├── vectors/             known-answer tests for the file format
│   └── e2e/                 spawn daemon, drive via CLI, assert
│
├── extension/               phase 2
├── Makefile
├── go.mod
└── README.md
```

**Why this shape:**

- `cmd/` binaries hold no logic — just flag parsing and wiring. Everything testable lives under `internal/`.
- `internal/` (not `pkg/`) for all of it. Nothing here is a stable public API yet, and Go's `internal` rule enforces that mechanically. When we want to publish a client library, promote `protocol` and `client` and take the compatibility obligation deliberately.
- `crypto` and `vault` are split because `crypto` should be reviewable in isolation, with no knowledge of what an Entry is. That's the package a security reviewer reads first.
- `client` exists so the CLI never speaks the wire format directly, and so end-to-end tests drive the real API rather than internal functions.

### Dependencies (target: 7)

`golang.org/x/crypto` · `golang.org/x/sys` · `golang.org/x/term` · `golang.org/x/net` (publicsuffix) · `github.com/spf13/cobra` · `github.com/google/uuid` · `github.com/BurntSushi/toml`

Clipboard: shell out to `pbcopy` on macOS rather than take a cgo dependency. Revisit for Linux (`wl-copy`/`xclip`).

---

## 11. Testing

- **Known-answer vectors** for the file format, checked into `test/vectors/`. A fixed vault file + fixed password must decrypt to a fixed plaintext, forever. This is the regression test that catches an accidental format change during a refactor.
- **Tamper tests:** for every byte range in the header, flip a bit and assert decryption fails. Especially the KDF params.
- **Crash-safety test:** interrupt the write path at each step (injectable `syncer` interface), assert the vault is either the old or the new state, never a mix.
- **Property test** on the generator: charset coverage, no modulo bias over a large sample.
- **E2E:** spawn a real daemon on a temp socket, drive it through the real client, including lock/unlock cycles and pairing.
- `go test -race` in CI; `govulncheck` on every dependency bump.

---

## 12. Milestones

| # | Deliverable | Done when |
|---|---|---|
| 1 | `internal/crypto` + `internal/vault` | Round-trip encrypt/decrypt, vectors pass, tamper tests pass. No daemon yet. |
| 2 | `openpass init/add/get/ls` against the file directly | Usable single-shot CLI, unlocking per invocation. Proves the core. |
| 3 | `openpassd` + socket + `internal/client`; CLI switches to the API | Unlock persists across CLI calls; autolock works. |
| 4 | Pairing, policy, client management | Non-CLI clients can be approved and revoked. |
| 5 | `openpass-bridge` + extension MVP (match, reveal, fill) | Fill works on a real login page. |
| 6 | Hardening: launchd, TOTP, import from other managers | |

Milestone 2 shipping a *direct-file* CLI before the daemon exists is deliberate — it gets the crypto and format exercised by real use early, and the `internal/client` interface then swaps the implementation underneath without the CLI noticing.

---

## 13. Open questions

1. **Touch ID unlock.** The clean design is a second wrap of the DEK, with the KEK held in the Secure Enclave. Requires cgo. Worth it for daily usability — but which milestone?
2. **Should `vault.match` reset the autolock timer?** Leaning no (§7.3).
3. **Import formats.** 1Password `.1pux`, Bitwarden JSON, Chrome CSV. Which first? Whichever the first real user needs.
4. **`rev` as rollback protection** is only meaningful if we remember the last-seen `rev` somewhere outside the vault file. Is a separate `state.json` worth the complexity, or do we accept rollback-to-older-vault as out of scope?
5. **Windows.** Everything here assumes Unix sockets and POSIX permissions. Named pipes + DPAPI is a real port, not a tweak. Defer, but don't let non-portable assumptions leak outside `internal/ipc` and `internal/config`.
