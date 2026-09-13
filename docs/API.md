# openpass Daemon API

**Status:** draft v0.1 — companion to [DESIGN.md](./DESIGN.md)

The daemon's only interface. The CLI, the browser bridge, and any future GUI are all just clients of what's below.

---

## Transport

- **Endpoint:** `$HOME/.openpass/run/openpassd.sock` (Unix stream socket, mode `0600`, in a `0700` directory)
- **Framing:** newline-delimited JSON. One request object per line, one response object per line. No length prefixes, no batching.
- **Encoding:** UTF-8 JSON-RPC 2.0.
- **Connections:** multiple concurrent connections allowed; the daemon serializes vault mutations internally.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "vault.get",
  "params": { "id": "3f2a...", "reveal": true },
  "auth": {
    "client_id": "ext-chrome-a91f",
    "nonce": "<b64, 16 bytes>",
    "ts": 1789012345,
    "sig": "<b64 Ed25519 over the signing string>"
  }
}
```

**Signing string:** `method || "\n" || canonical_json(params) || "\n" || nonce || "\n" || ts`

The daemon rejects a request whose `ts` is more than 30 seconds from its own clock, or whose `nonce` it has seen within that window.

`auth` is omitted for `client.pair` and `status` (the only two unauthenticated methods).

### Response

```json
{ "jsonrpc": "2.0", "id": 1, "result": { ... } }
```

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "vault is locked" } }
```

### Error codes

| Code | Meaning | Client should |
|---|---|---|
| `-32700`/`-32600`/`-32601`/`-32602` | Standard JSON-RPC parse/request/method/params errors | Fix the call |
| `-32001` | `VAULT_LOCKED` | Prompt the user to unlock |
| `-32002` | `BAD_PASSWORD` | Re-prompt; respect the backoff |
| `-32003` | `NOT_FOUND` | |
| `-32004` | `AMBIGUOUS` — a name matched more than one entry | Disambiguate by id |
| `-32005` | `NOT_PAIRED` | Run the pairing flow |
| `-32006` | `DENIED_BY_POLICY` | Tell the user; do not retry in a loop |
| `-32007` | `USER_REJECTED` — approval prompt declined | Give up quietly |
| `-32008` | `VAULT_EXISTS` / `NO_VAULT` | |
| `-32009` | `STORAGE` — I/O or integrity failure | Surface loudly; may indicate tampering |

Errors never include secret material, and never distinguish "wrong password" from "corrupt vault" in a way that helps an attacker — a failed body decrypt after a successful DEK unwrap is reported as `STORAGE`, not `BAD_PASSWORD`.

---

## Session methods

### `status` — unauthenticated

```json
→ {"method": "status"}
← {"result": {
     "version": "0.1.0",
     "vault_present": true,
     "locked": true,
     "entry_count": null,
     "autolock_seconds": 900,
     "locks_in": null
   }}
```

`entry_count` and `locks_in` are `null` while locked — a locked vault leaks nothing, not even its size.

### `unlock`

```json
→ {"method": "unlock", "params": {"password": "<string>"}}
← {"result": {"locked": false, "entry_count": 42, "locks_in": 900}}
```

Runs Argon2id; expect ~500ms. On failure, returns `BAD_PASSWORD` after a delay of `100ms × consecutive_failures` (capped 5s).

The password is the one place a plaintext secret travels *into* the API. It is zeroed immediately after key derivation.

### `lock`

```json
→ {"method": "lock"}
← {"result": {"locked": true}}
```

Zeroes the DEK and the decrypted vault. Idempotent.

---

## Vault methods

All require an unlocked vault.

### `vault.list`

**Never returns secrets.** Use this for anything that displays a list.

```json
→ {"method": "vault.list", "params": {"tag": "work", "query": "git"}}
← {"result": {"entries": [
     {"id": "3f2a...", "name": "GitHub", "username": "chetan",
      "urls": ["https://github.com"], "tags": ["work"],
      "has_totp": false, "updated_at": "2026-09-01T12:00:00Z"}
   ]}}
```

Both params optional. `query` is a case-insensitive substring match over name, username, and URL.

### `vault.match`

Given a page URL, return entries whose saved URLs share the same registrable domain (eTLD+1). The daemon owns this logic — clients must not implement their own matching.

```json
→ {"method": "vault.match", "params": {"url": "https://login.github.com/session"}}
← {"result": {
     "domain": "github.com",
     "entries": [ { …same shape as vault.list… } ]
   }}
```

No secrets in the response. `https://paypal.com.evil.com/` returns `domain: "evil.com"` and, correctly, no PayPal entry.

### `vault.get`

```json
→ {"method": "vault.get", "params": {"id": "3f2a...", "reveal": true, "fields": ["password"]}}
← {"result": {"entry": {
     "id": "3f2a...", "name": "GitHub", "username": "chetan",
     "password": "correct-horse-battery-staple",
     "urls": ["https://github.com"], "notes": "", "tags": ["work"],
     "created_at": "...", "updated_at": "..."
   }}}
```

- Accepts `id` **or** `name`. A `name` matching multiple entries returns `AMBIGUOUS` with the candidate ids — it never picks one.
- `reveal: false` (default) omits `password`, `totp`, and `custom` values.
- `reveal: true` is the policy checkpoint: for a client whose policy is `prompt`, the daemon blocks and asks the user; `never` returns `DENIED_BY_POLICY`. This call resets the autolock timer; `vault.list`/`vault.match` do not.
- `fields` narrows what's revealed. An extension filling a login form asks for `["password"]` and gets nothing else.

### `vault.add`

```json
→ {"method": "vault.add", "params": {
     "name": "GitHub", "username": "chetan",
     "password": "…",          // or omit and set "generate"
     "generate": {"length": 24, "symbols": true},
     "urls": ["https://github.com"], "tags": ["work"], "notes": ""
   }}
← {"result": {"id": "3f2a...", "rev": 43}}
```

Exactly one of `password` or `generate` must be present. When generated, the new secret is returned **only** if `return_secret: true` — otherwise the caller gets just the id, which is what you want when the browser generated it via the daemon and the extension is about to fill it.

Duplicate `name` is allowed (people have two Google accounts) but returns a `warnings` array so the CLI can say so.

### `vault.update`

```json
→ {"method": "vault.update", "params": {
     "id": "3f2a...",
     "set": {"password": "…", "notes": "rotated 2026-09"},
     "expected_rev": 43
   }}
← {"result": {"rev": 44}}
```

- Only the keys present in `set` change. `null` clears a field.
- Replacing `password` pushes the old value onto `history` (capped at 10).
- `expected_rev` is optional optimistic locking. If supplied and stale, the call fails rather than clobbering a concurrent edit from another client.

### `vault.delete`

```json
→ {"method": "vault.delete", "params": {"id": "3f2a...", "expected_rev": 44}}
← {"result": {"rev": 45}}
```

Hard delete, including history. No trash in v1 — the `.bak` file is the only recovery path, and it holds exactly one generation.

### `vault.export`

```json
→ {"method": "vault.export", "params": {"format": "json", "confirm": "EXPORT PLAINTEXT"}}
← {"result": {"data": "…"}}
```

Emits **plaintext**. The literal `confirm` string is required, the export is logged to the daemon's audit log, and `history` is excluded unless `include_history: true`. Clients with policy `prompt` or `never` cannot call this at all — export is CLI-only by default.

---

## Client methods

### `client.pair` — unauthenticated

```json
→ {"method": "client.pair", "params": {
     "name": "Chrome extension", "kind": "browser",
     "pubkey": "<b64 Ed25519 public key>"
   }}
← {"result": {"client_id": "ext-chrome-a91f", "code": "4821-9930", "state": "pending"}}
```

The daemon prints/displays `code`; the user runs `openpass client approve 4821-9930` in a terminal. The pairing request expires after 120 seconds. Until approved, every authenticated call from that client returns `NOT_PAIRED`.

The out-of-band approval is the whole point: it means a process that can reach the socket still cannot read secrets without a human acting in a separate, trusted channel.

### `client.list` / `client.revoke`

```json
→ {"method": "client.list"}
← {"result": {"clients": [
     {"id": "cli-local", "name": "openpass CLI", "kind": "cli",
      "policy": {"reveal": "always"}, "last_seen": "…"},
     {"id": "ext-chrome-a91f", "name": "Chrome extension", "kind": "browser",
      "policy": {"reveal": "prompt"}, "last_seen": "…"}
   ]}}

→ {"method": "client.revoke", "params": {"id": "ext-chrome-a91f"}}
← {"result": {"revoked": true}}
```

Revocation is immediate and drops any open connection from that client.

---

## Utility methods

### `generate.password`

```json
→ {"method": "generate.password", "params": {
     "length": 24, "upper": true, "lower": true, "digits": true,
     "symbols": true, "exclude_ambiguous": false
   }}
← {"result": {"password": "…", "entropy_bits": 151.2}}
```

Passphrase mode:

```json
→ {"method": "generate.password", "params": {"words": 6, "separator": "-"}}
← {"result": {"password": "plaza-suffix-unread-cobra-tundra-fixate", "entropy_bits": 77.5}}
```

Available while locked — generation needs no vault access, and being able to generate a password before you've unlocked is genuinely useful.

---

## Notes for client implementers

1. **Assume locked.** Any call can return `VAULT_LOCKED` at any time — autolock can fire between two of your requests. Handle it as a normal state, not an error condition.
2. **Don't cache secrets.** Call `vault.get` at the moment of use and drop the value straight after. The daemon is the cache.
3. **Use `vault.list`/`vault.match` for UI.** If your UI holds a secret it isn't currently typing into a field, the design is wrong.
4. **One pairing per installation.** Generate the keypair on first run, store the private key in the browser's extension storage (or the CLI's config dir), and never transmit it.
5. **Respect `USER_REJECTED`.** Do not re-ask automatically. A prompt loop trains users to click "allow."
