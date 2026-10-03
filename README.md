# openpass

A completely local password manager. No sync, no accounts, no network.

A daemon (`openpassd`) owns an encrypted vault file and exposes a JSON-RPC API over a Unix socket. A CLI and a browser extension are both just clients of that API.

**Status:** usable from the command line. The crypto, vault, daemon and CLI are implemented and tested — you can create a vault, add secrets, and read them back with `openpass`.

Not yet built: client pairing, the browser extension, and changing your master password. See [Current limitations](#current-limitations).

## Docs

- [docs/DESIGN.md](docs/DESIGN.md) — threat model, crypto, vault format, daemon, repo layout, milestones
- [docs/API.md](docs/API.md) — the daemon's RPC API

## The shape of it

```
openpass get github          →  openpassd  →  vault.opv
browser extension            ↗   (holds the key in memory while unlocked)
```

- **Argon2id** derives a key-encryption key (KEK) from your master password; that unwraps a random data key (DEK) which encrypts the vault body with **XChaCha20-Poly1305**.
- The whole vault is one authenticated ciphertext, so the file leaks no entry names, usernames, or URLs.
- The daemon starts locked. Unlock once, and every read and write afterwards is instant — the DEK stays in memory, so nothing but `unlock` pays the Argon2id cost.
- The vault auto-locks after 15 minutes idle, zeroing the key.

---

## Requirements

- Go 1.27 or newer
- macOS or Linux (Unix sockets and POSIX file permissions; Windows is not supported)

## Building

```bash
go build -o bin/openpass  ./cmd/openpass
go build -o bin/openpassd ./cmd/openpassd
```

Keep both binaries in the same directory — `openpass` looks for `openpassd` next to itself before falling back to `PATH`, so a locally built pair works without installing anything.

Run the tests:

```bash
go test ./...            # full suite
go test -race ./...      # with the race detector
go vet ./...
```

The vault format has a fuzz target. Worth a longer run after touching `internal/vault`:

```bash
go test -fuzz FuzzDecode -fuzztime 60s ./internal/vault
```

## Running the daemon

```bash
./bin/openpassd
```

It runs in the **foreground** and logs to stderr. To background it, use your shell or a supervisor — the daemon does not fork itself:

```bash
./bin/openpassd > ~/.openpass/daemon.log 2>&1 &
```

Defaults:

| Flag | Default | |
|---|---|---|
| `-vault` | `~/.openpass/vault.opv` | |
| `-socket` | `~/.openpass/run/openpassd.sock` | |
| `-autolock` | `15m` | `0` disables it |

You usually don't need to start it yourself: `openpass` spawns the daemon on first use if it isn't already running.

For experimenting, point it somewhere disposable:

```bash
./bin/openpassd -vault /tmp/demo/vault.opv -socket /tmp/demo/d.sock
```

The daemon takes an exclusive lock on the vault file at startup, so a second instance on the same vault exits immediately rather than racing it. `Ctrl-C` (or `SIGTERM`) zeroes the key in memory and removes the socket.

---

## Using it

```bash
openpass init                  # create the vault, set the master password
openpass add GitHub -user chetan -url https://github.com -gen   # generate one
openpass add Bank   -user chetan                                # type one you have
openpass ls
openpass get GitHub            # copies to the clipboard
openpass lock
```

That's the whole loop. Each command is covered below.

### Create a vault

Once, ever. `init` prompts twice and there is **no way to recover a lost master password**.

```bash
openpass init
# Choose a master password. There is no way to recover it:
# Master password:
# Confirm:
# Created /Users/you/.openpass/vault.opv
```

Passwords are read with the terminal echo off, never taken as a flag — a flag would land in your shell history and in `ps` output.

### Add an entry

Three ways to supply the password.

**Type one you already have** — the default:

```bash
openpass add Bank -user chetan
# Password for Bank:
# Added Bank (a9544034)
```

**Generate a new one** with `-gen`:

```bash
openpass add GitHub -user chetan -url https://github.com -tags work -gen -len 20
# Added GitHub (f5d8147a)
# Copied GitHub to the clipboard.
```

**Pipe one in** with `-stdin`, for scripts and bulk import:

```bash
echo 'my-existing-secret' | openpass add Bank -user chetan -stdin

# importing from somewhere else
openpass unlock
while IFS=, read -r name user pw; do
  printf '%s' "$pw" | openpass add "$name" -user "$user" -stdin
done < passwords.csv
```

There is deliberately **no `-password` flag**: a flag value lands in your shell history and is visible in `ps` output to every process on the machine. A pipe is the only way to hand a secret to a program without leaking it that way.

`-stdin` strips exactly one trailing newline, because `echo` adds one. Nothing else is trimmed — if your password ends in a space, it is kept. Use `printf '%s'` to pipe a password with no newline at all.

Unlocking always needs a terminal, so run `openpass unlock` once before a batch of piped adds. Otherwise you get exit code 2 and a reminder to do so.

| Flag | |
|---|---|
| `-user` | username |
| `-url` | URL, or a comma-separated list |
| `-tags` | comma-separated tags |
| `-notes` | freeform notes |
| `-gen` | generate the password |
| `-len` | length of the generated password (default 24) |
| `-stdin` | read an existing password from stdin |

Flags work on either side of the name, so `openpass add -gen GitHub` is the same thing.

### List

```bash
openpass ls
# ID        NAME        USERNAME        URLS
# f5d8147a  GitHub      chetan          https://github.com
# 80dac678  Gmail       me@example.com  https://mail.google.com

openpass ls -tag work
```

`ls` never shows secrets.

### Read

```bash
openpass get GitHub              # → clipboard
openpass get GitHub -print       # → stdout
openpass get GitHub -field username
openpass get GitHub | docker login --password-stdin
```

Interactive use goes to the clipboard so a password doesn't end up in your scrollback. **Piping gets the raw value** with no trailing newline, so scripting works. One `isatty` check makes the safe thing the default without breaking either.

You can name an entry by id, exact name, unique prefix, or a substring of its name, username or URL:

```bash
openpass get git                 # prefix
openpass get github.com          # URL substring
```

An ambiguous name is **always an error**, never a guess — resolving to the wrong entry means filling the wrong credential:

```bash
openpass get Gm
# openpass: "Gm" matches 2 entries:
#   80dac678  Gmail  me@example.com
#   215432f8  Gmail-work  other
# be more specific, or use an id
```

### Delete

```bash
openpass rm Gmail          # confirms first
openpass rm Gmail -f       # skips the confirmation
```

Deletion is permanent. The only copy left is one generation of `vault.opv.bak`.

### Lock and unlock

```bash
openpass status
openpass unlock
openpass lock
```

You rarely need `unlock` — any command that needs the vault prompts for the password and then carries on with what you asked:

```bash
openpass ls
# Master password:
# ID        NAME    ...
```

`unlock` takes about half a second. That's Argon2id doing its job. After that, reads and writes are instant until the vault auto-locks.

### Exit codes

Scripts need to tell "locked" from "no such entry":

| Code | |
|---|---|
| 0 | success |
| 1 | general error |
| 2 | vault locked (and no terminal to prompt on) |
| 3 | not found |
| 4 | ambiguous name |

### Talking to the daemon directly

The CLI is just a client. Anything it does, the API can do — that's what keeps the browser extension a first-class consumer rather than an afterthought. Requests are newline-delimited JSON-RPC 2.0:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"status"}' | nc -U ~/.openpass/run/openpassd.sock
# {"jsonrpc":"2.0","id":1,"result":{"entry_count":null,"locked":true,"locks_in":null,"vault_present":true}}
```

### Methods

| Method | Params | Notes |
|---|---|---|
| `status` | — | Works while locked. Reports `null` for `entry_count` and `locks_in` — a locked vault reveals nothing, not even its size |
| `vault.init` | `password` | Creates the vault; fails if one exists |
| `unlock` | `password` | ~500 ms |
| `lock` | — | Zeroes the key |
| `vault.list` | — | Metadata only, never secrets |
| `vault.get` | `id`, `reveal` | `reveal: true` to include the password |
| `vault.add` | `name`, `username`, `password`, `urls`, `tags`, `notes` | Returns the new `id` |
| `vault.update` | `id`, `entry` | Only the fields you supply change |
| `vault.delete` | `id` | Permanent |

Errors come back as JSON-RPC errors with the codes in [docs/API.md](docs/API.md) — the ones you'll meet most are `-32001` (vault locked), `-32002` (wrong password) and `-32003` (not found).

### Files

```
~/.openpass/
├── vault.opv            the encrypted vault (0600)
├── vault.opv.bak        previous generation, kept on every save
├── vault.opv.lock       the daemon's exclusive lock
└── run/
    └── openpassd.sock   the API socket (0600, in a 0700 directory)
```

The header is readable plaintext — salt, KDF parameters, nonces. That's by design: you need it to derive the key, and it's a recipe, not a key. Everything else in the file is ciphertext.

---

## Current limitations

Worth knowing before you put a real password in it:

- **No client pairing.** The daemon checks that a connection comes from your own user, but any process running as you can call any method. The approval flow in DESIGN.md §7.4 isn't built.
- **No password change.** The design supports it cheaply (`Rekey`), but it isn't implemented.
- **`vault.init` is reachable over the socket** without authentication. `openpass init` prompts properly, but the underlying method does not require a terminal, and creating a vault probably should.
- **Your master password crosses the socket as a JSON string.** Go strings cannot be zeroed, so it lingers in daemon memory until the garbage collector happens to reuse that memory. The `[]byte` copies either side are wiped; the string is not.
- **Your master password is unrecoverable.** There is no reset, by design. Lose it and the vault is gone.

## Contributing

Run `gofmt -w .`, `go vet ./...` and `go test -race ./...` before committing.

`internal/crypto` is the package to read first and change last — it's deliberately small and has exactly one caller, `internal/vault`. Keeping it that way is what makes every use of a cipher in this codebase auditable by reading one package's call sites.

One gap worth closing: there are no golden vectors yet (a committed vault file plus its password, asserted to still decrypt). Without them, a change to header canonicalization can silently break every existing vault and no test will notice. `docs/DESIGN.md` §11 describes what they should cover.
