# openpass command line

Reference for the CLI, client pairing, files, and the daemon. Setup is in the
[README](../README.md).

## Commands

Go 1.27+, macOS or Linux. `setup.sh` installs Go if needed and builds these; to do it by hand:

```bash
go build -o bin/openpass        ./cmd/openpass
go build -o bin/openpassd       ./cmd/openpassd
go build -o bin/openpass-bridge ./cmd/openpass-bridge
```

Keep them in one directory — `openpass` looks for `openpassd` next to itself
before falling back to `PATH`. You never start the daemon by hand; `openpass`
spawns it on first use.

```bash
openpass init                                        # create the vault
openpass add GitHub -user chetan -url https://github.com -gen
openpass ls
openpass get GitHub                                  # copies to the clipboard
openpass lock
```

### Adding entries

Three ways to supply the password:

```bash
openpass add Bank -user chetan                       # type one you already have
openpass add GitHub -user chetan -gen -len 20        # generate a new one
echo 'my-secret' | openpass add Bank -stdin          # pipe one in
```

There is deliberately **no `-password` flag**: a flag value lands in your shell history and is visible in `ps` to every process on the machine. A pipe is the only way to hand a secret to a program without leaking it that way.

`-stdin` strips exactly one trailing newline, because `echo` adds one, and trims nothing else. For a batch import, unlock once first:

```bash
openpass unlock
while IFS=, read -r name user pw; do
  printf '%s' "$pw" | openpass add "$name" -user "$user" -stdin
done < passwords.csv
```

| Flag | |
|---|---|
| `-user` | username |
| `-url` | URL, or a comma-separated list |
| `-tags` | comma-separated tags |
| `-notes` | freeform notes |
| `-gen` / `-len` | generate the password, and its length (default 24) |
| `-stdin` | read an existing password from stdin |

Flags work on either side of the name.

### Reading

```bash
openpass get GitHub                  # → clipboard
openpass get GitHub -print           # → stdout
openpass get GitHub -field username
openpass get GitHub | docker login --password-stdin
```

Interactive use goes to the clipboard so a password never lands in your scrollback. **Piping gets the raw value** with no trailing newline, so scripting works. One `isatty` check makes the safe thing the default without breaking either.

Name an entry by id, id prefix, exact name, unique name prefix, or a substring of its name, username or URL. An ambiguous name is **always an error, never a guess** — resolving to the wrong entry means filling the wrong credential:

```bash
openpass get Gm
# openpass: "Gm" matches 2 entries:
#   80dac678  Gmail  me@example.com
#   215432f8  Gmail-work  other
# be more specific, or use an id
```

### Other commands

```bash
openpass ls [-tag work]              # never shows secrets
openpass rm Gmail [-f]               # permanent; one .bak generation is the only copy
openpass status
openpass match https://github.com    # which entries a page resolves to
openpass client ls                   # paired clients
openpass watch                       # answer approval requests
```

You rarely need `unlock` — any command needing the vault prompts and then carries on with what you asked.

### Exit codes

| | |
|---|---|
| 0 | success |
| 1 | general error |
| 2 | vault locked, and no terminal to prompt on |
| 3 | not found |
| 4 | ambiguous name |

---

## Clients and approvals

Every client — the CLI included — has an Ed25519 keypair and signs every request. There is no unsigned path: if unsigned requests were accepted at all, every policy below could be bypassed by omitting the signature.

```bash
openpass client ls
# ID                    NAME              KIND     STATE     REVEAL
# browser-d67f47205f47  Chrome extension  browser  approved  prompt
# cli-2b460df42d4e      openpass CLI      cli      approved  always
```

A new client gets a pairing code, shown in **that client's** UI. You type it into a channel that is already trusted:

```bash
openpass client approve 4821-9930
openpass client revoke browser-d67f47205f47
```

The approval comes from a party the daemon already trusts, never from the one asking to be trusted.

Policy differs by kind:

| | CLI | Browser |
|---|---|---|
| Read a password | immediately | **asks you first** |
| Find, list, read metadata | yes | yes |
| Add an entry | yes | yes |
| Update, delete, unlock, manage clients | yes | **refused** |

`prompt` means the daemon parks the request and asks. Something must be listening — the menu bar app on macOS, or:

```bash
openpass watch
# Browser extension wants the password for "GitHub" (github.com)
# Allow? [y/N]
```

Yes grants that client and site 5 minutes (`-remember 0` to be asked every time). Grants are dropped when the vault locks. It fails closed in every direction: no watcher, no answer in 30s, or a watcher that disconnects all deny.

**Be clear about what pairing buys.** Anything running as your user can read `clients.json` and `client.key`, forge a signature, and impersonate a client. Pairing gives you policy, revocation and an audit trail — not protection from local malware. The one control malware cannot satisfy is the human answering `openpass watch`.

---

## Files

```
~/.openpass/
├── vault.opv            encrypted vault (0600)
├── vault.opv.bak        previous generation, kept on every save
├── vault.opv.lock       the daemon's exclusive lock
├── clients.json         paired clients and their policies (0600)
├── client.key           this machine's CLI identity (0600)
├── bridge.key           the browser bridge's identity (0600)
├── menubar.key          the menu bar app's identity (0600)
└── run/
    └── openpassd.sock   API socket (0600, in a 0700 directory)
```

## Daemon

| Flag | Default | |
|---|---|---|
| `-vault` | `~/.openpass/vault.opv` | |
| `-socket` | `~/.openpass/run/openpassd.sock` | |
| `-autolock` | `15m` | `0` disables |

It runs in the foreground and logs to stderr; background it with your shell or a supervisor. An exclusive lock on the vault means a second instance exits immediately rather than racing. `Ctrl-C` zeroes the key and removes the socket.

**After upgrading, stop the old daemon.** It is long-lived, so a new CLI will otherwise meet a daemon from the previous build. The CLI detects this and tells you:

```
openpass: the running openpassd is older than this client.

Stop it and try again; a new one starts automatically:
  pkill openpassd
```

## Known gaps

- **Your master password crosses the socket as a JSON string.** Go strings cannot be zeroed, so it lingers in daemon memory until the GC reuses it. The `[]byte` copies either side are wiped; the string is not.
- **`vault.init` is reachable over the socket** without authentication.
- **No golden vectors yet** — a committed vault file plus its password, asserted to still decrypt. Without them, a change to header canonicalization breaks every existing vault and no test notices. DESIGN.md §11 describes what they should cover.

## Fuzzing

```bash
go test -fuzz FuzzDecode -fuzztime 60s ./internal/vault
```
