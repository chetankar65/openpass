# openpass browser extension

Fills logins from your local vault. Nothing leaves the machine — the extension
talks to `openpass-bridge`, which relays to the daemon over a Unix socket.

## How it works, and why it has no autofill

**You click the field. Then you pick what goes in it.** There is no field
detection at all.

Every password manager that guesses which field is which eventually guesses
wrong, and the failure mode is bad: a password typed into a visible text box, or
a search field that ships it to a server. Your click removes the guess, and with
it every case that defeats heuristics — shadow DOM, custom elements, multi-step
logins, single-page apps that render the form late, sites with no `<form>` at
all.

It also means nothing is ever filled without a deliberate gesture, which is the
anti-phishing rule in DESIGN.md §9 enforced by the interaction itself rather
than by a check that could be wrong.

Sites that "block paste" block the paste *event*. Filling from a content script
is not a paste, so those handlers never run.

## Install

**1. Build everything**

```bash
go build -o bin/openpass        ./cmd/openpass
go build -o bin/openpassd       ./cmd/openpassd
go build -o bin/openpass-bridge ./cmd/openpass-bridge
```

**2. Load the extension**

`chrome://extensions` → enable Developer mode → *Load unpacked* → pick this
`extension/` directory. Copy the extension ID it shows.

**3. Register the bridge**

```bash
./extension/install-host.sh <extension-id> ./bin/openpass-bridge
```

Chrome only launches the bridge for the extension IDs in that manifest, so no
other extension can reach your vault. That restriction is the browser's, and it
is stronger than anything openpass could enforce itself.

**4. Approve it**

Restart the browser and open the extension. It will show a pairing code:

```bash
openpass client approve 4821-9930
```

**5. Allow reveals**

A browser client's default policy is `prompt`, so the daemon asks before handing
over a password. Something has to be listening to ask:

```bash
openpass watch
```

Leave that running. When the extension requests a password you get:

```
Browser extension wants the password for "GitHub" (github.com)
Allow? [y/N]
```

Answering yes grants that site 5 minutes by default (`-remember 0` to be asked
every time). Grants are dropped when the vault locks.

## Using it

**Filling a login**

1. Click the field you want filled
2. Click the openpass toolbar icon
3. Click **Username** or **Password**

**Saving a new site**

On a site with no saved login, the popup offers **Save this site…**:

- **Name** is prefilled from the domain
- **Use what's on the page** pulls the username and password you just typed into
  the login form
- **⟳** generates a new password instead
- **Save** stores it against the page's origin, so it matches on every subdomain
  afterwards

The capture button guesses which field is which — unlike filling, which never
does. Guessing is safe here because the result lands in a form you review before
saving, so a wrong guess costs you an edit. A wrong guess while filling would
leak a password.

The popup lists only entries registered to the page's registrable domain. The
daemon decides that, not the extension — `paypal.com.evil.com` resolves to
`evil.com` and matches nothing.

## What the extension can and cannot do

Enforced by the daemon, not by this code:

| | |
|---|---|
| `status`, `vault.match`, `vault.list`, `vault.get` | allowed |
| `vault.add` | allowed, so new sites can be saved |
| update, delete, unlock, lock, manage clients | **refused** |
| read a password | **only after you approve it** |

Adding is allowed because the risk is clutter, not disclosure: an entry a
hostile extension created holds a password it already knew. Reading an existing
secret still needs your approval, and nothing can modify or delete what is
already there.

One gap worth knowing: a save is not announced. It appears in the daemon log but
`openpass watch` does not surface it, so an unwanted entry would be found by
running `openpass ls`, not by being told.

The popup shows which logins exist for a site using `vault.match`, which never
returns secrets. A password is requested only when you click a specific field
button, and is dropped straight after filling.

## Troubleshooting

| Symptom | Cause |
|---|---|
| "Could not start openpass-bridge" | host manifest missing or wrong extension ID — rerun `install-host.sh`, restart the browser |
| "Not approved yet" | run the `openpass client approve` command shown |
| "Approval needed" | `openpass watch` is not running |
| "Vault is locked" | run `openpass unlock` |
| "Click the field you want filled" | nothing was focused; click the field first |
| Nothing happens on an http page | https only, by design |

## Limitations

- **Chrome-family only.** Firefox uses a different native messaging manifest
  location and key (`allowed_extensions`).
- **No automatic save-on-submit.** Saving is a deliberate click in the popup;
  the extension never offers to save on its own.
- **No TOTP.**
- **`openpass watch` must be running** for any password to be revealed. A
  menubar app would be the better home for that; the terminal is the honest
  minimum.
