const statusEl = document.getElementById("status");
const addBar = document.getElementById("addBar");
const addForm = document.getElementById("addForm");
const addError = document.getElementById("addError");
const entriesEl = document.getElementById("entries");
const domainEl = document.getElementById("domain");
const hintEl = document.getElementById("hint");

function rpc(method, params) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action: "rpc", method, params }, (resp) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!resp) return reject(new Error("no response from the extension background"));
      if (!resp.ok) {
        const err = new Error(resp.error);
        err.code = resp.code;
        return reject(err);
      }
      resolve(resp.result);
    });
  });
}

function tabMessage(tabId, msg) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, msg, (resp) => {
      if (chrome.runtime.lastError) return resolve(null);
      resolve(resp);
    });
  });
}

function setStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.className = isError ? "error" : "";
  statusEl.hidden = !text;
}

function setHint(html, warn) {
  hintEl.innerHTML = html;
  hintEl.className = warn ? "warn" : "";
  hintEl.hidden = !html;
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// Fills the field the user focused before opening this popup. The secret is
// requested only now, at the moment of use, and is not kept afterwards.
async function fillField(tabId, entryId, field, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "…";

  try {
    const entry = await rpc("vault.get", { id: entryId, reveal: field === "password" });
    const value = field === "password" ? entry.password : entry.username;

    if (!value) {
      setStatus(`That entry has no ${field}.`, true);
      return;
    }

    const result = await tabMessage(tabId, { action: "fill", value });
    if (!result) {
      setStatus("The page did not respond. Reload it and try again.", true);
    } else if (!result.ok) {
      setStatus(result.error, true);
    } else {
      window.close();
    }
  } catch (err) {
    if (err.code === -32001) {
      setStatus("Your vault is locked. Run `openpass unlock`.", true);
    } else if (err.code === -32005) {
      setHint(`Not approved yet.<br>Run: <code>${err.message.replace(/^.*approve /, "openpass client approve ")}</code>`, true);
      setStatus("", false);
    } else if (err.code === -32007) {
      setStatus("Request declined.", true);
    } else if (err.code === -32006) {
      setHint(`Approval needed. Run <code>openpass watch</code> in a terminal, then try again.`, true);
      setStatus("", false);
    } else {
      setStatus(err.message, true);
    }
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderEntries(tabId, entries, focused) {
  entriesEl.replaceChildren();

  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "entry";

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = entry.name;
    row.appendChild(name);

    if (entry.username) {
      const user = document.createElement("div");
      user.className = "user";
      user.textContent = entry.username;
      row.appendChild(user);
    }

    const fields = document.createElement("div");
    fields.className = "fields";

    for (const field of ["username", "password"]) {
      const button = document.createElement("button");
      button.textContent = field === "username" ? "Username" : "Password";
      button.disabled = !focused;
      button.addEventListener("click", () => fillField(tabId, entry.id, field, button));
      fields.appendChild(button);
    }

    row.appendChild(fields);
    entriesEl.appendChild(row);
  }
}

const PASSWORD_ALPHABET =
  "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";

// Unbiased selection: rejecting the tail of the byte range keeps every
// character equally likely, which taking a byte mod 68 would not.
function generatePassword(length = 24) {
  const limit = 256 - (256 % PASSWORD_ALPHABET.length);
  const out = [];

  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    for (const b of bytes) {
      if (b < limit) out.push(PASSWORD_ALPHABET[b % PASSWORD_ALPHABET.length]);
      if (out.length === length) break;
    }
  }
  return out.join("");
}

// "github.com" reads better as "Github" in a list.
function titleFromDomain(domain) {
  const label = (domain || "").split(".")[0];
  return label ? label.charAt(0).toUpperCase() + label.slice(1) : "";
}

function setupAddForm(tab, domain) {
  const name = document.getElementById("addName");
  const user = document.getElementById("addUser");
  const pass = document.getElementById("addPass");

  name.value = titleFromDomain(domain);

  addBar.hidden = false;

  document.getElementById("addToggle").addEventListener("click", () => {
    addBar.hidden = true;
    addForm.hidden = false;
    (user.value ? pass : user).focus();
  });

  document.getElementById("addCancel").addEventListener("click", () => {
    addForm.hidden = true;
    addBar.hidden = false;
    pass.value = "";
  });

  document.getElementById("addGen").addEventListener("click", () => {
    pass.value = generatePassword();
    pass.type = "text";
  });

  document.getElementById("addShow").addEventListener("click", () => {
    pass.type = pass.type === "password" ? "text" : "password";
  });

  document.getElementById("addCapture").addEventListener("click", async () => {
    const found = await tabMessage(tab.id, { action: "capture" });
    if (!found) {
      addError.textContent = "Nothing filled in on the page yet.";
      addError.hidden = false;
      return;
    }
    if (found.username) user.value = found.username;
    if (found.password) pass.value = found.password;
    addError.hidden = true;
  });

  addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    addError.hidden = true;

    if (!pass.value) {
      addError.textContent = "A password is required.";
      addError.hidden = false;
      return;
    }

    const save = document.getElementById("addSave");
    save.disabled = true;
    save.textContent = "Saving…";

    try {
      await rpc("vault.add", {
        name: name.value || domain,
        username: user.value,
        password: pass.value,
        urls: [new URL(tab.url).origin],
      });
      pass.value = "";
      window.close();
    } catch (err) {
      addError.textContent = err.code === -32001 ? "Vault is locked. Run `openpass unlock`." : err.message;
      addError.hidden = false;
      save.disabled = false;
      save.textContent = "Save";
    }
  });
}

async function main() {
  const tab = await currentTab();
  if (!tab || !tab.url || !tab.url.startsWith("https://")) {
    setStatus("openpass only fills on https pages.", true);
    return;
  }

  let status;
  try {
    status = await rpc("status");
  } catch (err) {
    if (err.code === -32005) {
      setHint(`First run. Approve this extension:<br><code>${err.message.replace(/^.*Run: /, "")}</code>`, true);
      setStatus("", false);
    } else {
      setStatus(err.message, true);
    }
    return;
  }

  if (!status.vault_present) {
    setStatus("No vault yet. Run `openpass init`.", true);
    return;
  }
  if (status.locked) {
    setStatus("Vault is locked. Run `openpass unlock`.", true);
    return;
  }

  let match;
  try {
    match = await rpc("vault.match", { url: tab.url });
  } catch (err) {
    setStatus(err.message, true);
    return;
  }

  domainEl.textContent = match.domain || "";

  setupAddForm(tab, match.domain);

  if (!match.entries || match.entries.length === 0) {
    setStatus(`No saved logins for ${match.domain}.`);
    return;
  }

  const focused = await tabMessage(tab.id, { action: "focused" });
  if (focused) {
    setHint(`Will fill the focused <code>${focused.name || focused.type || focused.tag}</code> field.`);
  } else {
    setHint("Click the field you want to fill, then reopen openpass.", true);
  }

  setStatus("");
  renderEntries(tab.id, match.entries, focused);
}

main();
