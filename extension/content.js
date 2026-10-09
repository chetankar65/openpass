// Tracks which field the user last focused, and fills it on request.
//
// There is no field detection here on purpose. The user's click already says
// which field they mean, which removes every case that breaks heuristics:
// shadow DOM, custom elements, multi-step logins, SPAs that render late.

const HOST = "com.openpass.bridge";

let lastFocused = null;

function isFillable(el) {
  if (!el) return false;
  if (el.isContentEditable) return true;
  if (el.tagName !== "INPUT" && el.tagName !== "TEXTAREA") return false;
  if (el.disabled || el.readOnly) return false;

  const skip = ["checkbox", "radio", "submit", "button", "file", "hidden", "range", "color"];
  return !skip.includes((el.type || "").toLowerCase());
}

// focusin crosses shadow boundaries where focus does not, so it catches fields
// inside custom elements too.
document.addEventListener(
  "focusin",
  (event) => {
    const el = event.composedPath ? event.composedPath()[0] : event.target;
    if (isFillable(el)) lastFocused = el;
  },
  true
);

// Setting .value directly is invisible to React and Vue, which track state
// through their own event system. Going through the prototype's setter and
// then dispatching input/change is what makes the page notice.
function setValue(el, value) {
  if (el.isContentEditable) {
    el.textContent = value;
    el.dispatchEvent(new InputEvent("input", { bubbles: true, data: value }));
    return;
  }

  const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value").set;

  setter.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// Last resort for fields that only react to real keystrokes.
function typeValue(el, value) {
  el.focus();
  for (const ch of value) {
    el.dispatchEvent(new KeyboardEvent("keydown", { key: ch, bubbles: true }));
    setValue(el, (el.value || "") + ch);
    el.dispatchEvent(new KeyboardEvent("keyup", { key: ch, bubbles: true }));
  }
}

function fill(value, mode) {
  const el = lastFocused;
  if (!isFillable(el) || !el.isConnected) {
    return { ok: false, error: "Click the field you want filled, then try again." };
  }

  el.focus();
  if (mode === "type") {
    typeValue(el, value);
  } else {
    setValue(el, value);
  }

  // Briefly outline the field so it is obvious what was filled.
  const previous = el.style.outline;
  el.style.outline = "2px solid #2d7";
  setTimeout(() => {
    el.style.outline = previous;
  }, 600);

  return { ok: true };
}

// Reads whatever is currently typed into the page's login fields.
//
// This guesses which field is which, unlike filling, which never does. Guessing
// is safe here: the result lands in a form you review before saving, so a wrong
// guess costs an edit. A wrong guess while filling would leak a password.
function capture() {
  const visible = (el) => {
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && getComputedStyle(el).visibility !== "hidden";
  };

  const passwords = [...document.querySelectorAll("input[type=password]")].filter(visible);
  const password = passwords.length ? passwords[0].value : "";

  let username = "";

  // Prefer the field the page itself labels as the username.
  const declared = document.querySelector(
    "input[autocomplete='username'], input[autocomplete='email']"
  );
  if (declared && visible(declared) && declared.value) {
    username = declared.value;
  }

  // Otherwise the nearest filled text field above the password.
  if (!username && passwords.length) {
    const candidates = [...document.querySelectorAll("input")].filter(
      (el) => ["text", "email", "tel", ""].includes((el.type || "").toLowerCase()) && visible(el) && el.value
    );
    const pwIndex = [...document.querySelectorAll("input")].indexOf(passwords[0]);
    const before = candidates.filter(
      (el) => [...document.querySelectorAll("input")].indexOf(el) < pwIndex
    );
    username = (before.length ? before[before.length - 1] : candidates[0])?.value || "";
  }

  return { username, password, title: document.title || "" };
}

function describeFocused() {
  const el = lastFocused;
  if (!isFillable(el) || !el.isConnected) return null;

  return {
    tag: el.tagName.toLowerCase(),
    type: (el.type || "").toLowerCase(),
    name: el.name || el.id || el.getAttribute("aria-label") || "",
    isPassword: (el.type || "").toLowerCase() === "password",
  };
}

// Every frame on the page runs a copy of this script, and a message sent to
// the tab reaches all of them. A frame with nothing to say stays silent so the
// first reply comes from the frame the user is actually working in, rather than
// from whichever one happened to answer first.
chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  const focused = describeFocused();

  if (msg.action === "focused") {
    if (!focused) return false;
    respond(focused);
    return true;
  }

  if (msg.action === "fill") {
    if (!focused) return false;
    respond(fill(msg.value, msg.mode));
    return true;
  }

  if (msg.action === "capture") {
    const found = capture();
    if (!found.username && !found.password) return false;
    respond(found);
    return true;
  }

  return false;
});
