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

chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  if (msg.action === "fill") {
    respond(fill(msg.value, msg.mode));
    return true;
  }
  if (msg.action === "focused") {
    respond(describeFocused());
    return true;
  }
  return false;
});
