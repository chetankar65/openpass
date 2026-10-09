// Talks to openpass-bridge over native messaging.
//
// Manifest V3 stops this service worker after about 30 seconds idle and takes
// the native host with it, so there is no long-lived port to keep. Each call
// gets its own connection. The daemon holds the session, not the socket, so
// reconnecting costs nothing.

const HOST = "com.openpass.bridge";

let nextId = 0;

function send(method, params) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    let port;

    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      reject(new Error("Could not start openpass-bridge. Is it installed?"));
      return;
    }

    const done = (fn, arg) => {
      try {
        port.disconnect();
      } catch (e) {
        /* already gone */
      }
      fn(arg);
    };

    port.onMessage.addListener((msg) => {
      if (msg.id !== id) return;
      if (msg.error) {
        const err = new Error(msg.error.message);
        err.code = msg.error.code;
        done(reject, err);
      } else {
        done(resolve, msg.result);
      }
    });

    port.onDisconnect.addListener(() => {
      const e = chrome.runtime.lastError;
      reject(new Error(e ? e.message : "openpass-bridge closed the connection"));
    });

    port.postMessage({ id, method, params });
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  if (msg.action !== "rpc") return false;

  send(msg.method, msg.params)
    .then((result) => respond({ ok: true, result }))
    .catch((err) => respond({ ok: false, error: err.message, code: err.code }));

  return true;
});
