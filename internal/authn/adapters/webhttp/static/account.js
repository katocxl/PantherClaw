// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Account page actions. Every state-changing request is a same-origin fetch
// with the PC-CSRF header and a JSON body (HR-151). The page runs under
// Trusted Types: text is written with textContent only.
"use strict";

class APIError extends Error {
  constructor(code, data) {
    super(code);
    this.code = code;
    this.data = data;
  }
}

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "PC-CSRF": "1" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) {
    throw new APIError(data.error || ("http_" + res.status), data);
  }
  return data;
}

function say(text) {
  const el = document.getElementById("status");
  if (el) { el.textContent = text; }
}

const messages = {
  recent_auth_required: "For this change, sign in again or verify with a security key you already have.",
  no_keys: "You have no active security key yet.",
  ceremony_invalid: "That request expired or was already used. Try again.",
  verification_failed: "The security key's answer could not be verified.",
  key_suspended: "That key was suspended: its counter went backwards, which can mean it was copied. Remove it and add a new one.",
  key_exists: "That security key is already registered.",
  too_many_keys: "You have too many security keys. Remove one first.",
  not_found: "That item no longer exists.",
  bad_name: "Use a name of 1 to 64 ordinary characters.",
};

function explain(e) {
  return messages[e.code] || ("Something went wrong (" + e.message + ").");
}

// base64url <-> ArrayBuffer, for browsers without the WebAuthn JSON helpers.
function fromB64(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) { out[i] = b.charCodeAt(i); }
  return out.buffer;
}

function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const x of bytes) { s += String.fromCharCode(x); }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function creationOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) {
    return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  }
  const p = Object.assign({}, o);
  p.challenge = fromB64(o.challenge);
  p.user = Object.assign({}, o.user, { id: fromB64(o.user.id) });
  p.excludeCredentials = (o.excludeCredentials || []).map((c) => Object.assign({}, c, { id: fromB64(c.id) }));
  return p;
}

function requestOptions(o) {
  if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  }
  const p = Object.assign({}, o);
  p.challenge = fromB64(o.challenge);
  p.allowCredentials = (o.allowCredentials || []).map((c) => Object.assign({}, c, { id: fromB64(c.id) }));
  return p;
}

function credentialJSON(c) {
  if (typeof c.toJSON === "function") { return c.toJSON(); }
  const r = c.response;
  const out = { id: c.id, rawId: toB64(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(), response: {} };
  out.response.clientDataJSON = toB64(r.clientDataJSON);
  if (r.attestationObject) {
    out.response.attestationObject = toB64(r.attestationObject);
    out.response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  } else {
    out.response.authenticatorData = toB64(r.authenticatorData);
    out.response.signature = toB64(r.signature);
    if (r.userHandle) { out.response.userHandle = toB64(r.userHandle); }
  }
  return out;
}

async function stepUp() {
  const c = await post("/account/step-up-options");
  const cred = await navigator.credentials.get({ publicKey: requestOptions(c.options.publicKey) });
  await post("/account/step-up", { ceremony: c.ceremony, response: credentialJSON(cred) });
}

// withRecentAuth runs action; when the server asks for recent strong
// authentication it steps up with an existing key (if there is one) and
// retries once, or sends the person to sign in again.
async function withRecentAuth(action) {
  try {
    return await action();
  } catch (e) {
    if (!(e instanceof APIError) || e.code !== "recent_auth_required") { throw e; }
    try {
      await stepUp();
    } catch (s) {
      if (s instanceof APIError && s.code === "no_keys") {
        window.location.assign(e.data.sign_in);
        return undefined;
      }
      throw s;
    }
    return await action();
  }
}

async function addKey() {
  const name = (document.getElementById("key-name") || {}).value || "Security key";
  await withRecentAuth(async () => {
    const c = await post("/account/keys/registration-options");
    const cred = await navigator.credentials.create({ publicKey: creationOptions(c.options.publicKey) });
    await post("/account/keys", { ceremony: c.ceremony, name: name, response: credentialJSON(cred) });
  });
}

function on(id, fn) {
  const el = document.getElementById(id);
  if (!el) { return; }
  el.addEventListener("click", async () => {
    try {
      await fn();
    } catch (e) {
      say(e instanceof APIError ? explain(e) : ("The browser stopped the request: " + e.message));
    }
  });
}

function onEach(selector, fn) {
  for (const btn of document.querySelectorAll(selector)) {
    btn.addEventListener("click", async () => {
      try {
        await fn(btn);
      } catch (e) {
        say(e instanceof APIError ? explain(e) : ("The browser stopped the request: " + e.message));
      }
    });
  }
}

on("sign-out", async () => {
  await post("/logout");
  window.location.assign("/signed-out");
});

on("add-key", async () => {
  await addKey();
  window.location.reload();
});

on("step-up", async () => {
  await stepUp();
  window.location.reload();
});

onEach("button.revoke-session", async (btn) => {
  await post("/account/sessions/" + encodeURIComponent(btn.dataset.id) + "/revoke");
  window.location.reload();
});

onEach("button.rename-key", async (btn) => {
  const name = window.prompt("New name for this key (1 to 64 characters)");
  if (name === null) { return; }
  await post("/account/keys/" + encodeURIComponent(btn.dataset.id) + "/rename", { name: name });
  window.location.reload();
});

onEach("button.remove-key", async (btn) => {
  if (!window.confirm("Remove this key? It will no longer work with PantherClaw.")) { return; }
  await withRecentAuth(() => post("/account/keys/" + encodeURIComponent(btn.dataset.id) + "/remove"));
  window.location.reload();
});
