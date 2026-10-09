// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
//
// Account page actions. Every state-changing request is a same-origin fetch
// with the PC-CSRF header and a JSON body (HR-151). The page runs under
// Trusted Types: text is written with textContent only.
"use strict";

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
    throw new Error(data.error || ("HTTP " + res.status));
  }
  return data;
}

function say(text) {
  const el = document.getElementById("status");
  if (el) { el.textContent = text; }
}

document.getElementById("sign-out")?.addEventListener("click", async () => {
  try {
    await post("/logout");
    window.location.assign("/signed-out");
  } catch (e) {
    say("Sign-out failed: " + e.message);
  }
});

for (const btn of document.querySelectorAll("button.revoke-session")) {
  btn.addEventListener("click", async () => {
    try {
      await post("/account/sessions/" + encodeURIComponent(btn.dataset.id) + "/revoke");
      window.location.reload();
    } catch (e) {
      say("Could not sign that session out: " + e.message);
    }
  });
}
