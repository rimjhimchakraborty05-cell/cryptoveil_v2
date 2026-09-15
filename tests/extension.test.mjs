import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(
  new URL("../extension/background.js", import.meta.url),
  "utf8",
);
let fixtureNumber = 0;

// Model Chrome storage and the application's receipts without a browser or network.
async function worker(t) {
  const originalChrome = globalThis.chrome;
  const originalFetch = globalThis.fetch;
  const storage = { cv_queue: [], cv_queue_version: 2 };
  const network = { mode: "ok", attempts: [] };
  const listener = { addListener() {} };
  let onMessage;
  const runtime = {
    id: "a".repeat(32),
    getURL: (path) => `chrome-extension://${"a".repeat(32)}/${path}`,
    onStartup: listener,
    onMessage: {
      addListener: (fn) => {
        onMessage = fn;
      },
    },
  };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get(keys) {
          const names = typeof keys === "string" ? [keys] : keys;
          return structuredClone(
            Object.fromEntries(names.map((key) => [key, storage[key]])),
          );
        },
        async set(values) {
          Object.assign(storage, structuredClone(values));
        },
      },
    },
    runtime,
    alarms: { create() {}, onAlarm: listener },
    action: { async setBadgeText() {}, async setBadgeBackgroundColor() {} },
    webNavigation: { onCommitted: listener },
    webRequest: { onBeforeRequest: listener },
    tabs: {
      async sendMessage() {},
      async query() {
        return [];
      },
      async create() {},
    },
  };
  globalThis.fetch = async (url, options) => {
    const payload = JSON.parse(options.body);
    if (url.endsWith("/pairing/complete")) {
      return Response.json({ token: "test-pairing-token", name: payload.name });
    }
    assert.equal(options.headers.Authorization, "Bearer test-pairing-token");
    if (url.endsWith("/telemetry")) {
      network.attempts.push(payload);
      if (network.mode === "offline")
        throw new TypeError("Network unavailable");
      if (network.mode === "paused") {
        return Response.json(
          { detail: "Evidence integrity failed; collection paused" },
          { status: 503 },
        );
      }
      return Response.json({
        received: true,
        event_id:
          network.mode === "wrong-receipt" ? "another-event" : payload.event_id,
        seq: network.attempts.length - 1,
        hash: "a".repeat(64),
      });
    }
    assert.ok(url.endsWith("/heartbeat"));
    return Response.json({ received: true, collection_paused: false });
  };
  t.after(() => {
    globalThis.chrome = originalChrome;
    globalThis.fetch = originalFetch;
  });
  const code = `${source}\n// isolated fixture ${++fixtureNumber}`;
  const module = await import(
    `data:text/javascript;base64,${Buffer.from(code).toString("base64")}`
  );
  await module.ready;
  await module.startup;
  const response = await new Promise((resolve) => {
    onMessage(
      {
        type: "cv_pair",
        code: "12345678",
        name: "Test browser",
        app_url: "http://127.0.0.1:8765",
      },
      { id: runtime.id, url: runtime.getURL("popup.html") },
      resolve,
    );
  });
  assert.deepEqual(response, { ok: true });
  const send = (
    payload,
    sender = { id: runtime.id, url: runtime.getURL("popup.html") },
  ) =>
    new Promise((resolve) => {
      onMessage(payload, sender, resolve);
    });
  return { ...module, storage, network, send };
}

test("a stored receipt removes the acknowledged event, including sequence zero", async (t) => {
  const w = await worker(t);
  await w.queueEvent({ type: "site_visit", hostname: "example.com" });
  assert.equal(w.storage.cv_queue.length, 0);
  assert.equal(w.storage.cv_latest_receipt.seq, 0);
  assert.equal(w.storage.cv_status.online, true);
});

test("offline delivery retains the same event identity for a safe retry", async (t) => {
  const w = await worker(t);
  w.network.mode = "offline";
  await w.queueEvent({ type: "site_visit", hostname: "example.com" });
  assert.equal(w.storage.cv_queue.length, 1);
  const pending = structuredClone(w.storage.cv_queue[0]);
  assert.equal(w.storage.cv_status.online, false);
  w.network.mode = "ok";
  await w.flushQueue();
  assert.equal(w.storage.cv_queue.length, 0);
  assert.deepEqual(w.network.attempts, [pending, pending]);
});

test("an unrelated receipt cannot discard evidence", async (t) => {
  const w = await worker(t);
  w.network.mode = "wrong-receipt";
  await w.queueEvent({ type: "site_warning", hostname: "paypa1.com" });
  assert.equal(w.storage.cv_queue.length, 1);
  assert.match(w.storage.cv_status.last_error, /valid storage receipt/);
  assert.equal(w.storage.cv_latest_receipt, undefined);
});

test("an integrity failure pauses delivery and preserves queued evidence", async (t) => {
  const w = await worker(t);
  w.network.mode = "paused";
  await w.queueEvent({ type: "site_visit", hostname: "example.com" });
  assert.equal(w.storage.cv_queue.length, 1);
  assert.equal(w.storage.cv_status.collection_paused, true);
});

test("queue overflow preserves existing evidence and records the collection gap", async (t) => {
  const w = await worker(t);
  w.network.mode = "offline";
  w.storage.cv_queue = Array.from({ length: 1000 }, () =>
    w.normalize({ type: "site_visit", hostname: "example.com" }),
  );
  const firstId = w.storage.cv_queue[0].event_id;
  await w.queueEvent({ type: "site_visit", hostname: "overflow.example.com" });
  assert.equal(w.storage.cv_queue.length, 1000);
  assert.equal(w.storage.cv_queue[0].event_id, firstId);
  assert.equal(w.storage.cv_gap_pending, 1);
  assert.equal(w.storage.cv_dropped_total, 1);
  w.network.mode = "ok";
  await w.flushQueue();
  const gaps = w.storage.cv_queue.filter(
    (event) => event.type === "collection_gap",
  );
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0].dropped_count, 1);
  assert.equal(w.storage.cv_gap_pending, 0);
});

test("normalization excludes page secrets and URL paths from delivery", async (t) => {
  const w = await worker(t);
  await w.queueEvent({
    type: "sensitive_field_used",
    hostname: "https://example.com/private/path?token=secret",
    field_type: "password",
    password: "secret-password",
    value: "secret-value",
    email: "private@example.com",
    score: -10,
  });
  const sent = w.network.attempts[0];
  assert.equal(sent.hostname, "example.com");
  assert.equal(sent.score, 0);
  assert.deepEqual(Object.keys(sent).sort(), [
    "collected_at_ms",
    "event_id",
    "field_type",
    "hostname",
    "profile_context",
    "score",
    "type",
  ]);
  assert.equal(w.normalize({ type: "unsupported" }), null);
  assert.equal(w.localScore("https://accounts.google.com").score, 100);
  assert.ok(w.localScore("https://paypa1.com").score < 65);
});

test("account changes never relabel already queued evidence", async (t) => {
  const w = await worker(t);
  await w.send({
    type: "cv_identity_set",
    mode: "manual",
    email: "first@example.test",
  });
  w.network.mode = "offline";
  await w.queueEvent({ type: "site_visit", hostname: "example.test" });
  await w.send({
    type: "cv_identity_set",
    mode: "manual",
    email: "second@example.test",
  });
  assert.equal(
    w.storage.cv_queue[0].profile_context.account_email,
    "first@example.test",
  );
  w.network.mode = "ok";
  await w.flushQueue();
  assert.equal(
    w.network.attempts.at(-1).profile_context.account_email,
    "first@example.test",
  );
  await w.queueEvent({ type: "site_visit", hostname: "example.test" });
  assert.equal(
    w.network.attempts.at(-1).profile_context.account_email,
    "second@example.test",
  );
  assert.equal(
    w.network.attempts.at(-1).profile_context.account_source,
    "user_provided",
  );
});

test("profile email uses permission and clears stale identity after sign-out", async (t) => {
  const w = await worker(t);
  let email = "profile@example.test",
    allowed = true;
  chrome.permissions = { contains: async () => allowed };
  chrome.identity = { getProfileUserInfo: async () => ({ email }) };
  let result = await w.send({ type: "cv_identity_set", mode: "profile" });
  assert.equal(result.profile_context.account_email, email);
  assert.equal(result.profile_context.account_source, "browser_profile");
  email = "";
  await w.flushQueue();
  result = await w.send({ type: "cv_status" });
  assert.equal(result.profile_context.account_email, null);
  assert.equal(result.profile_context.account_source, "unavailable");
  email = "profile@example.test";
  allowed = false;
  await w.flushQueue();
  assert.equal(w.storage.cv_config.account_email, null);
});

test("page scripts cannot change the browser account label", async (t) => {
  const w = await worker(t);
  const response = await w.send(
    { type: "cv_identity_set", mode: "manual", email: "forged@example.test" },
    {
      id: "a".repeat(32),
      url: "https://example.test",
      tab: { id: 1, url: "https://example.test" },
    },
  );
  assert.match(response.error, /popup only/);
  assert.equal(w.storage.cv_config.account_email, null);
});

test("Chrome and Edge identification is independent of the search engine", async (t) => {
  const w = await worker(t);
  assert.equal(
    w.browserFamily({
      userAgent: "Mozilla/5.0 Chrome/152.0 Safari/537.36 Edg/152.0",
    }),
    "Edge",
  );
  assert.equal(
    w.browserFamily({ userAgent: "Mozilla/5.0 Chrome/152.0 Safari/537.36" }),
    "Chrome",
  );
  assert.equal(w.browserFamily({ userAgent: "Unknown browser" }), "Unknown");
});

test("DOM analysis accepts observable AI components without matching lookalike domains", async () => {
  const context = vm.createContext({ URL });
  vm.runInContext(
    await readFile(new URL("../extension/signals.js", import.meta.url), "utf8"),
    context,
  );
  const classify = context.CryptoVeilSignals.classify;
  assert.equal(
    classify(
      "SCRIPT",
      "https://api.openai.com/widget.js?token=private",
      "",
      "https://work.example",
    ).ai_domain,
    "api.openai.com",
  );
  assert.equal(
    classify("IFRAME", "https://sider.ai/panel", "", "https://work.example")
      .type,
    "shadow_ai_iframe",
  );
  assert.equal(
    classify(
      "SCRIPT",
      "https://openai.com.attacker.test/a.js",
      "",
      "https://work.example",
    ),
    null,
  );
  assert.equal(
    classify("DIV", "", "openai", "https://work.example").dom_signal,
    "ai_component",
  );
  assert.equal(classify("INPUT", "", "", "https://work.example"), null);
  assert.equal(classify("DIV", "", "__proto__", "https://work.example"), null);
});
