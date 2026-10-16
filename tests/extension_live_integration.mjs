import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";

const [phase, storagePath, appUrl = "http://127.0.0.1:8765"] = process.argv.slice(2);
if (!["pair", "offline", "recover"].includes(phase) || !storagePath) {
  throw new Error(
    "Usage: node tests/extension_live_integration.mjs <pair|offline|recover> <storage.json> [appUrl]",
  );
}

const extensionId = "a".repeat(32);
const extensionOrigin = `chrome-extension://${extensionId}`;
const popupUrl = `${extensionOrigin}/popup.html`;
const source = await readFile(
  new URL("../extension/background.js", import.meta.url),
  "utf8",
);

let storage = {};
try {
  storage = JSON.parse(await readFile(storagePath, "utf8"));
} catch {
  storage = { cv_queue: [], cv_queue_version: 2 };
}
storage.cv_queue ||= [];
storage.cv_queue_version ||= 2;

const listener = { addListener() {} };
let onMessage;
globalThis.chrome = {
  storage: {
    local: {
      async setAccessLevel() {},
      async get(keys) {
        const names =
          typeof keys === "string"
            ? [keys]
            : Array.isArray(keys)
              ? keys
              : Object.keys(keys || {});
        return structuredClone(
          Object.fromEntries(names.map((key) => [key, storage[key]])),
        );
      },
      async set(values) {
        Object.assign(storage, structuredClone(values));
        await writeFile(storagePath, JSON.stringify(storage, null, 2));
      },
    },
  },
  runtime: {
    id: extensionId,
    getURL: (path) => `${extensionOrigin}/${path}`,
    onStartup: listener,
    onMessage: {
      addListener(fn) {
        onMessage = fn;
      },
    },
  },
  alarms: { create() {}, onAlarm: listener },
  action: {
    async setBadgeText() {},
    async setBadgeBackgroundColor() {},
  },
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

const nativeFetch = globalThis.fetch;
globalThis.fetch = (url, options = {}) => {
  const headers = new Headers(options.headers || {});
  headers.set("Origin", extensionOrigin);
  return nativeFetch(url, { ...options, headers });
};

async function dashboardSession() {
  const session = await nativeFetch(`${appUrl}/api/session`, {
    cache: "no-store",
  });
  assert.equal(session.status, 200);
  const data = await session.json();
  const cookie = session.headers.get("set-cookie")?.split(";", 1)[0];
  assert.ok(cookie, "dashboard session cookie missing");
  return { cookie, csrf: data.csrf_token };
}

async function pairingCode() {
  const { cookie, csrf } = await dashboardSession();
  const response = await nativeFetch(`${appUrl}/api/pairing/code`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CryptoVeil-CSRF": csrf,
      Cookie: cookie,
    },
    body: "{}",
  });
  assert.equal(response.status, 200);
  return (await response.json()).code;
}

async function dashboardEvents() {
  const { cookie } = await dashboardSession();
  const response = await nativeFetch(`${appUrl}/api/events?limit=50`, {
    headers: { Cookie: cookie },
    cache: "no-store",
  });
  assert.equal(response.status, 200);
  return (await response.json()).events;
}

function send(payload) {
  return new Promise((resolve) => {
    onMessage(
      payload,
      { id: extensionId, url: popupUrl },
      resolve,
    );
  });
}

const moduleUrl =
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}#live-${phase}`;
const worker = await import(moduleUrl);
await worker.ready;

if (phase === "pair") {
  const code = await pairingCode();
  const paired = await send({
    type: "cv_pair",
    code,
    name: "Windows integration browser",
    app_url: appUrl,
  });
  assert.deepEqual(paired, { ok: true });

  await worker.queueEvent({
    type: "site_visit",
    hostname: "paired-live.example",
    score: 100,
  });

  assert.equal(storage.cv_queue.length, 0);
  assert.ok(storage.cv_config?.token, "pairing token was not persisted");
  assert.ok(storage.cv_latest_receipt?.hash, "durable storage receipt missing");
  assert.equal(storage.cv_status?.online, true);
  await writeFile(storagePath, JSON.stringify(storage, null, 2));
  process.stdout.write("extension pair + durable receipt: PASS\n");
}

if (phase === "offline") {
  await worker.startup;
  await worker.queueEvent({
    type: "site_visit",
    hostname: "offline-recovery.example",
    score: 100,
  });

  assert.equal(storage.cv_queue.length, 1);
  assert.equal(storage.cv_queue[0].hostname, "offline-recovery.example");
  assert.equal(storage.cv_status?.online, false);
  assert.ok(storage.cv_config?.token, "offline queue lost the paired token");
  await writeFile(storagePath, JSON.stringify(storage, null, 2));
  process.stdout.write("extension offline queue persistence: PASS\n");
}

if (phase === "recover") {
  await worker.startup;

  const deadline = Date.now() + 10000;
  while (storage.cv_queue.length && Date.now() < deadline) {
    await worker.flushQueue();
    await new Promise((resolve) => setTimeout(resolve, 150));
  }

  assert.equal(storage.cv_queue.length, 0);
  assert.equal(storage.cv_status?.online, true);
  assert.ok(storage.cv_latest_receipt?.hash, "recovery receipt missing");

  const events = await dashboardEvents();
  const recovered = events.find(
    (item) => item.event?.hostname === "offline-recovery.example",
  );
  assert.ok(recovered, "queued browser event was not recovered after app restart");
  assert.equal(recovered.event?.topic, "browser.telemetry");
  assert.ok(recovered.hash, "recovered event is missing forensic hash");
  await writeFile(storagePath, JSON.stringify(storage, null, 2));
  process.stdout.write("extension restart recovery + evidence persistence: PASS\n");
}
