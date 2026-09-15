/* CryptoVeil: paired, acknowledged evidence delivery. No form values or URL paths are collected. */
const DEFAULT_APP = "http://127.0.0.1:8765";
const QUEUE_LIMIT = 1000;
const TYPES = new Set([
  "site_visit",
  "site_warning",
  "shadow_ai_network",
  "shadow_ai_iframe",
  "sensitive_field_used",
  "masking_activated",
  "masking_deactivated",
  "collection_gap",
]);
const BRANDS = [
  "google.com",
  "paypal.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "facebook.com",
  "netflix.com",
  "instagram.com",
  "linkedin.com",
  "github.com",
  "youtube.com",
];
const AI_HOSTS = [
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.perplexity.ai",
  "api.cohere.ai",
  "api.mistral.ai",
  "copilot.microsoft.com",
  "api.together.xyz",
  "openrouter.ai",
];
const cache = new Map();
let config = { app_url: DEFAULT_APP, token: "", name: "" },
  flushing = false;
function hostOnly(value) {
  try {
    return new URL(
      value.includes("://") ? value : `https://${value}`,
    ).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}
function appURL(value) {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost"].includes(url.hostname) ||
    url.username ||
    url.password
  )
    throw new Error("Use a local address such as http://127.0.0.1:8765");
  return url.origin;
}
function editDistance(a, b) {
  let row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const next = [i];
    for (let j = 1; j <= b.length; j++)
      next[j] = Math.min(
        next[j - 1] + 1,
        row[j] + 1,
        row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    row = next;
  }
  return row[b.length];
}
function localScore(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { score: 100, reasons: [] };
  }
  const host = url.hostname.toLowerCase();
  let score = 100;
  const reasons = [];
  if (url.protocol === "http:") {
    score -= 25;
    reasons.push("This page uses unencrypted HTTP.");
  }
  if (BRANDS.some((b) => host === b || host.endsWith(`.${b}`)))
    return { score, reasons };
  const candidate = host.replace(/^www\./, "");
  for (const brand of BRANDS) {
    if (Math.abs(candidate.length - brand.length) > 2) continue;
    const distance = editDistance(candidate, brand);
    if (distance > 0 && distance <= 2) {
      score -= 50;
      reasons.push(`The hostname resembles ${brand}; check its spelling.`);
      break;
    }
  }
  if (host.includes("xn--")) {
    score -= 15;
    reasons.push("This is an internationalised hostname; check it carefully.");
  }
  const label = host.split(".")[0],
    digits = (label.match(/\d/g) || []).length;
  if (label.length > 18 && digits / label.length > 0.3) {
    score -= 20;
    reasons.push("The hostname has a long, unusual letter-and-number pattern.");
  }
  return { score: Math.max(0, score), reasons };
}
function normalize(event) {
  if (!event || typeof event !== "object" || !TYPES.has(event.type))
    return null;
  const result = {
    event_id: event.event_id || crypto.randomUUID(),
    type: event.type,
    collected_at_ms: Number.isInteger(event.collected_at_ms)
      ? event.collected_at_ms
      : Number.isInteger(event.ts)
        ? event.ts
        : Date.now(),
  };
  if (event.hostname) {
    const h = hostOnly(event.hostname);
    if (h && /^[a-z0-9][a-z0-9.\-]{0,252}$/.test(h)) result.hostname = h;
  }
  if (Number.isInteger(event.score))
    result.score = Math.max(0, Math.min(100, event.score));
  if (Array.isArray(event.reasons))
    result.reasons = event.reasons
      .slice(0, 10)
      .map((s) => String(s).slice(0, 250));
  const ai = hostOnly(event.ai_domain || event.aiDomain || "");
  if (ai) result.ai_domain = ai;
  if (event.field_type)
    result.field_type = String(event.field_type).slice(0, 30);
  if (event.dropped_count)
    result.dropped_count = Math.min(
      2 ** 31 - 1,
      Math.max(0, event.dropped_count),
    );
  return result;
}
async function initialize() {
  try {
    if (chrome.storage.local.setAccessLevel)
      await chrome.storage.local.setAccessLevel({
        accessLevel: "TRUSTED_CONTEXTS",
      });
  } catch {}
  const data = await chrome.storage.local.get([
    "cv_config",
    "cv_queue",
    "cv_queue_version",
    "cv_legacy_queue",
  ]);
  config = { ...config, ...data.cv_config };
  try {
    config.app_url = appURL(config.app_url);
  } catch {
    config.app_url = DEFAULT_APP;
    config.token = "";
  }
  if (data.cv_queue_version !== 2) {
    const old = data.cv_queue || [],
      migrated = old.map(normalize).filter(Boolean);
    await chrome.storage.local.set({
      cv_queue: migrated,
      cv_queue_version: 2,
      cv_legacy_queue: [
        ...(data.cv_legacy_queue || []),
        ...old.filter((e) => !TYPES.has(e.type)),
      ],
      cv_config: config,
    });
  }
}
const ready = initialize();
let serial = ready;
function locked(work) {
  const result = serial.then(work);
  serial = result.catch(() => {});
  return result;
}
async function updateStatus(update) {
  await locked(async () => {
    const { cv_status = {} } = await chrome.storage.local.get("cv_status");
    await chrome.storage.local.set({
      cv_status: { ...cv_status, ...update, updated_at: Date.now() },
    });
  });
}
async function queueEvent(event) {
  const normalized = normalize(event);
  if (!normalized) return;
  await locked(async () => {
    const data = await chrome.storage.local.get([
      "cv_queue",
      "cv_gap_pending",
      "cv_dropped_total",
    ]);
    const queue = data.cv_queue || [];
    if (queue.length >= QUEUE_LIMIT) {
      await chrome.storage.local.set({
        cv_gap_pending: Math.min(2 ** 31 - 1, (data.cv_gap_pending || 0) + 1),
        cv_dropped_total: Math.min(
          2 ** 31 - 1,
          (data.cv_dropped_total || 0) + 1,
        ),
      });
      return;
    }
    queue.push(normalized);
    await chrome.storage.local.set({ cv_queue: queue });
  });
  await flushQueue();
}
async function request(path, body, token = config.token) {
  const response = await fetch(`${config.app_url}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(8000),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {}
  if (!response.ok) {
    const error = new Error(
      typeof data.detail === "string"
        ? data.detail
        : `Request rejected (${response.status}). Evidence stays queued.`,
    );
    error.status = response.status;
    throw error;
  }
  return data;
}
async function flushQueue() {
  await ready;
  if (flushing || !config.token) return;
  flushing = true;
  try {
    for (let i = 0; i < 40; i++) {
      const event = await locked(async () => {
        const data = await chrome.storage.local.get([
          "cv_queue",
          "cv_gap_pending",
        ]);
        const queue = data.cv_queue || [];
        if (data.cv_gap_pending && queue.length < QUEUE_LIMIT) {
          queue.push(
            normalize({
              type: "collection_gap",
              dropped_count: data.cv_gap_pending,
              reasons: [
                "The offline queue reached capacity; some observations could not be saved.",
              ],
            }),
          );
          await chrome.storage.local.set({
            cv_queue: queue,
            cv_gap_pending: 0,
          });
        }
        return queue[0];
      });
      if (!event) break;
      const ack = await request("/api/browser/telemetry", event);
      if (
        !ack.received ||
        ack.event_id !== event.event_id ||
        !Number.isInteger(ack.seq) ||
        !/^[a-f0-9]{64}$/.test(ack.hash || "")
      )
        throw new Error(
          "The app did not provide a valid storage receipt. Evidence stays queued.",
        );
      await locked(async () => {
        const { cv_queue = [] } = await chrome.storage.local.get("cv_queue");
        await chrome.storage.local.set({
          cv_queue: cv_queue.filter((e) => e.event_id !== event.event_id),
          cv_latest_receipt: {
            seq: ack.seq,
            hash: ack.hash,
            received_at: Date.now(),
          },
        });
      });
    }
    const { cv_queue = [], cv_dropped_total = 0 } =
      await chrome.storage.local.get(["cv_queue", "cv_dropped_total"]);
    const heartbeat = await request("/api/browser/heartbeat", {
      queued_events: cv_queue.length,
      dropped_events: cv_dropped_total,
    });
    await updateStatus({
      online: true,
      collection_paused: heartbeat.collection_paused,
      last_error: "",
    });
    await chrome.action.setBadgeText({
      text: heartbeat.collection_paused
        ? "!"
        : cv_queue.length
          ? String(Math.min(99, cv_queue.length))
          : "",
    });
    await chrome.action.setBadgeBackgroundColor({
      color: heartbeat.collection_paused ? "#ac3e3b" : "#356b4f",
    });
  } catch (error) {
    if (error.status === 401) {
      await locked(async () => {
        config.token = "";
        await chrome.storage.local.set({ cv_config: config });
      });
    }
    await updateStatus({
      online: false,
      collection_paused: error.status === 503,
      last_error: error.message,
    });
    await chrome.action.setBadgeText({ text: "!" });
    await chrome.action.setBadgeBackgroundColor({ color: "#a56a26" });
  } finally {
    flushing = false;
  }
}
chrome.alarms.create("cv_delivery", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "cv_delivery") flushQueue();
});
chrome.runtime.onStartup.addListener(() => flushQueue());
ready.then(() => flushQueue()).catch(() => {});
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/.test(details.url)) return;
  const url = new URL(details.url);
  if (["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) return;
  const scored = localScore(details.url);
  cache.set(details.tabId, scored);
  if (cache.size > 256) cache.delete(cache.keys().next().value);
  chrome.tabs
    .sendMessage(details.tabId, { type: "cv_trust_update", ...scored })
    .catch(() => {});
  await queueEvent({ type: "site_visit", hostname: url.hostname, ...scored });
  if (scored.score < 65)
    await queueEvent({
      type: "site_warning",
      hostname: url.hostname,
      ...scored,
    });
});
const aiLastSeen = new Map();
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const host = hostOnly(details.url);
    const matched = AI_HOSTS.find((h) => host === h || host?.endsWith(`.${h}`));
    if (!matched) return;
    const key = `${details.tabId}:${matched}`,
      now = Date.now();
    if (now - (aiLastSeen.get(key) || 0) < 60000) return;
    aiLastSeen.set(key, now);
    if (aiLastSeen.size > 256)
      aiLastSeen.delete(aiLastSeen.keys().next().value);
    queueEvent({
      type: "shadow_ai_network",
      ai_domain: matched,
      hostname: host,
    }).catch(() => {});
  },
  { urls: ["http://*/*", "https://*/*"] },
);
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id) return false;
  (async () => {
    await ready;
    const popup = sender.url === chrome.runtime.getURL("popup.html");
    if (message.type === "cv_dom_event" && sender.tab) {
      const pageHost = hostOnly(sender.tab.url || "");
      if (
        ![
          "shadow_ai_iframe",
          "sensitive_field_used",
          "masking_activated",
          "masking_deactivated",
        ].includes(message.payload?.type)
      )
        throw new Error("Unsupported page observation");
      await queueEvent({ ...message.payload, hostname: pageHost });
      return { ok: true };
    }
    if (message.type === "cv_get_page_settings") {
      const data = await chrome.storage.local.get("cv_masking");
      const url = sender.tab?.url || message.url || "";
      return { ...localScore(url), masking: Boolean(data.cv_masking) };
    }
    if (!popup)
      throw new Error(
        "This action is available from the extension popup only.",
      );
    if (message.type === "cv_status") {
      const data = await chrome.storage.local.get([
        "cv_queue",
        "cv_status",
        "cv_latest_receipt",
        "cv_dropped_total",
        "cv_masking",
        "cv_legacy_queue",
      ]);
      return {
        paired: Boolean(config.token),
        name: config.name,
        app_url: config.app_url,
        queue_count: (data.cv_queue || []).length,
        status: data.cv_status || {},
        last_receipt: data.cv_latest_receipt,
        dropped_total: data.cv_dropped_total || 0,
        masking: Boolean(data.cv_masking),
        legacy_count: (data.cv_legacy_queue || []).length,
      };
    }
    if (message.type === "cv_pair") {
      const url = appURL(message.app_url);
      let result;
      await locked(async () => {
        config.app_url = url;
        result = await request(
          "/api/pairing/complete",
          {
            code: String(message.code).trim(),
            name: String(message.name || "My browser").slice(0, 60),
          },
          "",
        );
        config = { app_url: url, token: result.token, name: result.name };
        await chrome.storage.local.set({ cv_config: config });
      });
      await flushQueue();
      return { ok: true };
    }
    if (message.type === "cv_retry") {
      await flushQueue();
      return { ok: true };
    }
    if (message.type === "cv_masking") {
      await locked(() =>
        chrome.storage.local.set({ cv_masking: Boolean(message.active) }),
      );
      const tabs = await chrome.tabs.query({});
      await Promise.allSettled(
        tabs.map((tab) =>
          chrome.tabs.sendMessage(tab.id, {
            type: "cv_masking",
            active: Boolean(message.active),
          }),
        ),
      );
      return { ok: true };
    }
    if (message.type === "cv_open_app") {
      await chrome.tabs.create({ url: `${config.app_url}/dashboard/` });
      return { ok: true };
    }
    throw new Error("Unknown request");
  })()
    .then(respond)
    .catch((error) => respond({ error: error.message }));
  return true;
});
// Pure functions are exported for regression tests; tokens never leave the worker.
export { localScore, normalize, queueEvent, flushQueue, ready };
