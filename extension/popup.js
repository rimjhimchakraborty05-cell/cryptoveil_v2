"use strict";
const $ = (id) => document.getElementById(id);

async function message(payload) {
  const result = await chrome.runtime.sendMessage(payload);
  if (result?.error) throw new Error(result.error);
  return result;
}

function setState(id, text, tone = "neutral") {
  const target = $(id);
  target.textContent = text;
  target.className = `status-value ${tone}`;
}

function verdict(score) {
  if (!Number.isFinite(score)) return { label: "Unavailable", tone: "neutral" };
  if (score >= 80) return { label: "SAFE", tone: "good" };
  if (score >= 50) return { label: "CAUTION", tone: "warn" };
  return { label: "HIGH RISK", tone: "bad" };
}

async function currentPageStatus() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    return { supported: false };
  }

  const host = new URL(tab.url).hostname;
  const trust = await message({ type: "cv_get_page_settings", url: tab.url });

  let page = null;
  try {
    page = await chrome.tabs.sendMessage(tab.id, { type: "cv_page_status" });
  } catch {
    // Restricted pages and pages still loading may not have a content script yet.
  }

  return {
    supported: true,
    host,
    score: trust.score,
    reasons: trust.reasons || [],
    sensitive_fields_detected: Number.isInteger(page?.sensitive_fields_detected)
      ? page.sensitive_fields_detected
      : null,
    shadow_ai_monitoring: true,
  };
}

async function refresh() {
  const data = await message({ type: "cv_status" });
  const recent = Date.now() - (data.status.updated_at || 0) < 90000;
  const online = Boolean(data.paired && recent && data.status.online);

  $("pair-form").hidden = data.paired;
  $("security-panel").hidden = !data.paired;
  $("app-url").value = data.app_url;

  if (!data.paired) return;

  setState(
    "extension-status",
    data.status.collection_paused
      ? "Paused"
      : online
        ? "Connected"
        : "App offline",
    data.status.collection_paused ? "bad" : online ? "good" : "warn",
  );

  setState(
    "auth-status",
    online ? "Authenticated" : "Not verified now",
    online ? "good" : "warn",
  );

  $("connection-note").textContent = data.status.collection_paused
    ? "Evidence collection is paused because the desktop application reported an integrity or storage problem."
    : online
      ? "The paired desktop application is responding and authenticated delivery is available."
      : "The browser is paired, but the desktop application is not currently responding.";

  const page = await currentPageStatus();
  if (!page.supported) {
    $("site-name").textContent = "This browser page is not monitored";
    $("site-score-number").textContent = "—";
    $("site-score-text").textContent =
      "Open a normal HTTP or HTTPS website to view the CryptoVeil trust score.";
    $("site-verdict").textContent = "Unavailable";
    $("site-verdict").className = "verdict neutral";
    $("score-ring").className = "score-ring neutral";
    setState("sensitive-status", "Unavailable", "neutral");
    setState("shadow-status", "Unavailable", "neutral");
    return;
  }

  $("site-name").textContent = page.host;
  $("site-score-number").textContent = page.score;
  const result = verdict(page.score);
  $("site-verdict").textContent = result.label;
  $("site-verdict").className = `verdict ${result.tone}`;
  $("score-ring").className = `score-ring ${result.tone}`;
  $("site-score-text").textContent = page.reasons.length
    ? page.reasons[0]
    : "No strong local hostname risk indicator was found.";

  if (page.sensitive_fields_detected === null) {
    setState("sensitive-status", "Checking page", "neutral");
  } else if (page.sensitive_fields_detected > 0) {
    setState(
      "sensitive-status",
      `${page.sensitive_fields_detected} detected`,
      "warn",
    );
  } else {
    setState("sensitive-status", "None detected", "good");
  }

  setState(
    "shadow-status",
    page.shadow_ai_monitoring ? "Active" : "Inactive",
    page.shadow_ai_monitoring ? "good" : "neutral",
  );
}

async function run(button, work) {
  button.disabled = true;
  $("message").textContent = "";
  try {
    await work();
    await refresh();
  } catch (error) {
    $("message").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

$("pair-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run($("pair-button"), () =>
    message({
      type: "cv_pair",
      code: $("pair-code").value,
      name: $("browser-name").value,
      app_url: $("app-url").value,
    }),
  );
});

$("open-app").addEventListener("click", (event) =>
  run(event.currentTarget, () => message({ type: "cv_open_app" })),
);

(async () => {
  try {
    await refresh();
  } catch (error) {
    $("message").textContent = error.message;
  }
})();

setInterval(() => refresh().catch(() => {}), 3000);
