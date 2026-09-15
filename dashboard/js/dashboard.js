"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  view: "overview",
  csrf: "",
  timezone: "Asia/Kolkata",
  status: null,
  events: [],
  selected: null,
  polling: false,
};
const titles = {
  overview: "Overview",
  activity: "Activity",
  evidence: "Evidence",
  reports: "Daily reports",
};
function node(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = String(text);
  return n;
}
function badge(text, cls = "neutral") {
  return node("span", `badge ${cls}`, text);
}
function number(value) {
  return Number.isFinite(value) ? value.toLocaleString() : "—";
}
function timeLabel(ts, full = false) {
  if (!Number.isFinite(ts)) return "Not checked";
  return new Intl.DateTimeFormat(undefined, {
    timeZone: state.timezone,
    ...(full
      ? { dateStyle: "medium", timeStyle: "medium" }
      : { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  }).format(new Date(ts * 1000));
}
function errorText(data) {
  const d = data?.detail;
  if (Array.isArray(d))
    return d
      .map((e) => `${e.loc?.slice(1).join(".") || "Request"}: ${e.msg}`)
      .join("; ");
  return typeof d === "string"
    ? d
    : "The application could not complete this request.";
}
async function bootstrap() {
  const res = await fetch("/api/session", { cache: "no-store" });
  if (!res.ok) throw new Error("Unable to start a local application session.");
  const data = await res.json();
  state.csrf = data.csrf_token;
  state.timezone = data.timezone;
  $("report-date").value ||= data.today;
  $("report-date").max = data.today;
}
async function api(path, body, retry = true) {
  const options = { cache: "no-store", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CryptoVeil-CSRF"] = state.csrf;
    options.body = JSON.stringify(body);
  }
  const res = await fetch(path, options);
  if (res.status === 401 && retry) {
    await bootstrap();
    return api(path, body, false);
  }
  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error("The application returned an unreadable response.");
  }
  if (!res.ok) throw new Error(errorText(data));
  return data;
}
let toastTimer;
function toast(message) {
  $("toast").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("toast").hidden = true), 6000);
}
function showError(error) {
  $("error-banner").textContent = error.message || String(error);
  $("error-banner").hidden = false;
}
async function action(button, work, errorTarget) {
  button.disabled = true;
  $("error-banner").hidden = true;
  try {
    await work();
  } catch (e) {
    showError(e);
    if (errorTarget) $(errorTarget).textContent = e.message;
    else toast(e.message);
  } finally {
    button.disabled = false;
  }
}
function setBanner(id, cls, title, message) {
  const target = $(id);
  target.className = `banner ${cls}`;
  target.replaceChildren(node("strong", "", title), node("p", "", message));
}
function setBadge(id, text, cls) {
  $(id).className = `badge ${cls}`;
  $(id).textContent = text;
}
function selectView(view) {
  if (!titles[view]) view = "overview";
  state.view = view;
  document
    .querySelectorAll(".view")
    .forEach((v) => (v.hidden = v.id !== `view-${view}`));
  document.querySelectorAll("[data-view]").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === view);
    if (b.dataset.view === view) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  $("breadcrumb").textContent = `Workspace / ${titles[view]}`;
  history.replaceState(null, "", `#${view}`);
  if (view === "activity") loadActivity().catch(showError);
  if (view === "reports") loadReports().catch(showError);
}
function renderIntegrity(result) {
  const count = result.expected_events || 0;
  if (!result.verified)
    setBanner(
      "evidence-banner",
      "error",
      "Evidence has been modified or is missing.",
      "Preserve the files and review the differences below. Collection is paused to avoid treating changed evidence as a new baseline.",
    );
  else if (result.collection_paused)
    setBanner(
      "evidence-banner",
      "warn",
      "The current files match, but collection is paused.",
      result.collection_error ||
        "Review the earlier storage problem before restarting the application.",
    );
  else if (!count)
    setBanner(
      "evidence-banner",
      "neutral",
      "Ready to collect evidence.",
      "There are no evidence records yet. Pair your browser extension and use the browser to begin.",
    );
  else
    setBanner(
      "evidence-banner",
      "good",
      "Your evidence matches its saved baseline.",
      "The record hashes, sequence, signed checkpoints and archive copies passed the last verification.",
    );
  $("original-root").textContent =
    result.original_root || "Original baseline unavailable";
  $("current-root").textContent =
    result.recomputed_root || "Unable to calculate current root";
  const match = Boolean(
    result.original_root && result.original_root === result.recomputed_root,
  );
  setBadge(
    "root-match",
    match
      ? result.verified
        ? "Hashes match"
        : "Hashes match · other checks failed"
      : "Hashes differ",
    match && result.verified ? "good" : "bad",
  );
  $("expected-records").textContent = number(result.expected_events);
  $("found-records").textContent = number(result.total_events);
  $("signature-status").textContent = result.signatures_verified
    ? "Verified"
    : "Not verified";
  $("evidence-checked").textContent = timeLabel(result.checked_at);
  $("archive-path").textContent = result.archive?.path || "Unavailable";
  $("public-key").textContent = result.public_key || "Unavailable";
  $("legacy-note").hidden = !result.legacy_checkpoints;
  $("violations-panel").hidden = result.verified;
  const labels = {
    EVIDENCE_MODIFIED: "A stored evidence record changed",
    EVIDENCE_MISSING_OR_ADDED: "The evidence count changed",
    TAIL_HASH_MISMATCH: "The end of the evidence log does not match",
    ARCHIVE_EVIDENCE_MISSING: "An archived evidence copy is missing",
    ARCHIVE_EVIDENCE_MODIFIED: "An archived evidence copy changed",
    MALFORMED_RECORD: "A record is unreadable",
    HEAD_SIGNATURE_FAILED: "The signed baseline is missing or invalid",
    CHECKPOINT_MODIFIED: "A checkpoint was changed",
    CHECKPOINT_SIGNATURE_FAILED: "A checkpoint signature failed",
    EVIDENCE_ROOT_MISMATCH: "The recalculated Merkle root differs",
    MERKLE_ROOT_MISMATCH: "A checkpoint Merkle root differs",
    KEY_ERROR: "The signing key needs attention",
  };
  $("violations-list").replaceChildren(
    ...(result.violations || [])
      .slice(0, 20)
      .map((v) =>
        node(
          "li",
          "",
          `${labels[v.status] || v.status.replaceAll("_", " ").toLowerCase()}${v.seq !== undefined ? ` · record #${v.seq}` : ""}${v.detail ? ` — ${v.detail}` : ""}`,
        ),
      ),
  );
  if (result.violation_count > 20)
    $("violations-list").append(
      node(
        "li",
        "",
        `${result.violation_count - 20} additional findings are included in the integrity result.`,
      ),
    );
}
function renderStatus(data) {
  state.status = data;
  state.timezone = data.timezone;
  $("app-status").textContent = "Application online";
  $("app-dot").classList.add("online");
  const integrity = data.integrity;
  const connected = data.clients.filter((c) => c.connected);
  $("metric-evidence").textContent = number(
    Math.max(data.total_events, integrity.expected_events || 0),
  );
  $("metric-browsers").textContent = number(connected.length);
  $("browser-caption").textContent = data.clients.length
    ? `${data.clients.length} paired · ${connected.length} recently seen`
    : "Pair your extension to begin";
  $("metric-alerts").textContent = number(data.recent_alert_count);
  $("metric-check").textContent = timeLabel(integrity.checked_at);
  $("check-caption").textContent =
    `Automatic checks every ${data.verification_interval_seconds} seconds`;
  $("today-label").textContent = data.today;
  $("last-updated").textContent = `Updated ${timeLabel(Date.now() / 1000)}`;
  $("data-path").textContent = data.storage_path;
  $("extension-path").textContent = data.extension_path;
  $("report-date").max = data.today;
  $("report-timezone").textContent =
    `Reporting timezone: ${data.timezone}. Today refreshes every 15 minutes when new events arrive.`;
  if (!integrity.verified || data.collection_paused) {
    setBadge("overview-badge", "Evidence needs attention", "bad");
    setBanner(
      "priority-banner",
      "error",
      "Review your evidence before continuing.",
      data.collection_paused
        ? integrity.collection_error ||
            "New collection is paused after an integrity or storage failure."
        : "One or more stored records failed verification.",
    );
  } else if (!connected.length) {
    setBadge("overview-badge", "Browser not connected", "neutral");
    setBanner(
      "priority-banner",
      "neutral",
      data.clients.length
        ? "Your paired browser is offline."
        : "Connect a browser to start collecting evidence.",
      data.clients.length
        ? "Open the paired browser and check the extension popup. Offline events stay queued until the application acknowledges them."
        : "Use “Connect browser” to pair the extension with this application.",
    );
  } else if (data.recent_alert_count) {
    setBadge("overview-badge", "Activity to review", "warn");
    setBanner(
      "priority-banner",
      "warn",
      `${data.recent_alert_count} recent observations need review.`,
      "Start with the activity below. The suggested steps help you decide whether each observation was expected.",
    );
  } else if (
    data.sensors.some((s) => s.status !== "active") ||
    !data.sensors_enabled ||
    data.delivery_errors ||
    data.report_error
  ) {
    setBadge("overview-badge", "Check collection status", "warn");
    setBanner(
      "priority-banner",
      "warn",
      "Some checks need attention.",
      "Browser evidence is connected. Review the device checks and reporting status below for gaps in coverage.",
    );
  } else {
    setBadge("overview-badge", "Evidence verified", "good");
    setBanner(
      "priority-banner",
      "good",
      "No alerts in the recent activity window.",
      "Evidence matches the saved baseline at the last check. Keep the application and paired browser running to continue collection.",
    );
  }
  const alerts = $("recent-alerts");
  alerts.replaceChildren();
  if (!data.recent_alerts.length) {
    const empty = node("div", "empty-state");
    empty.append(
      node("strong", "", "No alerts in the recent activity window."),
      node(
        "span",
        "",
        connected.length
          ? "New observations will appear here as the application receives them."
          : "Connect your browser to begin. Device observations appear when their sensors are available.",
      ),
    );
    alerts.append(empty);
  }
  for (const item of data.recent_alerts) {
    const row = node("div", "alert-row"),
      dot = node("span", `alert-dot ${item.severity}`),
      button = node("button");
    button.append(
      node("strong", "", item.summary),
      node("p", "", item.next_step),
    );
    button.addEventListener("click", () => openEvent(item));
    row.append(dot, button, node("small", "", timeLabel(item.timestamp)));
    alerts.append(row);
  }
  const sensorNames = {
    ProcessWatcher: "Process activity",
    NetworkEngine: "Network connections",
    EntropyWatcher: "File changes",
    ClipboardWatcher: "Wallet clipboard changes",
  };
  const list = $("sensor-list");
  list.replaceChildren();
  const rows = [
    {
      name: "Browser evidence",
      status: connected.length ? "active" : "unavailable",
      detail: connected.length
        ? `${connected.length} connected browser(s)`
        : "Pair or reopen your extension",
    },
    ...data.sensors.map((s) => ({ ...s, name: sensorNames[s.name] || s.name })),
  ];
  if (!data.sensors_enabled)
    rows.push({
      name: "Device checks",
      status: "disabled",
      detail: "Not enabled in this application session",
    });
  if (data.delivery_errors)
    rows.push({
      name: "Delivery diagnostics",
      status: "unavailable",
      detail: `${data.delivery_errors} subscriber or storage errors recorded`,
    });
  if (data.report_error)
    rows.push({
      name: "Daily reports",
      status: "unavailable",
      detail: data.report_error,
    });
  for (const item of rows) {
    const row = node("div", "sensor-row"),
      label = node("div", "", item.name);
    if (item.detail) label.append(node("small", "", item.detail));
    row.append(
      label,
      badge(
        item.status === "active"
          ? "Active"
          : item.status === "starting"
            ? "Starting"
            : "Unavailable",
        item.status === "active" ? "good" : "neutral",
      ),
    );
    list.append(row);
  }
  renderIntegrity(integrity);
  renderClients(data.clients);
}
function renderClients(clients) {
  const list = $("paired-browsers");
  list.replaceChildren();
  if (!clients.length)
    list.append(node("p", "fine-print", "No browsers paired yet."));
  for (const client of clients) {
    const row = node("div", "paired-row"),
      label = node("div", "", client.name);
    label.append(
      node(
        "small",
        "",
        `${client.connected ? "Connected" : "Offline"} · ${client.queued_events || 0} queued${client.dropped_events ? ` · ${client.dropped_events} events could not be queued` : ""}`,
      ),
    );
    const button = node("button", "text-button danger-text", "Unpair");
    button.setAttribute("aria-label", `Unpair ${client.name}`);
    button.addEventListener("click", () =>
      action(
        button,
        async () => {
          await api(`/api/pairing/revoke/${encodeURIComponent(client.id)}`, {});
          await refreshStatus();
          $("connect-message").textContent =
            `${client.name} has been unpaired.`;
        },
        "connect-message",
      ),
    );
    row.append(label, button);
    list.append(row);
  }
}
async function refreshStatus() {
  renderStatus(await api("/api/status"));
}
async function loadActivity() {
  const data = await api("/api/events?limit=500");
  state.events = data.events;
  renderActivity();
}
function renderActivity() {
  const search = $("activity-search").value.toLowerCase().trim(),
    filter = $("activity-filter").value;
  const shown = state.events.filter(
    (e) =>
      (filter !== "alerts" ||
        ["medium", "high", "critical"].includes(e.severity)) &&
      (filter !== "browser" || e.source === "extension") &&
      (filter !== "device" || e.source !== "extension") &&
      `${e.summary} ${e.hostname} ${e.seq}`.toLowerCase().includes(search),
  );
  const tbody = $("activity-body");
  tbody.replaceChildren();
  $("activity-empty").hidden = !!shown.length;
  for (const e of shown) {
    const row = node("tr"),
      summary = node("td");
    summary.append(
      node("strong", "", e.summary),
      node("small", "", e.hostname),
    );
    const level = node("td");
    level.append(
      badge(
        e.severity,
        ["high", "critical"].includes(e.severity)
          ? "bad"
          : e.severity === "medium"
            ? "warn"
            : "neutral",
      ),
    );
    const detail = node("td"),
      button = node("button", "text-button", `View #${e.seq}`);
    button.addEventListener("click", () => openEvent(e));
    detail.append(button);
    row.append(
      node("td", "", timeLabel(e.timestamp)),
      summary,
      node("td", "", e.source === "extension" ? "Browser" : "Device"),
      level,
      detail,
    );
    tbody.append(row);
  }
}
function openEvent(event) {
  state.selected = event;
  $("event-title").textContent = `Evidence #${event.seq}`;
  $("event-summary").textContent = event.summary;
  $("event-action").textContent = event.next_step;
  $("event-time").textContent = timeLabel(event.timestamp, true);
  $("event-hash").textContent = event.hash || "Unavailable";
  $("event-json").textContent = JSON.stringify(event.event, null, 2);
  $("proof-result").textContent = "";
  $("event-dialog").showModal();
}
async function loadReports() {
  const data = await api("/api/reports"),
    tbody = $("reports-body");
  tbody.replaceChildren();
  $("reports-empty").hidden = !!data.reports.length;
  for (const report of data.reports) {
    const row = node("tr"),
      day = node("td", "", report.date);
    if (report.generated_at)
      day.append(
        node(
          "small",
          "",
          `Saved ${new Date(report.generated_at).toLocaleTimeString()}`,
        ),
      );
    const files = node("td");
    files.append(
      badge(
        report.verified ? "Verified" : "Needs review",
        report.verified ? "good" : "bad",
      ),
    );
    if (!report.verified)
      files.append(node("small", "", report.issues.join("; ")));
    const evidence = node("td");
    evidence.append(
      badge(
        report.evidence_verified_at_generation === true
          ? "Matched"
          : report.evidence_verified_at_generation === false
            ? "Changes found"
            : "Unknown",
        report.evidence_verified_at_generation === true
          ? "good"
          : report.evidence_verified_at_generation === false
            ? "bad"
            : "neutral",
      ),
    );
    const download = node("td"),
      button = node("button", "text-button", "Download ↓");
    button.disabled = !report.verified;
    button.setAttribute("aria-label", `Download report for ${report.date}`);
    button.addEventListener("click", () =>
      action(button, () => downloadReport(report.date)),
    );
    download.append(button);
    row.append(
      day,
      node("td", "", number(report.event_count)),
      files,
      evidence,
      download,
    );
    tbody.append(row);
  }
}
async function downloadReport(date) {
  const format = $("report-format").value,
    res = await fetch(`/api/reports/${date}/download?format=${format}`, {
      cache: "no-store",
    });
  if (!res.ok) {
    let data = {};
    try {
      data = await res.json();
    } catch {}
    throw new Error(errorText(data));
  }
  const url = URL.createObjectURL(await res.blob()),
    a = node("a");
  a.href = url;
  a.download = `cryptoveil_${date}.${format}`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function poll() {
  if (state.polling) return;
  state.polling = true;
  try {
    await refreshStatus();
    if (state.view === "activity") await loadActivity();
  } catch (e) {
    $("app-status").textContent = "Application unavailable";
    $("app-dot").classList.remove("online");
    setBadge("overview-badge", "Application offline", "bad");
    setBanner(
      "priority-banner",
      "error",
      "The application is not responding.",
      "Displayed activity may be out of date. Reopen the application and check the extension queue.",
    );
    setBanner(
      "evidence-banner",
      "warn",
      "Live verification is unavailable.",
      "The hashes shown are from the last successful connection.",
    );
  } finally {
    state.polling = false;
  }
}
document
  .querySelectorAll("[data-view]")
  .forEach((button) =>
    button.addEventListener("click", () => selectView(button.dataset.view)),
  );
document
  .querySelectorAll("[data-go]")
  .forEach((button) =>
    button.addEventListener("click", () => selectView(button.dataset.go)),
  );
document
  .querySelectorAll("[data-close]")
  .forEach((button) =>
    button.addEventListener("click", () => $(button.dataset.close).close()),
  );
$("connect-button").addEventListener("click", () =>
  $("connect-dialog").showModal(),
);
$("pair-code-button").addEventListener("click", (event) =>
  action(
    event.currentTarget,
    async () => {
      const data = await api("/api/pairing/code", {});
      $("pair-code").textContent = data.code;
      $("connect-message").textContent =
        "Enter this one-use code in the extension. It expires in five minutes.";
    },
    "connect-message",
  ),
);
$("copy-extension-path").addEventListener("click", (event) =>
  action(
    event.currentTarget,
    async () => {
      await navigator.clipboard.writeText(state.status?.extension_path || "");
      $("connect-message").textContent = "Extension folder path copied.";
    },
    "connect-message",
  ),
);
$("verify-button").addEventListener("click", (event) =>
  action(event.currentTarget, async () => {
    renderIntegrity(await api("/api/forensics/verify", {}));
    await refreshStatus();
    toast("Evidence verification finished.");
  }),
);
$("refresh-activity").addEventListener("click", (event) =>
  action(event.currentTarget, loadActivity),
);
$("refresh-reports").addEventListener("click", (event) =>
  action(event.currentTarget, loadReports),
);
$("activity-search").addEventListener("input", renderActivity);
$("activity-filter").addEventListener("change", renderActivity);
$("generate-report").addEventListener("click", (event) =>
  action(event.currentTarget, async () => {
    const date = $("report-date").value;
    if (!date) throw new Error("Choose a reporting day.");
    await api(`/api/reports/generate?date=${encodeURIComponent(date)}`, {});
    await loadReports();
    toast("A new signed report snapshot has been saved.");
  }),
);
$("proof-button").addEventListener("click", (event) =>
  action(
    event.currentTarget,
    async () => {
      const proof = await api(`/api/forensics/proof/${state.selected.seq}`);
      const result = await api("/api/forensics/verify_proof", proof);
      $("proof-result").textContent = result.valid
        ? "Verified: this record belongs to the signed checkpoint, using this application’s trusted key."
        : "The proof did not pass every check. Older checkpoints may not authenticate sequence metadata.";
    },
    "proof-result",
  ),
);
$("demo-button").addEventListener("click", (event) =>
  action(event.currentTarget, async () => {
    const data = await api("/api/forensics/demo", {});
    $("demo-results").replaceChildren(
      ...data.checks.map((check, index) => {
        const row = node("div", "demo-row");
        row.append(
          node("span", "", check.scenario),
          badge(
            check.verified ? "Verified" : "Change detected",
            check.verified ? "good" : "bad",
          ),
        );
        return row;
      }),
    );
  }),
);
(async () => {
  try {
    await bootstrap();
    selectView(location.hash.slice(1) || "overview");
    await poll();
  } catch (e) {
    showError(e);
  }
  setInterval(poll, 4000);
})();
