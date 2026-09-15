"use strict";
const $ = (id) => document.getElementById(id);
async function message(payload) {
  const result = await chrome.runtime.sendMessage(payload);
  if (result?.error) throw new Error(result.error);
  return result;
}
async function refresh() {
  const data = await message({ type: "cv_status" }),
    recent = Date.now() - (data.status.updated_at || 0) < 90000;
  $("pair-form").hidden = data.paired;
  $("paired-panel").hidden = !data.paired;
  $("account-panel").hidden = !data.paired;
  const profile = data.profile_context || {};
  const sources = {
    browser_profile: "Reported by browser profile",
    user_provided: "Manual label · not verified sign-in",
    unavailable: "Profile email unavailable · you can enter a manual label",
    not_shared: "Account email not shared",
  };
  $("account-status").textContent =
    `${profile.browser_family || "Browser"} · ${profile.account_email || "No email attached"} · ${sources[profile.account_source] || sources.not_shared}`;
  $("mask-toggle").checked = data.masking;
  $("app-url").value = data.app_url;
  const online = data.paired && recent && data.status.online;
  $("connection").textContent = !data.paired
    ? "Pair this extension to start delivery"
    : data.status.collection_paused
      ? "Collection paused — review evidence in the app"
      : online
        ? "Connected · evidence is acknowledged after saving"
        : "Application offline · evidence stays queued";
  $("connection").classList.toggle(
    "error",
    !online || data.status.collection_paused,
  );
  $("browser-label").textContent = data.name || "Your browser";
  $("queued").textContent = data.queue_count;
  $("saved").textContent = data.last_receipt
    ? `#${data.last_receipt.seq}`
    : "—";
  $("delivery-note").textContent = data.dropped_total
    ? `${data.dropped_total} observations could not be queued because the offline queue filled. A collection-gap event will be sent when delivery resumes.`
    : data.status.last_error ||
      "Queued evidence is removed only after the app confirms durable storage.";
  if (data.legacy_count)
    $("delivery-note").textContent +=
      ` ${data.legacy_count} legacy messages are retained in extension storage for review.`;
}
async function run(button, work) {
  button.disabled = true;
  $("message").textContent = "";
  try {
    await work();
    await refresh();
  } catch (e) {
    $("message").textContent = e.message;
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
$("retry-button").addEventListener("click", (event) =>
  run(event.currentTarget, () => message({ type: "cv_retry" })),
);
$("profile-account").addEventListener("click", (event) => {
  // Request directly during the user gesture, before any asynchronous work.
  const permission = chrome.permissions.request({
    permissions: ["identity", "identity.email"],
  });
  run(event.currentTarget, async () => {
    if (!(await permission))
      throw new Error(
        "Email permission was not granted. You can use a manual label.",
      );
    await message({ type: "cv_identity_set", mode: "profile" });
  });
});
$("account-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run($("manual-account"), async () => {
    await message({
      type: "cv_identity_set",
      mode: "manual",
      email: $("account-email").value,
    });
    $("account-email").value = "";
  });
});
$("clear-account").addEventListener("click", (event) =>
  run(event.currentTarget, async () => {
    await message({ type: "cv_identity_set", mode: "none" });
    await chrome.permissions.remove({
      permissions: ["identity", "identity.email"],
    });
  }),
);
$("open-app").addEventListener("click", (event) =>
  run(event.currentTarget, () => message({ type: "cv_open_app" })),
);
$("mask-toggle").addEventListener("change", (event) =>
  run(event.currentTarget, () =>
    message({ type: "cv_masking", active: event.currentTarget.checked }),
  ),
);
(async () => {
  try {
    await refresh();
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (tab?.url && /^https?:/.test(tab.url)) {
      const host = new URL(tab.url).hostname;
      $("site-name").textContent = host;
      const result = await message({
        type: "cv_get_page_settings",
        url: tab.url,
      });
      $("site-score").textContent =
        `Local risk estimate: ${result.score}/100 · ${result.score < 65 ? "Review this address" : "Few local risk signals"}`;
      $("site-reasons").replaceChildren(
        ...result.reasons.map((text) => {
          const li = document.createElement("li");
          li.textContent = text;
          return li;
        }),
      );
    }
  } catch (e) {
    $("message").textContent = e.message;
  }
})();
setInterval(() => refresh().catch(() => {}), 3000);
