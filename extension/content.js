/* Visual masking and observation only. Never override .value or change submitted data. */
(() => {
  "use strict";
  const sensitiveName =
    /password|passwd|credit.?card|cvv|cvc|ssn|secret|token/i;
  const seen = new WeakSet(),
    signals = new WeakMap(),
    originalStyles = new WeakMap();
  const signalTimes = new Map();
  let masked = false,
    banner = null;
  const isSensitive = (element) =>
    (element instanceof HTMLInputElement ||
      element instanceof HTMLTextAreaElement) &&
    (["password", "email", "tel"].includes(element.type) ||
      sensitiveName.test(
        `${element.name} ${element.id} ${element.autocomplete}`,
      ));
  const send = (payload) =>
    chrome.runtime
      .sendMessage({ type: "cv_dom_event", payload })
      .catch(() => {});
  function styleField(element, active) {
    if (!isSensitive(element)) return;
    if (active) {
      if (!originalStyles.has(element))
        originalStyles.set(element, {
          value: element.style.getPropertyValue("-webkit-text-security"),
          priority: element.style.getPropertyPriority("-webkit-text-security"),
        });
      element.style.setProperty("-webkit-text-security", "disc", "important");
    } else if (originalStyles.has(element)) {
      const old = originalStyles.get(element);
      if (old.value)
        element.style.setProperty(
          "-webkit-text-security",
          old.value,
          old.priority,
        );
      else element.style.removeProperty("-webkit-text-security");
      originalStyles.delete(element);
    }
  }
  function setMasking(active, report = true) {
    masked = Boolean(active);
    document
      .querySelectorAll("input,textarea")
      .forEach((el) => styleField(el, masked));
    if (report)
      send({ type: masked ? "masking_activated" : "masking_deactivated" });
  }
  function inspect(element) {
    if (isSensitive(element) && !seen.has(element)) {
      seen.add(element);
      styleField(element, masked);
      element.addEventListener(
        "focus",
        () =>
          send({
            type: "sensitive_field_used",
            field_type: element.type || "textarea",
          }),
        { once: true },
      );
    }
    const signal = CryptoVeilSignals.classify(
      element.tagName,
      element.getAttribute?.("src"),
      element.getAttribute?.("data-ai-provider"),
      location.href,
    );
    if (signal) {
      const key = JSON.stringify(signal),
        now = Date.now();
      if (
        signals.get(element) !== key &&
        now - (signalTimes.get(key) || 0) > 60000
      ) {
        signals.set(element, key);
        signalTimes.set(key, now);
        if (signalTimes.size > 100)
          signalTimes.delete(signalTimes.keys().next().value);
        send(signal);
      }
    }
  }
  function inspectTree(root) {
    if (root.nodeType === 1) inspect(root);
    root
      .querySelectorAll?.("input,textarea,iframe,script,[data-ai-provider]")
      .forEach(inspect);
  }
  const observer = new MutationObserver((changes) => {
    for (const change of changes) {
      if (change.type === "attributes") inspect(change.target);
      else for (const added of change.addedNodes) inspectTree(added);
    }
  });
  observer.observe(document, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["type", "src", "data-ai-provider"],
  });
  inspectTree(document);
  function warning(reasons) {
    if (banner || !document.documentElement) return;
    banner = document.createElement("div");
    const shadow = banner.attachShadow({ mode: "closed" });
    const panel = document.createElement("div");
    panel.setAttribute("role", "alert");
    panel.style.cssText =
      "position:fixed;top:12px;right:12px;max-width:350px;z-index:2147483647;background:#fff6e5;color:#513c16;border:1px solid #d8b979;border-radius:10px;padding:16px;font:13px/1.5 system-ui;box-shadow:0 4px 20px #0002";
    const title = document.createElement("strong");
    title.textContent = "CryptoVeil: check this website";
    const message = document.createElement("p");
    message.textContent =
      reasons.join(" ") ||
      "Review the website address before entering sensitive information.";
    const close = document.createElement("button");
    close.textContent = "Dismiss";
    close.style.cssText =
      "border:1px solid #c7b994;background:white;border-radius:5px;padding:5px 12px;color:#513c16;cursor:pointer";
    close.addEventListener("click", () => banner.remove());
    panel.append(title, message, close);
    shadow.append(panel);
    document.documentElement.append(banner);
  }
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "cv_masking") setMasking(msg.active);
    if (msg.type === "cv_trust_update" && msg.score < 65)
      warning(msg.reasons || []);
  });
  chrome.runtime
    .sendMessage({ type: "cv_get_page_settings" })
    .then((settings) => {
      if (!settings || settings.error) return;
      setMasking(settings.masking, false);
      if (settings.score < 65) warning(settings.reasons || []);
    })
    .catch(() => {});
})();
