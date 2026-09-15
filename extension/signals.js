/* Classify observable DOM metadata only; never read field values or page text. */
globalThis.CryptoVeilSignals = Object.freeze({
  classify(tag, src, provider, pageURL) {
    const domains = [
      "chatgpt.com",
      "openai.com",
      "claude.ai",
      "anthropic.com",
      "perplexity.ai",
      "sider.ai",
      "merlin.foyer.work",
      "monica.im",
      "harpa.ai",
    ];
    if (["IFRAME", "SCRIPT"].includes(tag) && src) {
      try {
        const url = new URL(src, pageURL);
        if (
          ["https:", "http:"].includes(url.protocol) &&
          domains.some(
            (d) => url.hostname === d || url.hostname.endsWith(`.${d}`),
          )
        ) {
          return {
            type: tag === "IFRAME" ? "shadow_ai_iframe" : "shadow_ai_dom",
            ai_domain: url.hostname,
            ...(tag === "SCRIPT" ? { dom_signal: "ai_script" } : {}),
          };
        }
      } catch {}
    }
    const declaredProviders = {
      openai: "openai.com",
      anthropic: "anthropic.com",
      perplexity: "perplexity.ai",
    };
    const key = String(provider || "").toLowerCase();
    const domain = Object.hasOwn(declaredProviders, key)
      ? declaredProviders[key]
      : undefined;
    return domain
      ? { type: "shadow_ai_dom", ai_domain: domain, dom_signal: "ai_component" }
      : null;
  },
});
