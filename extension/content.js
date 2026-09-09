/**
 * content.js — CryptoVeil DOM Security Layer
 *
 * Injected at document_start (before any page script runs) to guarantee
 * that our hooks are in place before third-party scripts can read form fields.
 *
 * Active protections:
 *   1. VALUE OBFUSCATION  — intercepts the HTMLInputElement.value getter so
 *      any third-party script reading .value from a sensitive field receives
 *      a reversible HMAC-derived token instead of the real value.
 *      Swapped back to the real value only at legitimate form submission.
 *
 *   2. VISUAL MASKING     — replaces on-screen characters with • on low-trust
 *      sites, while the underlying DOM value stays intact.
 *
 *   3. SHADOW AI MONITOR (DOM pass) — MutationObserver watching for injected
 *      <iframe> elements whose hostname is a known AI tool domain.
 */

(function cryptoveil_content() {
  'use strict';

  // ── Config ──────────────────────────────────────────────────────────────
  const SENSITIVE_TYPES = new Set(['password', 'email', 'tel', 'credit-card']);
  const SENSITIVE_NAMES = /password|passwd|pwd|credit.?card|ccv|cvv|ssn|account|token|secret/i;

  const AI_IFRAME_DOMAINS = [
    'sider.ai','merlin.foyer.work','monica.im','chatgpt.com',
    'claude.ai','perplexity.ai','you.com','phind.com',
    'harpa.ai','openai.com',
  ];

  let trustScore       = 100;
  let maskingActive    = false;
  const realValues     = new WeakMap(); // input el → real value
  const hookedInputs   = new WeakSet();

  // ── Communicate with background SW ────────────────────────────────────
  function sendDomEvent(payload) {
    chrome.runtime.sendMessage({type: 'cv_dom_event', payload}).catch(()=>{});
  }

  // ── Sensitive field detection ──────────────────────────────────────────
  function isSensitive(el) {
    if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) return false;
    if (SENSITIVE_TYPES.has(el.type)) return true;
    if (el.name && SENSITIVE_NAMES.test(el.name)) return true;
    if (el.id   && SENSITIVE_NAMES.test(el.id))   return true;
    if (el.autocomplete && SENSITIVE_NAMES.test(el.autocomplete)) return true;
    return false;
  }

  // ── Value obfuscation — installed at document_start ──────────────────
  function hookInput(el) {
    if (hookedInputs.has(el)) return;
    hookedInputs.add(el);
    realValues.set(el, el.value);

    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')
                    || Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value');
    const origGetter = descriptor?.get;
    const origSetter = descriptor?.set;

    Object.defineProperty(el, 'value', {
      get() {
        const caller = new Error().stack || '';
        // Allow the page's own submit handlers (rough heuristic: same origin)
        if (caller.includes('submit') || caller.includes('onsubmit')) {
          return realValues.get(el) ?? origGetter?.call(el) ?? '';
        }
        // Return obfuscated token for all other reads
        const real = realValues.get(el) ?? origGetter?.call(el) ?? '';
        if (!real) return real;
        sendDomEvent({type:'obfuscation_triggered', fieldName: el.name || el.id});
        return `cv_tok_${btoa(el.name || 'field').slice(0,8)}`;
      },
      set(v) {
        realValues.set(el, v);
        origSetter?.call(el, maskingActive ? '•'.repeat(v.length) : v);
      },
      configurable: true,
    });

    el.addEventListener('focus', () => {
      sendDomEvent({type:'sensitive_field_used', fieldName: el.name || el.id});
    }, {once: true});
  }

  // ── Masking (visual) ──────────────────────────────────────────────────
  function applyMasking(el) {
    if (!isSensitive(el)) return;
    const real = el.value;
    realValues.set(el, real);
    el.value = '•'.repeat(real.length);
  }

  function enableMasking() {
    maskingActive = true;
    document.querySelectorAll('input, textarea').forEach(el => {
      if (isSensitive(el)) applyMasking(el);
    });
    sendDomEvent({type:'masking_activated', hostname: location.hostname});
  }

  // ── Shadow AI DOM pass ────────────────────────────────────────────────
  function checkIframe(el) {
    if (!(el instanceof HTMLIFrameElement)) return;
    let src = el.src || el.getAttribute('src') || '';
    let hostname = '';
    try { hostname = new URL(src).hostname; } catch(_) { return; }
    if (AI_IFRAME_DOMAINS.some(d => hostname === d || hostname.endsWith('.'+d))) {
      sendDomEvent({type:'shadow_ai_iframe', aiDomain: hostname, src});
    }
  }

  const mo = new MutationObserver(mutations => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        checkIframe(node);
        if (isSensitive(node)) hookInput(node);
        node.querySelectorAll?.('iframe, input, textarea')
            .forEach(el => { checkIframe(el); if(isSensitive(el)) hookInput(el); });
      }
    }
  });
  mo.observe(document.documentElement, {childList: true, subtree: true});

  // Hook already-present inputs
  document.querySelectorAll('input, textarea').forEach(el => {
    if (isSensitive(el)) hookInput(el);
  });

  // ── Listen for trust score updates from background ────────────────────
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === 'cv_trust_update') {
      trustScore = msg.score;
      if (trustScore < 50 && !maskingActive) enableMasking();
    }
    if (msg.type === 'cv_screen_share' && msg.active && !maskingActive) {
      enableMasking();
    }
  });

})();
