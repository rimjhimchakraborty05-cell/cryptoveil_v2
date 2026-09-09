/**
 * background.js — CryptoVeil MV3 Service Worker
 *
 * Responsibilities:
 *   1. Two-pass domain trust scoring (local heuristics + companion app network pass)
 *   2. Persistent WebSocket bridge to the companion agent (with local queue for SW restarts)
 *   3. Shadow AI Monitor: webRequest interception of known AI API endpoints
 *   4. Forward all browser events to the agent as BrowserTelemetryEvent
 *   5. Receive agent pushes (trust updates, MITRE alerts, threat notifications)
 *   6. Badge management — show threat count on extension icon
 *   7. Alert storage — persist recent alerts for popup display
 */

const AGENT_HTTP = "http://127.0.0.1:8765";
const AGENT_WS   = "ws://127.0.0.1:8765/ws/extension";

// ── Known brand list for typosquat detection ──────────────────────────
const KNOWN_BRANDS = [
  "google.com","paypal.com","microsoft.com","apple.com","amazon.com",
  "facebook.com","bankofamerica.com","chase.com","wellsfargo.com",
  "netflix.com","instagram.com","linkedin.com","github.com","dropbox.com",
  "twitter.com","youtube.com","spotify.com",
];

// ── Known AI API domains ──────────────────────────────────────────────
const AI_API_HOSTS = [
  "api.openai.com","api.anthropic.com","generativelanguage.googleapis.com",
  "api.perplexity.ai","api.cohere.ai","api.mistral.ai",
  "copilot.microsoft.com","api.together.xyz","openrouter.ai",
];

// ── Utility ───────────────────────────────────────────────────────────
function levenshtein(a, b) {
  const dp = Array.from({length: a.length+1}, () => new Array(b.length+1).fill(0));
  for (let i=0;i<=a.length;i++) dp[i][0]=i;
  for (let j=0;j<=b.length;j++) dp[0][j]=j;
  for (let i=1;i<=a.length;i++)
    for (let j=1;j<=b.length;j++) {
      const c = a[i-1]===b[j-1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+c);
    }
  return dp[a.length][b.length];
}

function shannonEntropy(s) {
  const f={};
  for (const c of s) f[c]=(f[c]||0)+1;
  let e=0; const n=s.length;
  for (const c in f) { const p=f[c]/n; e-=p*Math.log2(p); }
  return e;
}

function localScore(hostname) {
  let score=100; const reasons=[];
  // Typosquat check
  for (const brand of KNOWN_BRANDS) {
    const d = levenshtein(hostname, brand);
    if (d > 0 && d <= 2) {
      score -= 40;
      reasons.push(`Hostname is ${d} edit(s) from "${brand}" — possible typosquat`);
      break;
    }
  }
  // Entropy check (DGA/phishing-kit signature)
  const ent = shannonEntropy(hostname.replace(/\./g,''));
  if (ent > 3.8) { score-=20; reasons.push(`High hostname entropy (${ent.toFixed(2)}) — DGA pattern`); }
  return { score: Math.max(0, score), reasons };
}

function isAiHost(hostname) {
  const h = hostname.toLowerCase();
  return AI_API_HOSTS.find(d => h === d || h.endsWith('.'+d)) || null;
}

// ── Account & Identity State ──────────────────────────────────────────
let currentAccount = { user_email: '', browser_name: '', profile_dir: '' };

async function loadAccount() {
  const { cv_user_email = '', cv_browser_name = '', cv_profile_dir = '' } =
    await chrome.storage.local.get(['cv_user_email', 'cv_browser_name', 'cv_profile_dir']);
  currentAccount = { user_email: cv_user_email, browser_name: cv_browser_name, profile_dir: cv_profile_dir };
}
loadAccount();

// ── Event queue (survives SW suspension) ─────────────────────────────
async function enqueue(event) {
  const {cv_queue=[]} = await chrome.storage.local.get('cv_queue');
  cv_queue.push({...event, ts: Date.now(), user_email: currentAccount.user_email, browser_name: currentAccount.browser_name});
  if (cv_queue.length > 300) cv_queue.splice(0, cv_queue.length-300);
  await chrome.storage.local.set({cv_queue});
}

async function flushQueue(ws) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const {cv_queue=[]} = await chrome.storage.local.get('cv_queue');
  if (!cv_queue.length) return;
  for (const ev of cv_queue) {
    try { ws.send(JSON.stringify(ev)); } catch(_) {}
  }
  await chrome.storage.local.set({cv_queue:[]});
}

// ── Alert storage ─────────────────────────────────────────────────────
async function storeAlert(alert) {
  const {cv_alerts=[]} = await chrome.storage.local.get('cv_alerts');
  cv_alerts.push({...alert, ts: Date.now()});
  // Keep only last 50 alerts
  if (cv_alerts.length > 50) cv_alerts.splice(0, cv_alerts.length - 50);
  await chrome.storage.local.set({cv_alerts});

  // Notify popup if open
  chrome.runtime.sendMessage({type: 'cv_alert_added'}).catch(()=>{});
}

// ── Badge management ──────────────────────────────────────────────────
let threatBadgeCount = 0;

function updateBadge() {
  if (threatBadgeCount > 0) {
    chrome.action.setBadgeText({text: String(threatBadgeCount)});
    chrome.action.setBadgeBackgroundColor({color: '#ff4455'});
  } else {
    chrome.action.setBadgeText({text: ''});
  }
}

// Reset badge on startup
chrome.action.setBadgeText({text: ''});

// ── WebSocket bridge (bidirectional) ──────────────────────────────────
let ws=null, reconnDelay=1500, _online=false;

function setOnline(online) {
  if (_online===online) return;
  _online=online;
  chrome.storage.local.set({cv_agent_online:{online, ts:Date.now()}});
  // Notify popup about connection change
  chrome.runtime.sendMessage({type: 'cv_connection_change', online}).catch(()=>{});
}

function connectBridge() {
  try {
    ws = new WebSocket(AGENT_WS);

    ws.onopen = async ()=>{
      reconnDelay=1500;
      setOnline(true);
      await loadAccount();
      try {
        ws.send(JSON.stringify({
          type: 'extension_hello',
          user_email: currentAccount.user_email,
          browser_name: currentAccount.browser_name,
          profile_dir: currentAccount.profile_dir,
        }));
      } catch (_) {}
      flushQueue(ws);
    };

    // ── Receive agent pushes ──────────────────────────────────────────
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleAgentPush(msg);
      } catch(_) {}
    };

    ws.onclose= ()=>{
      ws=null;
      setOnline(false);
      setTimeout(connectBridge,reconnDelay);
      reconnDelay=Math.min(reconnDelay*2,30000);
    };

    ws.onerror= ()=>{ try{ws.close();}catch(_){} };
  } catch(_) {
    setOnline(false);
    setTimeout(connectBridge, reconnDelay);
    reconnDelay = Math.min(reconnDelay*2, 30000);
  }
}
connectBridge();

// ── Handle agent push messages ────────────────────────────────────────
async function handleAgentPush(msg) {
  const pushType = msg.push_type || msg.type;

  switch (pushType) {
    case 'trust_update': {
      // Agent has processed a site and sends back enriched trust info
      const hostname = msg.hostname;
      const score = msg.score ?? msg.trust_score;
      const reasons = msg.reasons || [];

      if (hostname && score !== undefined) {
        // Update cache
        scoreCache.set(hostname, {score, reasons, ts: Date.now(), network: true});

        // Push to content script on the active tab
        const tabs = await chrome.tabs.query({active: true, currentWindow: true});
        for (const tab of tabs) {
          try {
            const tabHost = new URL(tab.url).hostname;
            if (tabHost === hostname) {
              chrome.tabs.sendMessage(tab.id, {
                type: 'cv_trust_update',
                score: score,
                reasons: reasons,
              }).catch(()=>{});
            }
          } catch(_) {}
        }

        // Notify popup
        chrome.runtime.sendMessage({
          type: 'cv_score_update',
          hostname, score, reasons
        }).catch(()=>{});
      }
      break;
    }

    case 'threat_alert': {
      // Agent detected a threat (MITRE, C2, DGA, etc.)
      threatBadgeCount++;
      updateBadge();

      await storeAlert({
        type: 'agent_threat',
        topic: msg.topic || 'unknown',
        description: msg.description || msg.detail || 'Threat detected by agent',
        severity: msg.severity || 'high',
      });

      // Chrome notification for critical threats
      if (msg.severity === 'critical' || msg.severity === 'high') {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: 'CryptoVeil — Threat Detected',
          message: msg.description || `${msg.topic}: Security threat detected`,
          priority: 2,
        });
      }
      break;
    }

    case 'extension_command': {
      // Agent can request the extension to take actions
      if (msg.action === 'enable_masking') {
        const tabs = await chrome.tabs.query({active: true, currentWindow: true});
        for (const tab of tabs) {
          chrome.tabs.sendMessage(tab.id, {
            type: 'cv_screen_share',
            active: true,
          }).catch(()=>{});
        }
      }
      break;
    }
  }
}

async function sendEvent(ev) {
  const payload = {
    ...ev,
    ts: Date.now(),
    user_email: currentAccount.user_email,
    browser_name: currentAccount.browser_name,
    profile_dir: currentAccount.profile_dir,
  };
  if (ws && ws.readyState===WebSocket.OPEN) {
    try { ws.send(JSON.stringify(payload)); return; } catch(_) {}
  }
  await enqueue(payload);
}

// ── Trust scoring on navigation ───────────────────────────────────────
const scoreCache = new Map();

chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0) return;
  let hostname;
  try { hostname = new URL(details.url).hostname; } catch(_) { return; }
  if (!hostname) return;

  const local = localScore(hostname);
  scoreCache.set(hostname, {...local, ts: Date.now(), network: false});

  // Notify popup of new score
  chrome.runtime.sendMessage({
    type: 'cv_score_update',
    hostname, score: local.score, reasons: local.reasons
  }).catch(()=>{});

  if (local.score < 50) {
    await storeAlert({
      type: 'site_warning',
      hostname,
      score: local.score,
      reasons: local.reasons,
    });
    await sendEvent({type:'site_warning', hostname, score:local.score, reasons:local.reasons});
    threatBadgeCount++;
    updateBadge();
  }

  // Async network pass — send to agent with bound account info
  try {
    await fetch(`${AGENT_HTTP}/api/browser/telemetry`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        type:'site_visit',
        hostname,
        score:local.score,
        user_email: currentAccount.user_email,
        browser_name: currentAccount.browser_name,
      }),
    });
  } catch(_) {}
});

// ── Shadow AI Monitor: webRequest pass ───────────────────────────────
chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.tabId < 0) return;
    let h;
    try { h = new URL(details.url).hostname; } catch(_) { return; }
    const matched = isAiHost(h);
    if (matched) {
      const alert = {type:'shadow_ai_network', aiDomain:matched, url:details.url, tabId:details.tabId};
      sendEvent(alert);
      storeAlert(alert);
      threatBadgeCount++;
      updateBadge();
    }
  },
  { urls: ['<all_urls>'] }
);

// ── Message handler ───────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === 'cv_account_updated') {
      currentAccount = {
        user_email: msg.user_email || '',
        browser_name: msg.browser_name || '',
        profile_dir: msg.profile_dir || '',
      };
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({
            type: 'extension_account_sync',
            user_email: currentAccount.user_email,
            browser_name: currentAccount.browser_name,
            profile_dir: currentAccount.profile_dir,
          }));
        } catch (_) {}
      }
      sendResponse({ok:true});
    } else if (msg.type === 'cv_dom_event') {
      await sendEvent({...msg.payload, tabId: sender.tab?.id});
      sendResponse({ok:true});
    } else if (msg.type === 'cv_get_score') {
      sendResponse(scoreCache.get(msg.hostname) || null);
    } else if (msg.type === 'cv_get_status') {
      const {cv_agent_online} = await chrome.storage.local.get('cv_agent_online');
      sendResponse(cv_agent_online || {online:false});
    }
  })();
  return true;
});

// ── Periodic badge reset (every 30 min) ──────────────────────────────
if (typeof chrome !== 'undefined' && chrome.alarms) {
  try {
    chrome.alarms.create('cv_badge_reset', { periodInMinutes: 30 });
    chrome.alarms.onAlarm.addListener(alarm => {
      if (alarm.name === 'cv_badge_reset') {
        threatBadgeCount = 0;
        updateBadge();
      }
    });
  } catch (_) {}
}
