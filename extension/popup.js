/**
 * popup.js — CryptoVeil Extension Popup Controller
 *
 * Responsibilities:
 *   1. Query background for current trust score and agent connection status
 *   2. Animate the SVG trust score ring
 *   3. Display risk factors and recent alerts from storage
 *   4. Handle protection toggles (relay to content script)
 *   5. Open dashboard link
 */

const AGENT_DASHBOARD = 'http://127.0.0.1:8765/dashboard/index.html';
const AGENT_HTTP = 'http://127.0.0.1:8765';
const STROKE_CIRCUMFERENCE = 2 * Math.PI * 52; // r=52 → ~326.7

// ── DOM refs ──────────────────────────────────────────────────────────
const $connStatus       = document.getElementById('conn-status');
const $connText         = document.getElementById('conn-text');
const $accDisplayEmail  = document.getElementById('acc-display-email');
const $accDisplayBrowser= document.getElementById('acc-display-browser');
const $btnToggleAccEdit = document.getElementById('btn-toggle-account-edit');
const $accountPicker    = document.getElementById('account-picker');
const $profileSelect    = document.getElementById('profile-select');
const $customEmailRow   = document.getElementById('custom-email-row');
const $customEmailInput = document.getElementById('custom-email-input');
const $btnSaveAccount   = document.getElementById('btn-save-account');
const $btnCancelAccount = document.getElementById('btn-cancel-account');

const $scoreRing        = document.getElementById('score-ring-fg');
const $scoreValue       = document.getElementById('score-value');
const $scoreHostname    = document.getElementById('score-hostname');
const $scoreVerdict     = document.getElementById('score-verdict');
const $reasonsSection   = document.getElementById('reasons-section');
const $reasonsList      = document.getElementById('reasons-list');
const $alertsList       = document.getElementById('alerts-list');
const $btnDashboard     = document.getElementById('btn-dashboard');

let detectedProfiles = [];

// ── Account & Email Profile Handling ─────────────────────────────────
async function loadAccountProfile() {
  const { cv_user_email = '', cv_browser_name = '', cv_profile_dir = '' } =
    await chrome.storage.local.get(['cv_user_email', 'cv_browser_name', 'cv_profile_dir']);

  if (cv_user_email) {
    $accDisplayEmail.textContent = cv_user_email;
    $accDisplayBrowser.textContent = cv_browser_name || 'Active';
  } else {
    $accDisplayEmail.textContent = 'Select your email ID';
    $accDisplayBrowser.textContent = 'Setup';
  }

  // Fetch host browser profiles from local agent
  try {
    const res = await fetch(`${AGENT_HTTP}/api/browser/profiles`);
    if (res.ok) {
      const data = await res.json();
      detectedProfiles = data.profiles || [];
      populateProfileSelect(cv_user_email);

      // Auto-set if none configured yet but profiles found with email
      if (!cv_user_email && detectedProfiles.length > 0) {
        const firstWithEmail = detectedProfiles.find(p => p.email) || detectedProfiles[0];
        if (firstWithEmail && firstWithEmail.email) {
          await saveAccount(firstWithEmail.email, firstWithEmail.browser, firstWithEmail.profile_dir);
        }
      }
    }
  } catch (_) {
    populateProfileSelect(cv_user_email);
  }
}

function populateProfileSelect(selectedEmail) {
  $profileSelect.innerHTML = '';

  if (detectedProfiles.length === 0) {
    const opt = document.createElement('option');
    opt.value = 'custom';
    opt.textContent = 'Custom Email Account…';
    $profileSelect.appendChild(opt);
    $customEmailRow.style.display = 'block';
    return;
  }

  detectedProfiles.forEach(p => {
    const opt = document.createElement('option');
    const label = p.email
      ? `[${p.browser}] ${p.display_name} (${p.email})`
      : `[${p.browser}] ${p.display_name} [${p.profile_dir}]`;
    opt.value = p.id;
    opt.dataset.email = p.email || '';
    opt.dataset.browser = p.browser;
    opt.dataset.profileDir = p.profile_dir;
    opt.textContent = label;
    if (selectedEmail && p.email === selectedEmail) {
      opt.selected = true;
    }
    $profileSelect.appendChild(opt);
  });

  const customOpt = document.createElement('option');
  customOpt.value = 'custom';
  customOpt.textContent = '➕ Enter Custom / Other Email…';
  $profileSelect.appendChild(customOpt);
}

async function saveAccount(email, browser, profileDir) {
  const cleanEmail = (email || '').trim();
  const cleanBrowser = browser || 'Browser';
  const cleanProfile = profileDir || 'Default';

  await chrome.storage.local.set({
    cv_user_email: cleanEmail,
    cv_browser_name: cleanBrowser,
    cv_profile_dir: cleanProfile,
  });

  $accDisplayEmail.textContent = cleanEmail || 'No email bound';
  $accDisplayBrowser.textContent = cleanBrowser;
  $accountPicker.style.display = 'none';

  // Notify background script
  chrome.runtime.sendMessage({
    type: 'cv_account_updated',
    user_email: cleanEmail,
    browser_name: cleanBrowser,
    profile_dir: cleanProfile,
  }).catch(() => {});
}

$btnToggleAccEdit?.addEventListener('click', () => {
  $accountPicker.style.display = $accountPicker.style.display === 'none' ? 'block' : 'none';
});

$btnCancelAccount?.addEventListener('click', () => {
  $accountPicker.style.display = 'none';
});

$profileSelect?.addEventListener('change', () => {
  if ($profileSelect.value === 'custom') {
    $customEmailRow.style.display = 'block';
    $customEmailInput.focus();
  } else {
    $customEmailRow.style.display = 'none';
  }
});

$btnSaveAccount?.addEventListener('click', async () => {
  if ($profileSelect.value === 'custom') {
    const email = $customEmailInput.value.trim();
    if (!email) {
      $customEmailInput.focus();
      return;
    }
    await saveAccount(email, 'Browser', 'Custom');
  } else {
    const selectedOpt = $profileSelect.selectedOptions[0];
    if (selectedOpt) {
      const email = selectedOpt.dataset.email || selectedOpt.textContent;
      const browser = selectedOpt.dataset.browser || 'Browser';
      const profileDir = selectedOpt.dataset.profileDir || 'Default';
      await saveAccount(email, browser, profileDir);
    }
  }
});

// ── Score ring animation ──────────────────────────────────────────────
function setScore(score, hostname, reasons) {
  // Animate ring
  const offset = STROKE_CIRCUMFERENCE - (score / 100) * STROKE_CIRCUMFERENCE;
  $scoreRing.style.strokeDashoffset = offset;

  // Color by score
  let color, verdict, verdictClass;
  if (score >= 75) {
    color = '#00ff88'; verdict = 'SAFE'; verdictClass = '';
  } else if (score >= 50) {
    color = '#ffaa00'; verdict = 'CAUTION'; verdictClass = 'warning';
  } else {
    color = '#ff4455'; verdict = 'DANGEROUS'; verdictClass = 'danger';
  }

  $scoreRing.style.stroke = color;
  $scoreValue.textContent = score;
  $scoreValue.style.color = color;
  $scoreHostname.textContent = hostname || 'Unknown';
  $scoreVerdict.textContent = verdict;
  $scoreVerdict.className = 'score-verdict ' + verdictClass;

  // Reasons
  if (reasons && reasons.length > 0) {
    $reasonsSection.style.display = 'block';
    $reasonsList.innerHTML = '';
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      $reasonsList.appendChild(li);
    });
  } else {
    $reasonsSection.style.display = 'none';
  }
}

// ── Connection status ─────────────────────────────────────────────────
function setOnline(online) {
  if (online) {
    $connStatus.classList.add('online');
    $connText.textContent = 'LIVE';
  } else {
    $connStatus.classList.remove('online');
    $connText.textContent = 'OFFLINE';
  }
}

// ── Render alerts ─────────────────────────────────────────────────────
function renderAlerts(alerts) {
  if (!alerts || alerts.length === 0) {
    $alertsList.innerHTML = '<div class="empty-alerts">No alerts this session</div>';
    return;
  }

  $alertsList.innerHTML = '';
  // Show most recent first, max 5
  alerts.slice(-5).reverse().forEach(a => {
    const item = document.createElement('div');
    let itemClass = 'alert-item';
    let sevClass = 'high';

    if (a.type === 'shadow_ai_network' || a.type === 'shadow_ai_iframe') {
      itemClass += ' ai';
      sevClass = 'medium';
    } else if (a.type === 'site_warning') {
      sevClass = 'high';
    } else {
      itemClass += ' warning';
      sevClass = 'low';
    }

    item.className = itemClass;

    const sev = document.createElement('span');
    sev.className = 'alert-sev ' + sevClass;
    sev.textContent = sevClass.toUpperCase();

    const body = document.createElement('div');
    body.className = 'alert-body';

    const text = document.createElement('div');
    text.className = 'alert-text';
    text.textContent = formatAlert(a);

    const time = document.createElement('div');
    time.className = 'alert-time';
    time.textContent = new Date(a.ts).toLocaleTimeString();

    body.append(text, time);
    item.append(sev, body);
    $alertsList.appendChild(item);
  });
}

function formatAlert(a) {
  switch (a.type) {
    case 'site_warning':
      return `Low trust: ${a.hostname} (score: ${a.score})`;
    case 'shadow_ai_network':
      return `Shadow AI: ${a.aiDomain} contacted`;
    case 'shadow_ai_iframe':
      return `AI iframe injected: ${a.aiDomain}`;
    case 'agent_threat':
      return a.description || `Threat: ${a.topic}`;
    default:
      return a.type || 'Security event';
  }
}

// ── Initialize ────────────────────────────────────────────────────────
async function init() {
  // 0. Load monitored account & email profile
  await loadAccountProfile();

  // 1. Get current tab hostname
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let hostname = '';
  try {
    hostname = new URL(tab.url).hostname;
  } catch (_) {}

  // 2. Get agent connection status
  chrome.runtime.sendMessage({ type: 'cv_get_status' }, response => {
    if (response && response.online) {
      setOnline(true);
    } else {
      setOnline(false);
    }
  });

  // 3. Get trust score for current hostname
  if (hostname) {
    chrome.runtime.sendMessage({ type: 'cv_get_score', hostname }, response => {
      if (response && response.score !== undefined) {
        setScore(response.score, hostname, response.reasons || []);
      } else {
        setScore(100, hostname, []);
      }
    });
  } else {
    $scoreHostname.textContent = 'No site loaded';
    $scoreVerdict.textContent = '—';
  }

  // 4. Load recent alerts from storage
  const { cv_alerts = [] } = await chrome.storage.local.get('cv_alerts');
  renderAlerts(cv_alerts);

  // 5. Load toggle states
  const { cv_protections = { obfuscation: true, masking: false, shadowai: true } } =
    await chrome.storage.local.get('cv_protections');
  document.getElementById('toggle-obfuscation').checked = cv_protections.obfuscation;
  document.getElementById('toggle-masking').checked = cv_protections.masking;
  document.getElementById('toggle-shadowai').checked = cv_protections.shadowai;
}

// ── Toggle handlers ───────────────────────────────────────────────────
document.getElementById('toggle-obfuscation').addEventListener('change', e => {
  saveProtections();
  broadcastToContent({ type: 'cv_toggle_obfuscation', enabled: e.target.checked });
});

document.getElementById('toggle-masking').addEventListener('change', e => {
  saveProtections();
  broadcastToContent({ type: 'cv_toggle_masking', enabled: e.target.checked });
});

document.getElementById('toggle-shadowai').addEventListener('change', e => {
  saveProtections();
});

async function saveProtections() {
  const protections = {
    obfuscation: document.getElementById('toggle-obfuscation').checked,
    masking: document.getElementById('toggle-masking').checked,
    shadowai: document.getElementById('toggle-shadowai').checked,
  };
  await chrome.storage.local.set({ cv_protections: protections });
}

async function broadcastToContent(msg) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    chrome.tabs.sendMessage(tab.id, msg).catch(() => {});
  }
}

// ── Dashboard button ──────────────────────────────────────────────────
$btnDashboard.addEventListener('click', () => {
  chrome.tabs.create({ url: AGENT_DASHBOARD });
});

// ── Listen for real-time updates while popup is open ──────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'cv_score_update') {
    setScore(msg.score, msg.hostname, msg.reasons || []);
  }
  if (msg.type === 'cv_alert_added') {
    chrome.storage.local.get('cv_alerts').then(({ cv_alerts = [] }) => {
      renderAlerts(cv_alerts);
    });
  }
  if (msg.type === 'cv_connection_change') {
    setOnline(msg.online);
  }
});

// ── Boot ──────────────────────────────────────────────────────────────
init();
