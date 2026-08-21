/*
 * CYBERSURAKSHAA browser extension — service worker.
 *
 * The whole point of this extension is the gap it closes: by the time a scam
 * message reaches an analyst console, the citizen has usually already paid.
 * Checking has to happen where the message is being read.
 *
 * Two constraints shape the code below.
 *
 * 1. Nothing is sent anywhere until the user asks. There is no passive page
 *    scanning, no keystroke observation and no background telemetry — an
 *    extension that quietly ships page contents to a server is spyware
 *    regardless of the server's intentions, and this one holds
 *    <all_urls> access.
 *
 * 2. The API key lives in chrome.storage and is entered by the user. It is
 *    never hardcoded here, because everything in an extension bundle is
 *    readable by anyone who installs it.
 */

const DEFAULT_ENDPOINT = 'http://localhost:5000';

// ── Settings ────────────────────────────────────────────────────────────
async function getSettings() {
  const stored = await chrome.storage.sync.get(['endpoint', 'apiKey']);
  return {
    endpoint: (stored.endpoint || DEFAULT_ENDPOINT).replace(/\/+$/, ''),
    apiKey: stored.apiKey || '',
  };
}

// ── Right-click entry point ─────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'cybersurakshaa-check',
    title: 'Check this text for scam patterns',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'cybersurakshaa-check' || !info.selectionText) return;
  const result = await checkText(info.selectionText);
  // The content script renders the panel in the page. If it is not injected
  // (chrome:// pages, the web store), fall back to a system notification so
  // the user still gets the answer rather than silence.
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'CS_RESULT', result });
  } catch (e) {
    notify(result);
  }
});

// ── Popup and content-script requests ───────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'CS_CHECK') {
    checkText(msg.text).then(sendResponse);
    return true;   // keep the message channel open for the async reply
  }
  if (msg.type === 'CS_SETTINGS') {
    getSettings().then(sendResponse);
    return true;
  }
});

// ── API call ────────────────────────────────────────────────────────────
async function checkText(text) {
  const { endpoint, apiKey } = await getSettings();

  if (!apiKey) {
    return {
      error: 'No API key configured. Open the extension options and paste the '
           + 'key issued by your CYBERSURAKSHAA deployment.',
    };
  }

  try {
    const resp = await fetch(endpoint + '/api/v1/check', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey,
      },
      body: JSON.stringify({ text: text.slice(0, 8000) }),
    });

    if (resp.status === 401) {
      return { error: 'The API key was rejected. Check it in the extension options.' };
    }
    if (resp.status === 429) {
      return { error: 'Rate limit reached. Try again shortly.' };
    }
    if (!resp.ok) {
      return { error: 'The service returned an error (' + resp.status + ').' };
    }
    return await resp.json();
  } catch (e) {
    // A failed check must never read as "safe". Saying the check did not
    // happen is the only honest outcome.
    return {
      error: 'Could not reach CYBERSURAKSHAA at ' + endpoint + '. The message '
           + 'was NOT checked — treat it with the same caution as before.',
    };
  }
}

function notify(result) {
  const title = result.error
    ? 'Check failed'
    : ({ LIKELY_SCAM: 'Likely scam', UNSURE: 'Cannot tell', SAFE: 'No scam patterns found' }[result.band]
       || 'Result');
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icon128.png',
    title: 'CYBERSURAKSHAA — ' + title,
    message: result.error || (result.advice && result.advice[0]) || '',
  });
}
