/*
 * Popup controller.
 *
 * As in content.js, results are written with textContent rather than
 * innerHTML. The strings here originate from a server response, and a
 * compromised or spoofed endpoint should not be able to run script inside the
 * extension's own origin — which is considerably more privileged than a page.
 */

const BAND_COLOUR = {
  LIKELY_SCAM: '#ef4444',
  UNSURE: '#f59e0b',
  SAFE: '#10b981',
};
const BAND_LABEL = {
  LIKELY_SCAM: 'Likely scam',
  UNSURE: 'Cannot tell from the text alone',
  SAFE: 'No scam patterns found',
};

const $ = (id) => document.getElementById(id);

function show(view) {
  $('check-view').style.display = view === 'check' ? 'block' : 'none';
  $('settings-view').style.display = view === 'settings' ? 'block' : 'none';
}

function render(result) {
  const box = $('result');
  box.textContent = '';

  if (result.error) {
    const p = document.createElement('p');
    p.style.color = '#b91c1c';
    p.textContent = result.error;
    box.appendChild(p);
    return;
  }

  const band = document.createElement('div');
  band.className = 'band';
  band.style.background = BAND_COLOUR[result.band] || '#64748b';
  band.textContent = BAND_LABEL[result.band] || result.band;
  box.appendChild(band);

  const list = document.createElement('ul');
  (result.advice || []).forEach((line) => {
    const li = document.createElement('li');
    li.textContent = line;
    list.appendChild(li);
  });
  box.appendChild(list);

  if (result.indicators && result.indicators.length) {
    const h = document.createElement('p');
    h.className = 'note';
    h.textContent = 'Identifiers found: '
      + result.indicators.map((i) => i.value).join(', ');
    box.appendChild(h);
  }

  const note = document.createElement('p');
  note.className = 'note';
  note.textContent = result.disclaimer || '';
  box.appendChild(note);
}

document.addEventListener('DOMContentLoaded', async () => {
  const settings = await chrome.runtime.sendMessage({ type: 'CS_SETTINGS' });
  $('endpoint').value = settings.endpoint || '';
  $('key').value = settings.apiKey || '';

  // Prompt for configuration on first run rather than failing silently on
  // the first check.
  if (!settings.apiKey) show('settings');

  $('go').addEventListener('click', async () => {
    const text = $('text').value.trim();
    if (!text) return;
    $('go').disabled = true;
    $('result').textContent = 'Checking…';
    const result = await chrome.runtime.sendMessage({ type: 'CS_CHECK', text });
    $('go').disabled = false;
    render(result);
  });

  $('show-settings').addEventListener('click', () => show('settings'));
  $('back').addEventListener('click', () => show('check'));

  $('save').addEventListener('click', async () => {
    await chrome.storage.sync.set({
      endpoint: $('endpoint').value.trim(),
      apiKey: $('key').value.trim(),
    });
    show('check');
    $('result').textContent = 'Settings saved.';
  });
});
