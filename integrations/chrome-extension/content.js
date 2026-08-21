/*
 * In-page result panel.
 *
 * Renders where the user is already looking, rather than in a popup they have
 * to go and open. Everything is built with DOM APIs and textContent — never
 * innerHTML — because the strings being displayed include text the *page*
 * supplied, and injecting that as markup into the page would hand any site a
 * scripting primitive through the extension.
 */

(function () {
  'use strict';

  const PANEL_ID = 'cybersurakshaa-panel';

  const BAND = {
    LIKELY_SCAM: { label: 'Likely scam', colour: '#ef4444', icon: '⚠' },
    UNSURE: { label: 'Cannot tell', colour: '#f59e0b', icon: '?' },
    SAFE: { label: 'No scam patterns found', colour: '#10b981', icon: '✓' },
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function removePanel() {
    const existing = document.getElementById(PANEL_ID);
    if (existing) existing.remove();
  }

  function render(result) {
    removePanel();

    const panel = el('div', 'cs-panel');
    panel.id = PANEL_ID;

    const head = el('div', 'cs-head');
    const band = BAND[result.band] || { label: 'Result', colour: '#64748b', icon: 'i' };

    if (result.error) {
      head.style.background = '#64748b';
      head.appendChild(el('span', 'cs-icon', '!'));
      head.appendChild(el('span', 'cs-title', 'Check did not complete'));
    } else {
      head.style.background = band.colour;
      head.appendChild(el('span', 'cs-icon', band.icon));
      head.appendChild(el('span', 'cs-title', band.label));
    }

    const close = el('button', 'cs-close', '×');
    close.setAttribute('aria-label', 'Close');
    close.addEventListener('click', removePanel);
    head.appendChild(close);
    panel.appendChild(head);

    const body = el('div', 'cs-body');

    if (result.error) {
      body.appendChild(el('p', 'cs-error', result.error));
    } else {
      // Advice first. The number is secondary and, on an uncalibrated model,
      // arguably misleading — so it is rendered small and always next to the
      // sentence saying what it is.
      const list = el('ul', 'cs-advice');
      (result.advice || []).forEach(function (line) {
        list.appendChild(el('li', null, line));
      });
      body.appendChild(list);

      if (result.indicators && result.indicators.length) {
        body.appendChild(el('h4', null, 'Identifiers found in this message'));
        const chips = el('div', 'cs-chips');
        result.indicators.forEach(function (i) {
          const chip = el('span', 'cs-chip');
          chip.appendChild(el('span', 'cs-chip-kind', i.label || i.kind));
          chip.appendChild(document.createTextNode(' ' + i.value));
          if (i.report_to) chip.title = 'Report to: ' + i.report_to;
          chips.appendChild(chip);
        });
        body.appendChild(chips);
      }

      if (result.reasons && result.reasons.length) {
        const details = el('details', 'cs-details');
        details.appendChild(el('summary', null, 'Why'));
        const why = el('ul');
        result.reasons.forEach(function (r) { why.appendChild(el('li', null, r)); });
        details.appendChild(why);
        body.appendChild(details);
      }

      const score = el('p', 'cs-score');
      score.textContent = 'Score ' + result.score + '/100. '
        + (result.calibrated
            ? 'This is a calibrated probability.'
            : 'This is a raw model score, not a probability — no calibration '
              + 'set exists for this check yet.');
      body.appendChild(score);
    }

    body.appendChild(el('p', 'cs-disclaimer',
      result.disclaimer
      || 'Automated assessment of text only. Not legal advice, and not a '
         + 'determination by any authority.'));

    panel.appendChild(body);
    document.body.appendChild(panel);
  }

  chrome.runtime.onMessage.addListener(function (msg) {
    if (msg && msg.type === 'CS_RESULT') render(msg.result);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') removePanel();
  });
})();
