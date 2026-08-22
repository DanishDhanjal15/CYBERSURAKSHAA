/* ═══════════════════════════════════════════════════════════════
   CYBERSURAKSHAA — All-in-One Detection Suite
   Shared JavaScript
   ═══════════════════════════════════════════════════════════════ */

// ── Utility Functions ───────────────────────────────────────

/**
 * Escape a value for safe interpolation into an HTML template string.
 *
 * Several panels build markup from server data with template literals. Some of
 * that data is not ours: the live threat feed carries titles and snippets
 * scraped from arbitrary web pages, and scan summaries carry text submitted by
 * other users, which an admin then views. Interpolated raw, either one runs as
 * markup in the analyst's session. Every `${...}` holding server data must go
 * through this.
 */
function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const __rawFetch = window.fetch.bind(window);

/** CSRF token rendered into the page by base.html. */
function csrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : '';
}

/**
 * apiFetch() wrapper that attaches the CSRF token to state-changing requests.
 */
function apiFetch(url, options = {}) {
  const opts = { ...options };
  const method = (opts.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    opts.headers = { ...(opts.headers || {}), 'X-CSRFToken': csrfToken() };
  }
  opts.headers = { ...(opts.headers || {}), 'X-Requested-With': 'XMLHttpRequest' };
  return __rawFetch(url, opts);
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function showToast(msg, type = 'success') {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    document.body.appendChild(toast);
  }
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  requestAnimationFrame(() => toast.classList.add('visible'));
  setTimeout(() => toast.classList.remove('visible'), 3500);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!');
  });
}

// ── Ring Gauge Renderer ─────────────────────────────────────
function renderRing(container, pct, color) {
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (circumference * pct / 100);

  container.innerHTML = `
    <svg width="96" height="96" style="transform:rotate(-90deg)">
      <circle cx="48" cy="48" r="${radius}" class="ring-bg"></circle>
      <circle cx="48" cy="48" r="${radius}" class="ring-fill"
        stroke="${color}"
        stroke-dasharray="${circumference}"
        stroke-dashoffset="${circumference}"></circle>
    </svg>
    <div class="ring-center">
      <span class="ring-pct" style="color:${color}">0%</span>
      <span class="ring-unit">Score</span>
    </div>
  `;

  requestAnimationFrame(() => {
    setTimeout(() => {
      container.querySelector('.ring-fill').style.strokeDashoffset = offset;
      animateValue(container.querySelector('.ring-pct'), 0, pct, 1000, '%');
    }, 100);
  });
}

function animateValue(el, start, end, duration, suffix = '') {
  const startTime = performance.now();
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (end - start) * eased);
    el.textContent = current + suffix;
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// ── Drag and Drop ───────────────────────────────────────────
// The file input is a transparent CSS overlay covering the drop zone.
// Clicking anywhere on the zone directly hits the input (no input.click() needed).
// We only need to handle drag events and the input's change event.
function initDropZone(zoneId, inputId, onFileSelected) {
  const zone = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  if (!zone || !input) return;

  // ── Drag & Drop events ──
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });

  zone.addEventListener('dragleave', (e) => {
    if (!zone.contains(e.relatedTarget)) {
      zone.classList.remove('drag-over');
    }
  });

  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
      if (onFileSelected) onFileSelected(e.dataTransfer.files[0]);
    }
  });

  // ── File selection via input (overlay click or drag drop) ──
  input.addEventListener('change', () => {
    if (input.files.length > 0 && onFileSelected) {
      onFileSelected(input.files[0]);
    }
  });
}

function showFileInfo(file, footerId, nameId, sizeId) {
  const footer = document.getElementById(footerId);
  const nameEl = document.getElementById(nameId);
  const sizeEl = document.getElementById(sizeId);
  if (!footer) return;

  nameEl.textContent = file.name;
  sizeEl.textContent = formatFileSize(file.size);
  footer.classList.add('visible');
}

function showPreview(file, previewWrapId, imgId, vidId) {
  const wrap = document.getElementById(previewWrapId);
  const img = document.getElementById(imgId);
  const vid = vidId ? document.getElementById(vidId) : null;
  if (!wrap) return;

  const url = URL.createObjectURL(file);
  const isVideo = file.type.startsWith('video/');

  if (isVideo && vid) {
    vid.src = url;
    vid.style.display = 'block';
    if (img) img.style.display = 'none';
  } else if (img) {
    img.src = url;
    img.style.display = 'block';
    if (vid) vid.style.display = 'none';
  }

  wrap.classList.add('visible');
}

// ── Loading Overlay ─────────────────────────────────────────
function showLoading(message, sub) {
  let overlay = document.getElementById('loading-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'loading-overlay';
    overlay.className = 'loading-overlay';
    overlay.innerHTML = `
      <div class="spinner"></div>
      <div class="loading-text"></div>
      <div class="loading-sub"></div>
    `;
    document.body.appendChild(overlay);
  }
  overlay.querySelector('.loading-text').textContent = message || 'Processing...';
  overlay.querySelector('.loading-sub').textContent = sub || '';
  overlay.classList.add('visible');
}

function hideLoading() {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) overlay.classList.remove('visible');
}

// ── AJAX Form Submit ────────────────────────────────────────
async function submitDetection(url, body, loadingMsg, loadingSub) {
  showLoading(loadingMsg, loadingSub);
  try {
    // FormData posts as multipart; anything else is sent as JSON. Without the
    // explicit Content-Type a string body goes out as text/plain and Flask's
    // request.get_json() quietly returns None — the NFC scanner hit exactly
    // that and every scan came back "No records provided".
    const opts = { method: 'POST', body: body };
    if (!(body instanceof FormData)) {
      if (typeof body !== 'string') opts.body = JSON.stringify(body);
      opts.headers = { 'Content-Type': 'application/json' };
    }
    const resp = await apiFetch(url, opts);
    const data = await resp.json();
    hideLoading();
    if (!resp.ok) {
      showToast(data.error || 'Detection failed', 'error');
      return null;
    }
    return data;
  } catch (err) {
    hideLoading();
    showToast('Network error: ' + err.message, 'error');
    return null;
  }
}

// ── Tab Switching ───────────────────────────────────────────
function initTabs(containerSelector) {
  const container = document.querySelector(containerSelector);
  if (!container) return;

  const btns = container.querySelectorAll('.tab-btn');
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      // Deactivate all
      btns.forEach(b => b.classList.remove('active'));
      container.parentElement.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      // Activate clicked
      btn.classList.add('active');
      const pane = document.getElementById(target);
      if (pane) pane.classList.add('active');
    });
  });
}

// ── OCR Expand/Collapse ─────────────────────────────────────
function toggleOcrExpand(headerId) {
  const header = document.getElementById(headerId);
  if (!header) return;
  const body = header.nextElementSibling;
  if (body) body.classList.toggle('visible');
}

// ── Calibration / abstention band ───────────────────────────
// Every detector now returns an `assessment` from services/intel/calibration.
// The important field is `calibrated`: when false, the percentage on screen is
// a raw model output, not a probability, and the UI has to say so. A detector
// that shows "94% confidence" without that caveat is claiming a rigour it does
// not have, and an analyst acting on it is acting on a number that was never
// checked against a labelled set.
function renderAssessment(container, a) {
  if (!container) return;
  if (!a) { container.innerHTML = ''; return; }

  const icon = {
    SAFE: 'fa-circle-check',
    THREAT: 'fa-triangle-exclamation',
    INSUFFICIENT_EVIDENCE: 'fa-circle-question',
  }[a.band] || 'fa-circle-info';

  const abstain = a.abstained
    ? `<div class="calibration-note">The score falls in the abstention band.
       The system is declining to classify this artefact rather than guessing;
       route it for human review.</div>`
    : '';

  container.innerHTML = `
    <div class="assessment-band band-${esc(a.band)}">
      <i class="fa-solid ${icon}"></i>
      <span><strong>${esc(a.band_label || a.band)}</strong>
        &nbsp;·&nbsp; ${esc(a.percent)}%
        ${a.calibrated
          ? `<span class="prov-chip prov-live" style="margin-left:8px">CALIBRATED</span>`
          : `<span class="prov-chip prov-sim" style="margin-left:8px">UNCALIBRATED</span>`}
      </span>
    </div>
    <div class="calibration-note">${esc(a.note || '')}</div>
    ${abstain}`;
}

// ── Extracted indicator chips ───────────────────────────────
// The identity-bearing strings on a scam creative — the deposit UPI ID, the
// Telegram handle, the mule account — are what an enforcement notice is
// actually about. Rendering them as chips makes them visible and copyable
// instead of buried in the OCR dump.
function renderIndicatorChips(container, indicators, opts) {
  if (!container) return;
  const list = indicators || [];
  if (!list.length) { container.innerHTML = ''; return; }

  const actionable = new Set(['upi_id', 'bank_account', 'phone', 'telegram',
                              'whatsapp', 'domain', 'crypto_wallet', 'apk_cert']);

  container.innerHTML = `
    <div class="info-card">
      <div class="info-card-title"><i class="fa-solid fa-fingerprint"></i>&nbsp;
        Indicators extracted (${list.length})</div>
      <div class="indicator-chips">
        ${list.map(i => `
          <span class="indicator-chip ${actionable.has(i.kind) ? 'actionable' : ''}"
                data-value="${esc(i.normalized || i.value || '')}"
                title="Click to copy">
            <span class="ind-kind">${esc((i.kind || '').replace(/_/g, ' '))}</span>
            ${esc(i.normalized || i.value || '')}
          </span>`).join('')}
      </div>
      <div class="calibration-note">
        Highlighted indicators identify the operator rather than the artefact,
        so they carry across every reskin of the same campaign.
        ${(opts && opts.scanId)
          ? `<a href="/intel/api/scan/${esc(opts.scanId)}/actions/html" target="_blank"
               rel="noopener">Open the enforcement action pack →</a>` : ''}
      </div>
    </div>`;

  container.querySelectorAll('.indicator-chip').forEach(chip => {
    chip.style.cursor = 'pointer';
    chip.addEventListener('click', () => {
      const text = chip.dataset.value || '';
      if (text && navigator.clipboard) {
        navigator.clipboard.writeText(text)
          .then(() => showToast('Copied: ' + text))
          .catch(() => {});
      }
    });
  });
}

// ── Intel-layer panels, shared by every detector ────────────
// Appends (once) an assessment band and an indicator-chip card to a results
// panel, then fills them. Idempotent: re-analysing reuses the same nodes
// instead of stacking duplicates down the page.
function attachIntelPanels(panel, data, moduleName) {
  if (!panel) return;

  let assessBox = panel.querySelector('.intel-assessment');
  if (!assessBox) {
    assessBox = document.createElement('div');
    assessBox.className = 'intel-assessment';
    panel.appendChild(assessBox);
  }
  renderAssessment(assessBox, data.assessment);

  let chipBox = panel.querySelector('.intel-indicators');
  if (!chipBox) {
    chipBox = document.createElement('div');
    chipBox.className = 'intel-indicators';
    panel.appendChild(chipBox);
  }
  const indicators = data.indicators_extracted
    || (data.graph && data.graph.indicators)
    || [];
  renderIndicatorChips(chipBox, indicators, { scanId: data.scan_id });

  attachFeedbackControl(panel, data, moduleName);
}

// ── Analyst feedback control ────────────────────────────────
// Attached to every results panel. This is the only place a human can tell
// the system it was wrong, and it is what eventually produces the confusion
// matrix on /intel/feedback and the labelled sets that make the confidence
// figures real probabilities instead of raw model scores.
//
// Deliberately not a single "report" button: "wrong" is ambiguous, and a
// false positive and a false negative point at opposite failures. The three
// options map exactly onto the labels in services/intel/feedback.py.
function attachFeedbackControl(panel, data, moduleName) {
  if (!panel) return;

  let box = panel.querySelector('.intel-feedback');
  if (!box) {
    box = document.createElement('div');
    box.className = 'intel-feedback';
    panel.appendChild(box);
  }

  box.innerHTML = ''
    + '<div class="info-card feedback-card">'
    + '  <div class="info-card-title"><i class="fa-solid fa-scale-balanced"></i>&nbsp;'
    + '    Was this verdict right?</div>'
    + '  <p class="calibration-note" style="margin-top:-4px">'
    + '    Your answer is recorded against this scan and the evidence chain. It'
    + '    becomes a training label only after a different analyst confirms it.'
    + '  </p>'
    + '  <div class="feedback-buttons">'
    + '    <button class="btn-secondary btn-sm" data-fb="CORRECT">'
    + '      <i class="fa-solid fa-check"></i> Verdict was right</button>'
    + '    <button class="btn-secondary btn-sm" data-fb="FALSE_POSITIVE">'
    + '      <i class="fa-solid fa-flag"></i> False positive</button>'
    + '    <button class="btn-secondary btn-sm" data-fb="FALSE_NEGATIVE">'
    + '      <i class="fa-solid fa-triangle-exclamation"></i> Missed a real threat</button>'
    + '    <button class="btn-secondary btn-sm" data-fb="UNSURE">'
    + '      <i class="fa-solid fa-circle-question"></i> Cannot tell</button>'
    + '  </div>'
    + '  <textarea class="text-input feedback-note" rows="2" style="min-height:0;margin-top:10px"'
    + '            placeholder="Optional: what did the system get wrong, and how do you know?"></textarea>'
    + '  <div class="feedback-status calibration-note"></div>'
    + '</div>';

  const statusEl = box.querySelector('.feedback-status');
  const noteEl = box.querySelector('.feedback-note');

  box.querySelectorAll('[data-fb]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const label = btn.dataset.fb;
      // The scan id arrives asynchronously from saveScanRegistryEntry, so it
      // may not exist yet on a very fast click. Submitting without it still
      // records the correction against the artefact hash; it just cannot be
      // scoped to a scan row.
      const scanId = panel.dataset.scanId ? parseInt(panel.dataset.scanId, 10) : null;

      box.querySelectorAll('[data-fb]').forEach(function (b) { b.disabled = true; });
      statusEl.textContent = 'Recording…';

      try {
        const resp = await apiFetch('/intel/api/feedback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: scanId,
            module: moduleName,
            label: label,
            system_verdict: data.verdict || data.classification
                            || data.risk_level || data.traffic_light,
            system_score: data.score != null ? data.score
                          : (data.confidence != null ? data.confidence
                             : data.final_fraud_score),
            file_hash: data.file_hash,
            note: noteEl.value.trim() || null,
          }),
        });
        const d = await resp.json();
        if (resp.ok) {
          statusEl.innerHTML = '<i class="fa-solid fa-circle-check" style="color:#10b981"></i> '
                             + esc(d.message || 'Recorded.');
          showToast('Feedback recorded.');
        } else {
          statusEl.textContent = d.error || 'Could not record feedback.';
          box.querySelectorAll('[data-fb]').forEach(function (b) { b.disabled = false; });
        }
      } catch (e) {
        statusEl.textContent = 'Could not record feedback.';
        box.querySelectorAll('[data-fb]').forEach(function (b) { b.disabled = false; });
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════
// BETTING DETECTOR
// ═══════════════════════════════════════════════════════════════
function initBettingDetector() {
  let selectedFile = null;

  initDropZone('betting-drop-zone', 'betting-file-input', (file) => {
    selectedFile = file;
    showFileInfo(file, 'betting-file-footer', 'betting-file-name', 'betting-file-size');
    showPreview(file, 'betting-preview-wrap', 'betting-preview-img');
    document.getElementById('betting-analyse-btn').disabled = false;
  });

  const analyseBtn = document.getElementById('betting-analyse-btn');
  if (analyseBtn) {
    analyseBtn.addEventListener('click', async () => {
      if (!selectedFile) return;
      const fd = new FormData();
      fd.append('image', selectedFile);

      const data = await submitDetection('/betting/detect', fd,
        'Analyzing Image...', 'Running OCR → NLP → YOLO → Fusion Pipeline');

      if (data) renderBettingResults(data);
    });
  }
}

function renderBettingResults(data) {
  const panel = document.getElementById('betting-results');
  if (!panel) return;

  attachIntelPanels(panel, data, 'Betting Content');
  
  const fileName = document.getElementById('betting-file-name')?.textContent || 'Uploaded Image';
  const extra = {
    file_hash: data.file_hash,
    indicators: {
      text_probability: data.text_probability,
      vision_probability: data.vision_probability,
      detected_logos: data.detected_logos,
      matched_keywords: data.matched_keywords
    },
    recommendation: data.recommendation
  };
  saveScanRegistryEntry('Betting Content', fileName, data.classification, Math.round(data.confidence), data.reasons, extra).then(scanId => {
    // Feedback and action-pack links key off this.
    if (scanId) panel.dataset.scanId = scanId;
    if (scanId) {
      const exportBtn = document.getElementById('betting-export-btn');
      if (exportBtn) {
        exportBtn.style.display = 'inline-flex';
        exportBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/pdf`, '_blank');
        
        // Add Takedown button dynamically
        let takedownBtn = document.getElementById('betting-takedown-btn');
        if (!takedownBtn) {
          takedownBtn = document.createElement('button');
          takedownBtn.id = 'betting-takedown-btn';
          takedownBtn.className = 'btn btn-outline btn-navy';
          takedownBtn.style.marginLeft = '10px';
          takedownBtn.style.borderColor = 'var(--secondary-gold)';
          takedownBtn.style.color = 'var(--secondary-gold)';
          takedownBtn.innerHTML = '<i class="fa-solid fa-gavel"></i> Takedown Notice';
          exportBtn.parentNode.appendChild(takedownBtn);
        }
        takedownBtn.style.display = 'inline-flex';
        takedownBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/takedown/pdf`, '_blank');
      }
    }
  });

  // Hide watermark first
  const wm = document.getElementById('betting-watermark');
  if (wm) wm.classList.remove('visible');

  panel.classList.add('visible');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Update preview image to show annotated bounding boxes if available
  if (data.annotated_image) {
    const previewImg = document.getElementById('betting-preview-img');
    if (previewImg) {
      previewImg.src = `data:image/png;base64,${data.annotated_image}`;
    }
  }

  // Determine state
  const cls = data.classification;
  let stateClass, color, badgeLabel;
  if (cls === 'BETTING') {
    stateClass = 'state-danger'; color = '#ef4444'; badgeLabel = '⚠ Betting Detected';
  } else if (cls === 'SUSPICIOUS') {
    stateClass = 'state-warn'; color = '#f59e0b'; badgeLabel = '⚡ Suspicious Content';
  } else {
    stateClass = 'state-safe'; color = '#10b981'; badgeLabel = '✓ Safe Content';
  }

  // Verdict banner
  const banner = panel.querySelector('.verdict-banner');
  banner.className = `verdict-banner ${stateClass}`;

  const badge = panel.querySelector('.verdict-badge');
  badge.textContent = badgeLabel;

  // Show watermark if betting or suspicious content
  if (cls === 'BETTING' || cls === 'SUSPICIOUS') {
    if (wm) wm.classList.add('visible');
  }

  const word = panel.querySelector('.verdict-word');
  word.textContent = cls;

  const desc = panel.querySelector('.verdict-desc');
  desc.textContent = data.reasons && data.reasons.length > 0 ? data.reasons[0] : 'Analysis complete.';

  // Ring gauge
  const ringWrap = panel.querySelector('.ring-wrap');
  renderRing(ringWrap, Math.round(data.confidence), color);

  // Metrics
  const textProb = panel.querySelector('#betting-text-prob');
  if (textProb) animateValue(textProb, 0, Math.round(data.text_probability), 800, '%');

  const visionProb = panel.querySelector('#betting-vision-prob');
  if (visionProb) animateValue(visionProb, 0, Math.round(data.vision_probability), 800, '%');

  // Keywords
  const kwContainer = panel.querySelector('#betting-keywords');
  if (kwContainer) {
    if (data.matched_keywords && data.matched_keywords.length > 0) {
      kwContainer.innerHTML = data.matched_keywords
        .map(kw => `<span class="keyword-chip">${esc(kw)}</span>`).join('');
    } else {
      kwContainer.innerHTML = '<span style="color:var(--text3);font-size:0.82rem">No betting keywords detected</span>';
    }
  }

  // Detected logos
  const logoContainer = panel.querySelector('#betting-logos');
  if (logoContainer) {
    if (data.detected_logos && data.detected_logos.length > 0) {
      logoContainer.innerHTML = data.detected_logos
        .map(l => `<span class="tag">${esc(l)}</span>`).join('');
    } else {
      logoContainer.innerHTML = '<span style="color:var(--text3);font-size:0.82rem">No betting logos detected</span>';
    }
  }

  // Evidence highlight image — only shown when the server actually boxed
  // something; an unchanged image presented as "evidence" would be worse
  // than none.
  const hlCard = document.getElementById('betting-highlight-card');
  const hlImg = document.getElementById('betting-highlight-img');
  if (hlCard && hlImg) {
    if (data.highlight_image) {
      hlImg.src = `data:image/jpeg;base64,${data.highlight_image}`;
      hlCard.style.display = '';
    } else {
      hlCard.style.display = 'none';
    }
  }

  // OCR text, with the words that scored wrapped in <mark>. Built from
  // escaped text and escaped keywords so OCR content can never inject HTML.
  const ocrBox = panel.querySelector('#betting-ocr-text');
  if (ocrBox) {
    const raw = data.ocr_text || '(no text detected)';
    let html = esc(raw);
    const kws = (data.matched_keywords || []).filter(k => String(k).length >= 3);
    if (kws.length) {
      const pattern = kws
        .map(k => esc(String(k)).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
        .join('|');
      try {
        html = html.replace(new RegExp(`(${pattern})`, 'gi'), '<mark>$1</mark>');
      } catch (e) { /* a malformed pattern falls back to plain text */ }
    }
    ocrBox.innerHTML = html;
  }

  // Reasons
  const reasonsList = panel.querySelector('#betting-reasons');
  if (reasonsList && data.reasons) {
    reasonsList.innerHTML = data.reasons.map(r => `
      <div class="reason-item">
        <span class="reason-dot" style="background:${color}"></span>
        <span>${esc(r)}</span>
      </div>
    `).join('');
  }
}

// ═══════════════════════════════════════════════════════════════
// DEEPFAKE DETECTOR
// ═══════════════════════════════════════════════════════════════
function initDeepfakeDetector() {
  let selectedFile = null;

  initDropZone('deepfake-drop-zone', 'deepfake-file-input', (file) => {
    selectedFile = file;
    showFileInfo(file, 'deepfake-file-footer', 'deepfake-file-name', 'deepfake-file-size');
    showPreview(file, 'deepfake-preview-wrap', 'deepfake-preview-img', 'deepfake-preview-vid');
    document.getElementById('deepfake-analyse-btn').disabled = false;
  });

  const analyseBtn = document.getElementById('deepfake-analyse-btn');
  if (analyseBtn) {
    analyseBtn.addEventListener('click', async () => {
      if (!selectedFile) return;
      const fd = new FormData();
      fd.append('file', selectedFile);

      const data = await submitDetection('/deepfake/predict', fd,
        'Analyzing Media...', 'Running Face Detection → EfficientNet B4 Inference');

      if (data) {
        if (data.error) {
          showToast(data.error, 'error');
        } else {
          renderDeepfakeResults(data);
        }
      }
    });
  }
}

function renderDeepfakeResults(data) {
  const panel = document.getElementById('deepfake-results');
  if (!panel) return;

  const scorePct = Math.round(data.score);
  const isFake = data.verdict === 'FAKE';

  // Save to registry
  const fileName = document.getElementById('deepfake-file-name')?.textContent || 'Uploaded Media';
  const reasons = [isFake ? 'Manipulation signals detected' : 'Media appears authentic', `${data.frames} frames processed`].filter(Boolean);
  const extra = {
    file_hash: data.file_hash,
    indicators: {
      score: data.score,
      frames: data.frames
    },
    recommendation: data.recommendation
  };
  saveScanRegistryEntry('Deepfake Face', fileName, data.verdict, scorePct, reasons, extra).then(scanId => {
    // Feedback and action-pack links key off this.
    if (scanId) panel.dataset.scanId = scanId;
    if (scanId) {
      const exportBtn = document.getElementById('deepfake-export-btn');
      if (exportBtn) {
        exportBtn.style.display = 'inline-flex';
        exportBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/pdf`, '_blank');
        
        // Add Takedown button dynamically
        let takedownBtn = document.getElementById('deepfake-takedown-btn');
        if (!takedownBtn) {
          takedownBtn = document.createElement('button');
          takedownBtn.id = 'deepfake-takedown-btn';
          takedownBtn.className = 'btn btn-outline btn-navy';
          takedownBtn.style.marginLeft = '10px';
          takedownBtn.style.borderColor = 'var(--secondary-gold)';
          takedownBtn.style.color = 'var(--secondary-gold)';
          takedownBtn.innerHTML = '<i class="fa-solid fa-gavel"></i> Takedown Notice';
          exportBtn.parentNode.appendChild(takedownBtn);
        }
        takedownBtn.style.display = 'inline-flex';
        takedownBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/takedown/pdf`, '_blank');
      }
    }
  });

  // Hide watermark first
  const wm = document.getElementById('deepfake-watermark');
  if (wm) wm.classList.remove('visible');

  panel.classList.add('visible');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const stateClass = isFake ? 'state-danger' : 'state-safe';
  const color = isFake ? '#ef4444' : '#10b981';

  // Show watermark if deepfake detected
  if (isFake) {
    if (wm) wm.classList.add('visible');
  }

  // Verdict banner
  const banner = panel.querySelector('.verdict-banner');
  banner.className = `verdict-banner ${stateClass}`;

  const badge = panel.querySelector('.verdict-badge');
  badge.textContent = isFake ? '⚠ Deepfake Detected' : '✓ Authentic Media';

  const word = panel.querySelector('.verdict-word');
  word.textContent = data.verdict;

  const desc = panel.querySelector('.verdict-desc');
  desc.textContent = isFake
    ? 'AI analysis indicates this media has been digitally manipulated. The facial features show signs of synthetic generation.'
    : 'No signs of digital manipulation detected. The facial features appear authentic and consistent.';

  // Ring gauge
  const ringWrap = panel.querySelector('.ring-wrap');
  renderRing(ringWrap, scorePct, color);

  // Metrics
  const frames = panel.querySelector('#deepfake-frames');
  if (frames) animateValue(frames, 0, data.frames, 600);

  const threat = panel.querySelector('#deepfake-threat');
  if (threat) {
    let level, levelColor;
    if (data.score > 80) { level = 'CRITICAL'; levelColor = 'var(--red-hi)'; }
    else if (data.score > 60) { level = 'HIGH'; levelColor = 'var(--orange)'; }
    else if (data.score > 40) { level = 'MEDIUM'; levelColor = 'var(--yellow)'; }
    else { level = 'LOW'; levelColor = 'var(--green-hi)'; }
    threat.textContent = level;
    threat.style.color = levelColor;
  }

  // Manipulation bar
  const barFill = panel.querySelector('#deepfake-bar-fill');
  const barPct = panel.querySelector('#deepfake-bar-pct');
  if (barFill) {
    barFill.style.background = `linear-gradient(90deg, var(--green), var(--yellow), var(--red))`;
    setTimeout(() => { barFill.style.width = scorePct + '%'; }, 100);
  }
  if (barPct) barPct.textContent = scorePct + '%';

  // ── Model explanation ────────────────────────────────────────
  // This replaced a "forensic diagnostics" matrix that derived five named
  // sub-metrics from `scorePct` plus a random jitter. The model computes no such
  // quantities; the panel invented them, and they changed between runs on the
  // same file. What is rendered now is the model's own Grad-CAM attribution.
  const explainCard = panel.querySelector('#deepfake-explain-card');
  const heatImg     = panel.querySelector('#deepfake-heatmap');
  const explainNote = panel.querySelector('#deepfake-explain-note');

  if (explainCard && heatImg) {
    if (data.heatmap) {
      heatImg.src = 'data:image/png;base64,' + data.heatmap;
      explainCard.style.display = 'block';
      if (explainNote) explainNote.textContent = data.explanation_note || '';
    } else {
      // No overlay is a real state, not an error: torch may be absent, or the
      // target layer unlocatable. Saying so beats hiding the panel silently.
      explainCard.style.display = 'block';
      heatImg.removeAttribute('src');
      heatImg.style.display = 'none';
      if (explainNote) {
        explainNote.textContent =
          'No attribution map could be produced for this file, so the score ' +
          'above is unexplained. Treat it as a lead requiring corroboration.';
      }
    }
  }

  // Calibration / abstention band
  const assessBox = panel.querySelector('#deepfake-assessment');
  if (assessBox) {
    renderAssessment(assessBox, data.assessment);
  }

  attachFeedbackControl(panel, data, 'Deepfake Face');
}

// ═══════════════════════════════════════════════════════════════
// CUSTOMER CARE DETECTOR
// ═══════════════════════════════════════════════════════════════
function initCustomerCareDetector() {
  let selectedFile = null;
  let activeTab = 'image';

  initTabs('#cc-tabs');

  // Track active tab
  document.querySelectorAll('#cc-tabs .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activeTab = btn.dataset.tab.replace('cc-tab-', '');
    });
  });

  initDropZone('cc-drop-zone', 'cc-file-input', (file) => {
    selectedFile = file;
    showFileInfo(file, 'cc-file-footer', 'cc-file-name', 'cc-file-size');
    showPreview(file, 'cc-preview-wrap', 'cc-preview-img');
  });

  const analyseBtn = document.getElementById('cc-analyse-btn');
  if (analyseBtn) {
    analyseBtn.addEventListener('click', async () => {
      const fd = new FormData();

      if (activeTab === 'image') {
        if (!selectedFile) { showToast('Please upload an image first', 'error'); return; }
        fd.append('input_type', 'image');
        fd.append('image_file', selectedFile);
      } else if (activeTab === 'url') {
        const url = document.getElementById('cc-url-input').value.trim();
        if (!url) { showToast('Please enter a URL', 'error'); return; }
        fd.append('input_type', 'url');
        fd.append('image_url', url);
      } else {
        const text = document.getElementById('cc-text-input').value.trim();
        if (!text) { showToast('Please enter text to analyze', 'error'); return; }
        fd.append('input_type', 'text');
        fd.append('pasted_text', text);
      }

      const data = await submitDetection('/customer-care/analyze', fd,
        'SHIELD Scanning...', 'Running PaddleOCR → Brand Detection → Risk Analysis');

      if (data) renderCustomerCareResults(data);
    });
  }
}

function renderCustomerCareResults(data) {
  const panel = document.getElementById('cc-results');
  if (!panel) return;

  attachIntelPanels(panel, data, 'Customer Care');

  let inputSource = 'Pasted Text / Image';
  const fileEl = document.getElementById('cc-file-name');
  const urlEl = document.getElementById('cc-url-input');
  if (document.getElementById('cc-tab-image')?.classList.contains('active') && fileEl && fileEl.textContent) {
    inputSource = 'Image: ' + fileEl.textContent;
  } else if (document.getElementById('cc-tab-url')?.classList.contains('active') && urlEl && urlEl.value.trim()) {
    inputSource = 'URL: ' + urlEl.value.trim();
  } else if (data.text) {
    inputSource = data.text;
  }
  const extra = {
    file_hash: data.file_hash,
    indicators: {
      detected_phone: data.detected_phone || 'None',
      brand: data.brand || 'None',
      official_phone: data.official_phone || 'None',
      telecom_label: data.telecom_label || 'None',
      urgency_score: data.urgency_score,
      coercion_score: data.coercion_score,
      anomaly_score: data.anomaly_score
    },
    recommendation: data.recommendation
  };
  saveScanRegistryEntry('Customer Care', inputSource, data.severity, data.risk_score, data.reasons, extra).then(scanId => {
    // Feedback and action-pack links key off this.
    if (scanId) panel.dataset.scanId = scanId;
    if (scanId) {
      const exportBtn = document.getElementById('cc-export-btn');
      if (exportBtn) {
        exportBtn.style.display = 'inline-flex';
        exportBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/pdf`, '_blank');
        
        // Add Takedown button dynamically
        let takedownBtn = document.getElementById('cc-takedown-btn');
        if (!takedownBtn) {
          takedownBtn = document.createElement('button');
          takedownBtn.id = 'cc-takedown-btn';
          takedownBtn.className = 'btn btn-outline btn-navy';
          takedownBtn.style.marginLeft = '10px';
          takedownBtn.style.borderColor = 'var(--secondary-gold)';
          takedownBtn.style.color = 'var(--secondary-gold)';
          takedownBtn.innerHTML = '<i class="fa-solid fa-gavel"></i> Takedown Notice';
          exportBtn.parentNode.appendChild(takedownBtn);
        }
        takedownBtn.style.display = 'inline-flex';
        takedownBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/takedown/pdf`, '_blank');
      }
    }
  });

  // Hide watermarks first
  const imageWm = document.getElementById('cc-watermark');
  const textWm = document.getElementById('cc-text-watermark');
  if (imageWm) imageWm.classList.remove('visible');
  if (textWm) textWm.classList.remove('visible');

  // Scanned text box update
  const textCard = document.getElementById('cc-scanned-text-card');
  const textBox = document.getElementById('cc-scanned-text-box');
  if (textCard && textBox) {
    if (data.text) {
      textBox.textContent = data.text;
      textCard.style.display = 'block';
    } else {
      textCard.style.display = 'none';
    }
  }

  panel.classList.add('visible');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const sev = data.severity;
  let stateClass, color;
  if (sev === 'Safe') { stateClass = 'state-safe'; color = '#10b981'; }
  else if (sev === 'Suspicious') { stateClass = 'state-warn'; color = '#f59e0b'; }
  else { stateClass = 'state-danger'; color = '#ef4444'; }

  // Show watermark if suspicious or danger
  if (sev !== 'Safe') {
    const isTextTab = document.getElementById('cc-tab-text')?.classList.contains('active');
    if (isTextTab) {
      if (textWm) textWm.classList.add('visible');
    } else {
      if (imageWm) imageWm.classList.add('visible');
    }
  }

  // Verdict banner
  const banner = panel.querySelector('.verdict-banner');
  banner.className = `verdict-banner ${stateClass}`;

  const badge = panel.querySelector('.verdict-badge');
  badge.textContent = sev === 'Safe' ? '✓ Safe' : sev === 'Suspicious' ? '⚡ Suspicious' : '⚠ ' + sev;

  const word = panel.querySelector('.verdict-word');
  word.textContent = sev.toUpperCase();

  const desc = panel.querySelector('.verdict-desc');
  desc.textContent = data.recommendation || 'Analysis complete.';

  // Ring gauge — risk score
  const ringWrap = panel.querySelector('.ring-wrap');
  renderRing(ringWrap, data.risk_score, color);
  panel.querySelector('.ring-unit').textContent = 'Risk';

  // Confidence ring
  const confRing = panel.querySelector('#cc-conf-ring');
  if (confRing) renderRing(confRing, Math.round(data.confidence), '#3b82f6');

  // Info rows
  const setInfo = (id, val) => {
    const el = panel.querySelector('#' + id);
    if (el) el.textContent = val || 'N/A';
  };

  setInfo('cc-brand', data.brand || 'Unknown');
  setInfo('cc-detected-phone', data.detected_phone || 'None');
  setInfo('cc-official-phone', data.official_phone || 'Not Available');
  setInfo('cc-prev-reports', data.previous_reports || '0');

  // Reasons
  const reasonsList = panel.querySelector('#cc-reasons');
  if (reasonsList && data.reasons) {
    reasonsList.innerHTML = data.reasons.map(r => `
      <div class="reason-item">
        <span class="reason-dot" style="background:${color}"></span>
        <span>${esc(r)}</span>
      </div>
    `).join('');
  }

  // Recommendation box
  const recoBox = panel.querySelector('#cc-reco-box');
  if (recoBox) {
    recoBox.className = `reco-box reco-${sev === 'Safe' ? 'safe' : sev === 'Suspicious' ? 'warn' : 'danger'}`;
    const recoText = recoBox.querySelector('#cc-reco-text');
    if (recoText) recoText.textContent = data.recommendation;
  }

  // ── Render Scam Heuristics Breakdown ──
  const ccMetrics = [
    { id: 'urgency', val: data.urgency_score || 5, isInverted: false },
    { id: 'coercion', val: data.coercion_score || 5, isInverted: false },
    { id: 'cta', val: data.cta_density || 5, isInverted: false },
    { id: 'telecom', val: data.telecom_trust || 95, isInverted: true },
    { id: 'syntax', val: data.anomaly_score || 5, isInverted: false }
  ];

  ccMetrics.forEach(m => {
    const fill = panel.querySelector(`#cc-diag-${m.id}-fill`);
    const badge = panel.querySelector(`#cc-diag-${m.id}-badge`);
    const valEl = panel.querySelector(`#cc-diag-${m.id}-val`);

    if (fill) {
      fill.className = 'diag-fill';
      if (m.isInverted) {
        // Higher trust is better
        if (m.val >= 75) fill.classList.add('bg-green');
        else if (m.val >= 40) fill.classList.add('bg-yellow');
        else fill.classList.add('bg-red');
      } else {
        // Lower threat is better
        if (m.val < 40) fill.classList.add('bg-green');
        else if (m.val < 70) fill.classList.add('bg-yellow');
        else fill.classList.add('bg-red');
      }
      setTimeout(() => { fill.style.width = m.val + '%'; }, 150);
    }

    if (badge) {
      badge.className = 'badge';
      if (m.isInverted) {
        if (m.val >= 75) { badge.classList.add('badge-safe'); badge.textContent = 'TRUSTED'; }
        else if (m.val >= 40) { badge.classList.add('badge-warn'); badge.textContent = 'UNVERIFIED'; }
        else { badge.classList.add('badge-danger'); badge.textContent = 'SUSPICIOUS'; }
      } else {
        if (m.val < 40) { badge.classList.add('badge-safe'); badge.textContent = 'SECURE'; }
        else if (m.val < 70) { badge.classList.add('badge-warn'); badge.textContent = 'WARNING'; }
        else { badge.classList.add('badge-danger'); badge.textContent = 'CRITICAL'; }
      }
    }

    if (valEl) valEl.textContent = m.val + '%';
  });

  const telecomDesc = panel.querySelector('#cc-diag-telecom-desc');
  if (telecomDesc) {
    telecomDesc.textContent = `Carrier classification: ${data.telecom_label || 'No Indicators Detected'}`;
  }

  // Report scam button
  const reportBtn = panel.querySelector('#cc-report-btn');
  if (reportBtn) {
    if (data.detected_phone && data.has_phone) {
      reportBtn.style.display = 'inline-flex';
      reportBtn.onclick = async () => {
        try {
          const resp = await apiFetch('/customer-care/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ phone: data.detected_phone }),
          });
          const result = await resp.json();
          if (result.success) {
            showToast('Reported successfully! Reports: ' + result.reports);
            setInfo('cc-prev-reports', result.reports);
          }
        } catch (e) {
          showToast('Failed to report', 'error');
        }
      };
    } else {
      reportBtn.style.display = 'none';
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// INVESTMENT SCAM DETECTOR
// ═══════════════════════════════════════════════════════════════
function initInvestmentDetector() {
  const textarea = document.getElementById('invest-text-input');
  const charCount = document.getElementById('invest-char-count');
  const analyseBtn = document.getElementById('invest-analyse-btn');
  const clearBtn = document.getElementById('invest-clear-btn');

  if (!textarea || !analyseBtn) return;

  // Character counter
  textarea.addEventListener('input', () => {
    charCount.textContent = textarea.value.length + ' chars';
  });

  // Clear button
  clearBtn.addEventListener('click', () => {
    textarea.value = '';
    charCount.textContent = '0 chars';
    document.getElementById('invest-results').classList.remove('visible');
    document.getElementById('invest-empty-state').style.display = '';
  });

  // Analyze button
  analyseBtn.addEventListener('click', async () => {
    const message = textarea.value.trim();
    if (!message) {
      showToast('Please enter a message to analyze.', 'error');
      return;
    }

    showLoading('Analyzing Message...', 'Running NLP → WHOIS → ML Scoring Pipeline');

    try {
      const resp = await apiFetch('/investment/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });

      const data = await resp.json();
      hideLoading();

      if (!resp.ok) {
        showToast(data.error || 'Analysis failed', 'error');
        return;
      }

      renderInvestmentResults(data);
    } catch (err) {
      hideLoading();
      showToast('Network error: ' + err.message, 'error');
    }
  });
}

function renderInvestmentResults(data) {
  const panel = document.getElementById('invest-results');
  if (!panel) return;

  attachIntelPanels(panel, data, 'Investment Scam');

  // Hide empty state, show results
  document.getElementById('invest-empty-state').style.display = 'none';
  panel.classList.add('visible');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const light = data.traffic_light || 'green';
  const score = data.final_fraud_score || 0;
  const breakdown = data.engine_breakdown || {};
  const engineStatus = data.engine_status || {};
  const reasons = data.reasons || [];

  // Determine state
  let stateClass, color, badgeLabel, verdictWord;
  if (light === 'red') {
    stateClass = 'state-danger'; color = '#ef4444';
    badgeLabel = '⚠ High Risk — Likely Scam'; verdictWord = 'SCAM';
  } else if (light === 'yellow') {
    stateClass = 'state-warn'; color = '#f59e0b';
    badgeLabel = '⚡ Suspicious — Proceed with Caution'; verdictWord = 'SUSPICIOUS';
  } else {
    stateClass = 'state-safe'; color = '#10b981';
    badgeLabel = '✓ Safe — No Scam Signals'; verdictWord = 'SAFE';
  }

  const inputMessage = document.getElementById('invest-text-input')?.value.trim() || 'Pasted Text';
  const extra = {
    file_hash: data.file_hash,
    indicators: {
      engine_breakdown: data.engine_breakdown,
      traffic_light: data.traffic_light
    },
    recommendation: data.recommendation
  };
  saveScanRegistryEntry('Investment Scam', inputMessage, verdictWord, score, reasons, extra).then(scanId => {
    // Feedback and action-pack links key off this.
    if (scanId) panel.dataset.scanId = scanId;
    if (scanId) {
      const exportBtn = document.getElementById('invest-export-btn');
      if (exportBtn) {
        exportBtn.style.display = 'inline-flex';
        exportBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/pdf`, '_blank');
        
        // Add Takedown button dynamically
        let takedownBtn = document.getElementById('invest-takedown-btn');
        if (!takedownBtn) {
          takedownBtn = document.createElement('button');
          takedownBtn.id = 'invest-takedown-btn';
          takedownBtn.className = 'btn btn-outline btn-navy';
          takedownBtn.style.marginLeft = '10px';
          takedownBtn.style.borderColor = 'var(--secondary-gold)';
          takedownBtn.style.color = 'var(--secondary-gold)';
          takedownBtn.innerHTML = '<i class="fa-solid fa-gavel"></i> Takedown Notice';
          exportBtn.parentNode.appendChild(takedownBtn);
        }
        takedownBtn.style.display = 'inline-flex';
        takedownBtn.onclick = () => window.open(`/auth/api/scans/${scanId}/takedown/pdf`, '_blank');
      }
    }
  });

  // Hide watermark first
  const wm = document.getElementById('invest-watermark');
  if (wm) wm.classList.remove('visible');

  // Update scanned text box
  const textBox = document.getElementById('invest-scanned-text-box');
  if (textBox) textBox.textContent = inputMessage;

  // Show watermark if warning or danger
  if (light === 'red' || light === 'yellow') {
    if (wm) wm.classList.add('visible');
  }

  // Verdict banner
  const banner = panel.querySelector('.verdict-banner');
  banner.className = `verdict-banner ${stateClass}`;

  const badge = panel.querySelector('.verdict-badge');
  badge.textContent = badgeLabel;

  const word = panel.querySelector('.verdict-word');
  word.textContent = verdictWord;

  const desc = panel.querySelector('.verdict-desc');
  if (light === 'red') {
    desc.textContent = 'Strong scam signals detected. This message contains multiple red flags commonly found in investment fraud.';
  } else if (light === 'yellow') {
    desc.textContent = 'Some suspicious patterns detected. Exercise caution and verify the claims independently before taking action.';
  } else {
    desc.textContent = 'No significant scam signals detected in this message. The content appears to be safe.';
  }

  // Ring gauge
  const ringWrap = panel.querySelector('.ring-wrap');
  renderRing(ringWrap, score, color);

  // Engine breakdown
  const engineA = breakdown.engine_a_xgboost || 0;
  const engineB = breakdown.engine_b_xlm_roberta || 0;

  const engineAVal = panel.querySelector('#invest-engine-a');
  if (engineAVal) animateValue(engineAVal, 0, engineA, 800);

  const engineBVal = panel.querySelector('#invest-engine-b');
  if (engineBVal) animateValue(engineBVal, 0, engineB, 800);

  // Engine status labels
  const engineAStatus = panel.querySelector('#invest-engine-a-status');
  if (engineAStatus) {
    engineAStatus.textContent = engineStatus.engine_a_online ? 'ML Model Active' : 'Keyword Fallback';
    engineAStatus.style.color = engineStatus.engine_a_online ? 'var(--green-hi)' : 'var(--yellow)';
  }

  const engineBStatus = panel.querySelector('#invest-engine-b-status');
  if (engineBStatus) {
    engineBStatus.textContent = engineStatus.engine_b_online ? 'Deep Learning Active' : 'Inactive';
    engineBStatus.style.color = engineStatus.engine_b_online ? 'var(--green-hi)' : 'var(--text3)';
  }

  // Engine warning
  const warning = document.getElementById('invest-engine-warning');
  const warningText = document.getElementById('invest-engine-warning-text');
  if (warning && warningText) {
    const msgs = [];
    if (!engineStatus.engine_a_online) msgs.push('Primary NLP model (Engine A) is offline. Using fallback rule-based analysis.');
    if (!engineStatus.engine_b_online) msgs.push('Multilingual semantic model (Engine B) is offline. Results are based on keyword analysis only.');
    if (msgs.length > 0) {
      warning.style.display = '';
      warningText.innerHTML = msgs.map(m => '<p style="margin:4px 0;font-size:0.82rem">' + esc(m) + '</p>').join('');
    } else {
      warning.style.display = 'none';
    }
  }

  // Risk score bar
  const barFill = panel.querySelector('#invest-bar-fill');
  const barPct = panel.querySelector('#invest-bar-pct');
  if (barFill) {
    barFill.style.background = `linear-gradient(90deg, var(--green), var(--yellow), var(--red))`;
    setTimeout(() => { barFill.style.width = score + '%'; }, 100);
  }
  if (barPct) barPct.textContent = score + '%';

  // Detected signals
  const signalCount = document.getElementById('invest-signal-count');
  if (signalCount) signalCount.textContent = reasons.length + ' found';

  const reasonsList = panel.querySelector('#invest-reasons');
  if (reasonsList) {
    reasonsList.innerHTML = reasons.map(r => `
      <div class="reason-item">
        <span class="reason-dot" style="background:${color}"></span>
        <span>${esc(r)}</span>
      </div>
    `).join('');
  }

  // Recommendation box
  const recoBox = document.getElementById('invest-reco-box');
  const recoText = document.getElementById('invest-reco-text');
  if (recoBox && recoText) {
    recoBox.className = `reco-box reco-${light === 'green' ? 'safe' : light === 'yellow' ? 'warn' : 'danger'}`;
    recoText.textContent = data.recommendation || '';
  }
}

// ═══════════════════════════════════════════════════════════════
// Theme Toggler & Scan Registry Functions
// ═══════════════════════════════════════════════════════════════
function initThemeToggler() {
  const toggleBtn = document.getElementById('theme-toggle');
  if (!toggleBtn) return;

  // Set initial icon based on theme
  const isDark = document.documentElement.classList.contains('dark-theme');
  const icon = toggleBtn.querySelector('i');
  if (icon) {
    icon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
  }

  toggleBtn.addEventListener('click', () => {
    const isNowDark = document.documentElement.classList.toggle('dark-theme');
    localStorage.setItem('cybersurakshaa-theme', isNowDark ? 'dark' : 'light');
    if (icon) {
      icon.className = isNowDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    }
  });
}

// Registry sync dummy getter for compatibility
function getScanRegistry() {
  return [];
}

async function saveScanRegistryEntry(moduleName, inputSummary, verdict, score, reasons, extra = {}) {
  try {
    const resp = await apiFetch('/auth/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        module: moduleName,
        input: inputSummary,
        verdict: verdict,
        score: score,
        reasons: reasons || [],
        file_hash: extra.file_hash || null,
        indicators: extra.indicators || null,
        recommendation: extra.recommendation || null
      })
    });
    // Dynamically refresh table if visible
    renderScanRegistryTable();
    if (resp.ok) {
      const data = await resp.json();
      return data.id;
    }
  } catch (e) {
    console.error("Failed to save scan registry entry to backend database", e);
  }
  return null;
}

async function deleteScanRegistryEntry(id) {
  if (!confirm('Are you sure you want to delete this scan log?')) return;
  try {
    const resp = await apiFetch('/auth/api/scans/' + id, { method: 'DELETE' });
    if (resp.ok) {
      showToast('Scan history log removed');
      renderScanRegistryTable();
    }
  } catch (e) {
    console.error("Failed to delete scan log", e);
  }
}

function showRegistryDetails(id) {
  // Details alert function handles details display via template variables or API
}

async function clearScanRegistry() {
  if (!confirm('Are you sure you want to clear your entire scan history?')) return;
  try {
    const resp = await apiFetch('/auth/api/scans', { method: 'DELETE' });
    if (resp.ok) {
      showToast('Scan history cleared successfully');
      renderScanRegistryTable();
    }
  } catch (e) {
    console.error("Failed to clear scan history", e);
  }
}

async function renderScanRegistryTable(filter = 'all') {
  const body = document.getElementById('registry-body');
  if (!body) return; // Drawer not active or not logged in

  try {
    const resp = await apiFetch('/auth/api/scans?filter=' + filter);
    if (!resp.ok) return;
    const filtered = await resp.json();

    if (filtered.length === 0) {
      body.innerHTML = `
        <tr>
          <td colspan="5">
            <div class="registry-empty">
              <i class="fa-solid fa-database"></i>
              <span>No scan records matching the active filter.</span>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    body.innerHTML = filtered.map(entry => {
      let badgeClass = 'badge-safe';
      const v = (entry.verdict || '').toUpperCase();
      if (v.includes('SUSPICIOUS') || v.includes('WARN') || v.includes('YELLOW')) {
        badgeClass = 'badge-suspicious';
      } else if (v.includes('BETTING') || v.includes('FAKE') || v.includes('SCAM') || v.includes('DANGER') || v.includes('RED') || v.includes('CRITICAL')) {
        badgeClass = 'badge-danger';
      }

      // Short summary text
      let summary = entry.input_summary || 'Unknown Source';
      if (summary.length > 50) {
        summary = summary.substring(0, 48) + '...';
      }

      let verdictLabel = entry.verdict || 'Unknown';
      if (entry.score !== undefined && entry.score !== null) {
        verdictLabel += ` (${entry.score}%)`;
      }

      // input_summary is user-submitted, and an admin sees every user's rows —
      // so an unescaped value here runs in the administrator's session.
      const reasonsStr = (entry.reasons || []).map(r => `• ${r}`).join('\n');
      const details = [
        `${entry.module} Scan History Log Details:`,
        '',
        `Timestamp: ${entry.timestamp}`,
        `Verdict: ${verdictLabel}`,
        `Target: ${entry.input_summary || ''}`,
        '',
        reasonsStr,
      ].join('\n');

      return `
        <tr data-details="${esc(details)}">
          <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem;">${esc(entry.timestamp)}</td>
          <td style="font-weight: 600; color: var(--primary-hi);">${esc(entry.module)}</td>
          <td title="${esc(entry.input_summary || '')}">${esc(summary)}</td>
          <td>
            <span class="status-badge ${badgeClass}">${esc(verdictLabel)}</span>
          </td>
          <td>
            <a href="/auth/api/scans/${encodeURIComponent(entry.id)}/pdf" class="btn-icon-pdf" style="color: #b91c1c; font-size: 0.95rem; margin-right: 8px;" title="Export CTI PDF Report" target="_blank">
              <i class="fa-solid fa-file-pdf"></i>
            </a>
            <a href="/auth/api/scans/${encodeURIComponent(entry.id)}/html" class="btn-icon-html" style="color: var(--primary-hi); font-size: 0.95rem; margin-right: 8px;" title="View HTML CTI Report" target="_blank">
              <i class="fa-solid fa-file-code"></i>
            </a>
            <a href="/auth/api/scans/${encodeURIComponent(entry.id)}/takedown/pdf" class="btn-icon-gavel" style="color: #d4af37; font-size: 0.95rem; margin-right: 8px;" title="Generate IT Act Sec 79 Takedown Notice" target="_blank">
              <i class="fa-solid fa-gavel"></i>
            </a>
            <button class="btn-icon-info" title="View Quick Details" data-show-details style="margin-right: 6px; border: none; background: none; color: var(--text3); cursor: pointer;">
              <i class="fa-solid fa-circle-info"></i>
            </button>
            <button class="btn-icon-danger" title="Delete Entry" data-delete-scan-id="${esc(entry.id)}" style="border: none; background: none; color: var(--red); cursor: pointer;">
              <i class="fa-solid fa-trash-can"></i>
            </button>
          </td>
        </tr>
      `;
    }).join('');

    // Bind handlers instead of embedding data in inline onclick attributes.
    // The old `onclick="alert('...')"` escaped only quotes, so a backslash or
    // newline in a scan summary broke out of the string and into JS.
    body.querySelectorAll('[data-show-details]').forEach(btn => {
      btn.addEventListener('click', () => {
        const row = btn.closest('tr');
        alert(row ? row.dataset.details : '');
      });
    });
    body.querySelectorAll('[data-delete-scan-id]').forEach(btn => {
      btn.addEventListener('click', () => deleteScanRegistryEntry(btn.dataset.deleteScanId));
    });
  } catch(e) {
    console.error("Failed to render scan history table", e);
  }
}

function initScanRegistry() {
  const toggleBtn = document.getElementById('history-toggle');
  const drawer = document.getElementById('history-drawer');
  const closeBtn = document.getElementById('history-drawer-close');
  const backdrop = document.getElementById('history-drawer-backdrop');

  if (toggleBtn && drawer) {
    toggleBtn.addEventListener('click', () => {
      drawer.classList.add('visible');
      renderScanRegistryTable();
      requestAnimationFrame(() => {
        const content = drawer.querySelector('.history-drawer-content');
        if (content) content.style.transform = 'translateX(0)';
      });
    });

    const closeDrawer = () => {
      const content = drawer.querySelector('.history-drawer-content');
      if (content) content.style.transform = 'translateX(100%)';
      setTimeout(() => {
        drawer.classList.remove('visible');
      }, 300);
    };

    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
    if (backdrop) backdrop.addEventListener('click', closeDrawer);
  }

  const clearBtn = document.getElementById('clear-registry-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', clearScanRegistry);
  }

  const filters = document.querySelectorAll('.registry-filters .filter-btn');
  filters.forEach(btn => {
    btn.addEventListener('click', () => {
      filters.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderScanRegistryTable(btn.dataset.filter);
    });
  });

  renderScanRegistryTable();
}

// ═══════════════════════════════════════════════════════════════
// Dashboard statistics
//
// Every figure below is a live count from /api/impact, which derives it from
// the database. This previously added invented baselines to the real counts —
// 124 threats, 38 high-risk cases, 1842 known scam numbers, 53 accounts under
// investigation — so a freshly installed system reported 124 threats detected
// before anyone had scanned anything. Numbers that pad themselves cannot be
// used to argue the platform had an effect, which is the only thing they are
// for.
// ═══════════════════════════════════════════════════════════════
async function loadHomeStats() {
  let m = null;
  try {
    const resp = await apiFetch('/api/impact');
    if (resp.ok) m = await resp.json();
  } catch (e) {
    console.error('Failed to load impact metrics', e);
  }
  if (!m) return;

  const targets = [
    ['stat-threats-today',  m.scans_flagged],
    ['stat-high-risk',      m.campaigns_identified],
    ['stat-scam-numbers',   m.indicators_actionable],
    ['stat-investigation',  m.cases_open],
    ['stat-entities',       m.entities_tracked],
    ['stat-evidence',       m.evidence_entries],
  ];

  for (const [id, value] of targets) {
    const el = document.getElementById(id);
    if (el && typeof value === 'number') animateValue(el, 0, value, 900);
  }

  // A brand-new deployment legitimately reads zero across the board. Say so,
  // rather than letting an empty dashboard look broken.
  const empty = document.getElementById('stats-empty-note');
  if (empty) {
    empty.style.display = (m.scans_total === 0) ? 'block' : 'none';
  }
}

// ═══════════════════════════════════════════════════════════════
// Auto-Init on DOMContentLoaded
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  // Init Theme and Registry Toggle logic
  initThemeToggler();
  initScanRegistry();

  // Load dynamic stats if on home dashboard
  if (document.getElementById('stat-threats-today')) {
    loadHomeStats();
  }

  // Detect which page we're on and init the right detector
  if (document.getElementById('betting-drop-zone')) initBettingDetector();
  if (document.getElementById('deepfake-drop-zone')) initDeepfakeDetector();
  if (document.getElementById('cc-drop-zone')) initCustomerCareDetector();
  if (document.getElementById('invest-text-input')) initInvestmentDetector();
  if (document.getElementById('threat-feed-ticker')) initLiveThreatFeed();
});

// ── Proactive Social Media Threat Feed ──────────────────────
async function fetchLiveThreatFeed() {
  const ticker = document.getElementById('threat-feed-ticker');
  if (!ticker) return;

  try {
    const resp = await apiFetch('/auth/api/alerts');
    if (!resp.ok) return;
    const alerts = await resp.json();

    if (alerts.length === 0) {
      ticker.innerHTML = `
        <div class="feed-initializing">
          <i class="fa-solid fa-satellite-dish"></i> Feeds scanning online. No new threat signatures flagged.
        </div>
      `;
      return;
    }

    // Keep track of existing alert IDs to avoid flashing re-renders if nothing changed
    const currentIds = Array.from(ticker.querySelectorAll('.ticker-item')).map(el => el.dataset.id);
    const newIds = alerts.map(a => String(a.id));
    
    // Simple equality check
    if (JSON.stringify(currentIds) === JSON.stringify(newIds)) {
      return; // No change, skip DOM manipulation
    }

    ticker.innerHTML = alerts.map(entry => {
      let badgeClass = 'alert-badge-investment';
      const cat = (entry.category || '').toLowerCase();
      if (cat.includes('betting')) badgeClass = 'alert-badge-betting';
      else if (cat.includes('deepfake')) badgeClass = 'alert-badge-deepfake';
      else if (cat.includes('customer') || cat.includes('support') || cat.includes('care')) badgeClass = 'alert-badge-custcare';
      
      const ts = String(entry.timestamp || '');
      const timePart = ts.split(' ')[1] || ts;

      // Provenance. The collector prefixes every source string with [LIVE] or
      // [SIMULATED]; a record that carries neither predates the change and is
      // shown as UNVERIFIED rather than silently assumed to be real.
      // Presenting demonstration data as an observation is the one thing this
      // feed must never do.
      const rawSource = String(entry.source || '');
      let provenance = 'UNVERIFIED', provClass = 'prov-unknown';
      if (rawSource.startsWith('[LIVE]')) {
        provenance = 'LIVE'; provClass = 'prov-live';
      } else if (rawSource.startsWith('[SIMULATED]')) {
        provenance = 'SIMULATED'; provClass = 'prov-sim';
      }
      const cleanSource = rawSource.replace(/^\[(LIVE|SIMULATED)\]\s*/, '');

      // Everything below is attacker-influenced: source/content/category come
      // from third-party threat feeds and pages found on the open web.
      return `
        <div class="ticker-item ${provClass}-row" data-id="${esc(entry.id)}">
          <div class="alert-left">
            <span class="alert-time">${esc(timePart)}</span>
            <span class="prov-chip ${provClass}" title="Data provenance">${esc(provenance)}</span>
            <span class="alert-source">${esc(cleanSource)}</span>
            <span class="alert-badge-pill ${badgeClass}">${esc(entry.category)}</span>
            <span class="alert-content" title="${esc(entry.content)}">${esc(entry.content)}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 12px;">
            <span class="alert-score-gauge">
              <i class="fa-solid fa-triangle-exclamation"></i> ${esc(entry.risk_score)}% Risk
            </span>
            <button class="alert-action-btn" data-block-alert-id="${esc(entry.id)}">
              <i class="fa-solid fa-gavel"></i> Block & Takedown
            </button>
          </div>
        </div>
      `;
    }).join('');

    // Wire the buttons up here rather than with an inline onclick, so the id
    // never has to survive a trip through an HTML attribute as JS source.
    ticker.querySelectorAll('[data-block-alert-id]').forEach(btn => {
      btn.addEventListener('click', () => blockCrawlerAlert(btn.dataset.blockAlertId));
    });

  } catch (e) {
    console.error("Failed to fetch threat feed alerts", e);
  }
}

async function blockCrawlerAlert(alertId) {
  if (!confirm('Are you sure you want to block this threat and generate a compliance takedown order?')) return;
  
  showLoading('Processing Takedown Directive...', 'Marking source as blocked & generating Section 79(3)(b) order');
  try {
    const resp = await apiFetch(`/auth/api/alerts/${alertId}/block`, {
      method: 'POST'
    });
    const result = await resp.json();
    hideLoading();
    
    if (resp.ok && result.success) {
      showToast('Threat blocked! Legal takedown compliance order compiled.');
      
      // Update scan history drawer table
      renderScanRegistryTable();
      
      // Refresh home stats numbers
      loadHomeStats();
      
      // Refresh live crawler feed
      fetchLiveThreatFeed();
      
      // Instantly open the compliance PDF notice in a new tab
      window.open(`/auth/api/scans/${result.scan_id}/takedown/pdf`, '_blank');
    } else {
      showToast(result.error || 'Failed to block alert', 'error');
    }
  } catch (e) {
    hideLoading();
    showToast('Network error: ' + e.message, 'error');
  }
}

function initLiveThreatFeed() {
  const ticker = document.getElementById('threat-feed-ticker');
  if (!ticker) return;
  
  // Fetch immediately
  fetchLiveThreatFeed();
  
  // Poll every 30s — matching the crawler's own sweep interval. Polling at
  // 8s produced ~450 requests/hour per tab and exhausted the rate limit.
  setInterval(fetchLiveThreatFeed, 30000);
}
