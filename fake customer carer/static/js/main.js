// SHIELD ENGINE - INTERACTIVE CONTROLS

// 1. Drag & Drop Upload Zone Configuration
const dropzone = document.getElementById('dropzone');

if (dropzone) {
    // Prevent defaults for drag-and-drop events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Highlight dropzone on drag enter/over
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => {
            dropzone.classList.add('dragover');
        }, false);
    });

    // Remove highlight on drag leave/drop
    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => {
            dropzone.classList.remove('dragover');
        }, false);
    });

    // Handle dropped files
    dropzone.addEventListener('drop', handleDrop, false);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        const fileInput = document.getElementById('image_file');
        
        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelect(fileInput);
        }
    }
}

// Open file dialog when clicking dropzone
function triggerFileSelect() {
    document.getElementById('image_file').click();
}

// Display file details and thumbnail preview
function handleFileSelect(input) {
    if (input.files && input.files[0]) {
        const file = input.files[0];
        
        // Populate metadata
        document.getElementById('preview-filename').textContent = file.name;
        
        const sizeKB = (file.size / 1024).toFixed(1);
        document.getElementById('preview-filesize').textContent = `${sizeKB} KB`;
        
        // Load Image Thumbnail Preview
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('preview-img').src = e.target.result;
            document.getElementById('preview-container').classList.remove('d-none');
        };
        reader.readAsDataURL(file);
    }
}

// Clear currently selected image file
function clearFileSelection() {
    document.getElementById('image_file').value = "";
    document.getElementById('preview-container').classList.add('d-none');
}

// 2. Tab Navigation - Set Input Type
function setInputType(type) {
    document.getElementById('input_type').value = type;
    // Clear URL error/preview when switching away from URL tab
    if (type !== 'url') {
        clearUrlPreview();
    }
}

// 3a. URL Preview — debounced auto-load as user types
let _urlDebounceTimer = null;
function debounceUrlPreview(value) {
    clearTimeout(_urlDebounceTimer);
    if (!value || value.trim().length < 10) return;
    _urlDebounceTimer = setTimeout(() => loadUrlPreview(value.trim()), 900);
}

// 3b. Load and display a preview of the entered image URL
function loadUrlPreview(url) {
    if (!url || !url.startsWith('http')) return;

    const previewContainer = document.getElementById('url-preview-container');
    const previewImg       = document.getElementById('url-preview-img');
    const errorMsg         = document.getElementById('url-error-msg');
    const statusText       = document.getElementById('url-preview-status');

    // Hide error, show preview container
    errorMsg.classList.add('d-none');
    previewContainer.classList.remove('d-none');
    if (statusText) {
        statusText.innerHTML = `<span class="spinner-border spinner-border-sm me-1 text-cyber-blue"></span> Resolving URL...`;
    }

    // Reset image src
    previewImg.src = '';

    fetch(`/resolve_url?url=${encodeURIComponent(url)}`)
        .then(response => {
            if (!response.ok) throw new Error('Failed to resolve URL');
            return response.json();
        })
        .then(data => {
            if (data.success && data.resolved_url) {
                previewImg.src = data.resolved_url;
                if (statusText) {
                    statusText.innerHTML = `<i class="fa-solid fa-circle-check me-1"></i> Image resolved — ready to scan`;
                }
            } else {
                throw new Error(data.error || 'No preview image found');
            }
        })
        .catch(err => {
            console.error(err);
            handleUrlPreviewError();
        });
}

// 3c. Clear URL preview
function clearUrlPreview() {
    document.getElementById('url-preview-container').classList.add('d-none');
    document.getElementById('url-error-msg').classList.add('d-none');
    const img = document.getElementById('url-preview-img');
    if (img) img.src = '#';
}

// 3d. Handle URL image load error
function handleUrlPreviewError() {
    document.getElementById('url-preview-container').classList.add('d-none');
    document.getElementById('url-error-msg').classList.remove('d-none');
    document.getElementById('url-error-text').textContent =
        'Could not load image from that URL. Make sure it\'s a direct image link (ending in .jpg, .png, .jpeg, or .webp).';
}

// 4. Form Validation + Loading Overlay (replaces the old showLoadingOverlay)
function validateAndShowOverlay(event) {
    const inputType     = document.getElementById('input_type').value;
    const loadingOverlay = document.getElementById('loadingOverlay');

    if (inputType === 'image') {
        const fileInput = document.getElementById('image_file');
        if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            event.preventDefault();
            showToast('No Image Selected', 'Please select or drag an image file before scanning.');
            return false;
        }
    } else if (inputType === 'url') {
        const urlInput = document.getElementById('image_url');
        const url = urlInput ? urlInput.value.trim() : '';
        if (!url || !url.startsWith('http')) {
            event.preventDefault();
            showToast('No URL Entered', 'Please enter a valid image URL (starting with http:// or https://) before scanning.');
            return false;
        }
    } else if (inputType === 'text') {
        const textArea = document.getElementById('pasted_text');
        if (!textArea || !textArea.value.trim()) {
            event.preventDefault();
            showToast('No Text Entered', 'Please paste some advertisement text before scanning.');
            return false;
        }
    }

    // All good — show the overlay
    if (loadingOverlay) {
        loadingOverlay.classList.remove('d-none');
    }

    const statuses = [
        { text: "INITIALIZING SHIELD CYBER ANALYSIS SYSTEM...", progress: 15 },
        { text: "FETCHING & PREPARING IMAGE FOR ANALYSIS...", progress: 28 },
        { text: "LOADING PADDLEOCR WEIGHTS & RUNNING INFERENCE...", progress: 42 },
        { text: "EXTRACTING TEXT BLOCKS AND CONFIDENCE MATRICES...", progress: 56 },
        { text: "RUNNING TOLL-FREE AND CELL PHONE REGEX ANALYSIS...", progress: 68 },
        { text: "PROCESSING SPACY NLP NAMED ENTITY RECOGNITION (NER)...", progress: 80 },
        { text: "CROSS-REFERENCING OFFICIAL DB AND THREAT INTELLIGENCE...", progress: 92 },
        { text: "COMPILING THREAT SCORES AND INVESTIGATION REPORTS...", progress: 98 }
    ];

    let currentStep = 0;
    const progressEl = document.getElementById('loader-progress');
    const textEl     = document.getElementById('loader-status');

    const interval = setInterval(() => {
        if (currentStep < statuses.length) {
            const step = statuses[currentStep];
            if (textEl)     textEl.textContent       = step.text;
            if (progressEl) progressEl.style.width   = `${step.progress}%`;
            currentStep++;
        } else {
            clearInterval(interval);
        }
    }, 1400);

    return true;
}


// 4. Utility: Copy to Clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast("Phone Number Copied", "Number copied to clipboard buffer.");
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

// 5. Dynamic Toast Alert Generator
function showToast(title, message) {
    // Check if container exists, else create it
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(container);
    }

    const toastId = `toast-${Date.now()}`;
    const toastHTML = `
        <div id="${toastId}" class="toast toast-cyber text-light border border-secondary border-opacity-20 rounded-3" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-dark bg-opacity-80 text-light border-bottom border-secondary border-opacity-10 py-2">
                <i class="fa-solid fa-shield-halved text-cyber-blue me-2"></i>
                <strong class="me-auto font-outfit">${title}</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body bg-dark bg-opacity-20 font-monospace small py-3">
                ${message}
            </div>
        </div>
    `;

    container.insertAdjacentHTML('beforeend', toastHTML);
    const toastEl = document.getElementById(toastId);
    const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
    bsToast.show();

    // Clean up DOM after hide
    toastEl.addEventListener('hidden.bs.toast', () => {
        toastEl.remove();
    });
}

// 6. Interactive AJAX Threat Reporting
function submitScamReport(phoneNumber) {
    const reportBtn = document.getElementById('report-scam-btn');
    if (!reportBtn) return;

    // Loading State
    const originalContent = reportBtn.innerHTML;
    reportBtn.disabled = true;
    reportBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> REPORTING...`;

    fetch('/report_scam', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ phone: phoneNumber })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Update Reports Count
            const countEl = document.getElementById('prev-reports-count');
            if (countEl) countEl.textContent = data.reports;

            // Trigger visual updates on the page if they were returned (meaning session matches)
            if (data.risk_score !== undefined) {
                // Update Risk Score value text
                const riskValEl = document.getElementById('risk-score-value');
                if (riskValEl) riskValEl.textContent = data.risk_score;

                // Update Risk Circle gauge offset
                const riskCircle = document.querySelector('.fill-risk-safe, .fill-risk-suspicious, .fill-risk-high_risk, .fill-risk-critical');
                if (riskCircle) {
                    const offset = 314.16 - (314.16 * data.risk_score) / 100;
                    riskCircle.style.strokeDashoffset = offset;

                    // Update circle class color mapping based on new severity
                    riskCircle.className.baseVal = `gauge-ring-fill fill-risk-${data.severity.toLowerCase().replace(' ', '_')}`;
                }

                // Update Severity Badge styling and text
                const badgeTextEl = document.querySelector('.severity-badge');
                const badgeGlowEl = document.querySelector('.severity-badge-glow');
                
                if (badgeTextEl && badgeGlowEl) {
                    const sevLower = data.severity.toLowerCase().replace(' ', '_');
                    
                    // Reset class names
                    badgeTextEl.className = `severity-badge px-4 py-2 rounded-pill font-outfit fw-bold severity-text-${sevLower}`;
                    badgeGlowEl.className = `severity-badge-glow severity-${sevLower}`;
                    
                    // Set icons and text
                    let iconClass = 'fa-circle-exclamation';
                    if (data.severity === 'Safe') iconClass = 'fa-circle-check';
                    else if (data.severity === 'Suspicious') iconClass = 'fa-circle-question';
                    else if (data.severity === 'High Risk') iconClass = 'fa-triangle-exclamation';
                    
                    badgeTextEl.innerHTML = `<i class="fa-solid ${iconClass} me-2"></i>${data.severity.toUpperCase()}`;
                }

                // Update Recommendation Box text and border
                const recTextEl = document.getElementById('recommendation-text');
                const recBoxEl = document.getElementById('recommendation-box');
                if (recTextEl && recBoxEl) {
                    recTextEl.textContent = data.recommendation;
                    
                    const sevLower = data.severity.toLowerCase().replace(' ', '_');
                    let alertType = 'danger';
                    if (data.severity === 'Safe') alertType = 'success';
                    else if (data.severity === 'Suspicious') alertType = 'warning';
                    
                    recBoxEl.className = `alert alert-${alertType} border-secondary border-opacity-10 bg-glass-alert bg-severity-overlay-${sevLower} rounded-4 p-3 mb-0`;
                }

                // Update Reasons List
                const reasonsListEl = document.getElementById('reasons-list');
                if (reasonsListEl && data.reasons) {
                    reasonsListEl.innerHTML = '';
                    data.reasons.forEach(reason => {
                        let icon = 'fa-circle-dot';
                        let colorClass = '';
                        
                        if (reason.includes('CRITICAL')) {
                            icon = 'fa-triangle-exclamation text-danger';
                        } else if (reason.includes('Verified Match')) {
                            icon = 'fa-circle-check text-success';
                        }
                        
                        const li = document.createElement('li');
                        li.className = 'd-flex align-items-start mb-3';
                        li.innerHTML = `
                            <span class="text-cyber-orange me-3 mt-1">
                                <i class="fa-solid ${icon}"></i>
                            </span>
                            <span class="text-light font-outfit">${reason}</span>
                        `;
                        reasonsListEl.appendChild(li);
                    });
                }
            }

            // Show Toast & Set button to success state
            showToast("Scam Database Updated", `Phone number ${phoneNumber} logged in threat database.`);
            
            reportBtn.className = "btn btn-success px-4 py-2 font-monospace rounded-pill text-uppercase";
            reportBtn.innerHTML = `<i class="fa-solid fa-circle-check me-2"></i> Reported Successfully`;
        } else {
            throw new Error(data.error || 'Failed reporting scam');
        }
    })
    .catch(err => {
        console.error('Scam reporting error: ', err);
        showToast("Reporting Failed", "Could not submit report to local threat database.");
        reportBtn.disabled = false;
        reportBtn.innerHTML = originalContent;
    });
}
