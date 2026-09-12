const API_BASE = '/api';
let activeTab = 'message';
let selectedFile = null;

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    checkHealth();
    fetchHistory();

    const msgInput = document.getElementById('messageInput');
    if (msgInput) {
        msgInput.addEventListener('input', () => {
            document.getElementById('msgCharCount').textContent = msgInput.value.length;
        });
    }
});

// Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem('scamshield_theme');
    const themeIcon = document.getElementById('themeIcon');

    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        if (themeIcon) themeIcon.textContent = '☀️';
    } else {
        document.body.classList.remove('light-theme');
        if (themeIcon) themeIcon.textContent = '🌙';
    }
}

function toggleTheme() {
    const isLight = document.body.classList.toggle('light-theme');
    const themeIcon = document.getElementById('themeIcon');

    if (isLight) {
        localStorage.setItem('scamshield_theme', 'light');
        if (themeIcon) themeIcon.textContent = '☀️';
    } else {
        localStorage.setItem('scamshield_theme', 'dark');
        if (themeIcon) themeIcon.textContent = '🌙';
    }
}

// Health check endpoint verification
async function checkHealth() {
    const statusPill = document.getElementById('backendStatusPill');
    if (!statusPill) return;

    try {
        const res = await fetch(`${API_BASE}/health`);
        if (res.ok) {
            const data = await res.json();
            statusPill.classList.add('online');
            statusPill.classList.remove('offline');
            statusPill.querySelector('.status-text').textContent = `System Ready (${data.ai_service || 'Active'})`;
        } else {
            throw new Error('Health check failed');
        }
    } catch (err) {
        statusPill.classList.add('offline');
        statusPill.classList.remove('online');
        statusPill.querySelector('.status-text').textContent = 'Backend Offline';
    }
}

// Tab Switching
function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        const isActive = btn.id === `tab-${tab}`;
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    document.querySelectorAll('.tab-panel').forEach(panel => {
        const isSelected = panel.id === `panel-${tab}`;
        panel.classList.toggle('active', isSelected);
        panel.hidden = !isSelected;
    });

    hideAlert();
}

// Dropzone & File Handlers
function handleDragOver(e) {
    e.preventDefault();
    document.getElementById('dropzone')?.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    document.getElementById('dropzone')?.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    document.getElementById('dropzone')?.classList.remove('drag-over');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        processFile(e.dataTransfer.files[0]);
    }
}

function handleFileSelect(e) {
    if (e.target.files && e.target.files[0]) {
        processFile(e.target.files[0]);
    }
}

function processFile(file) {
    const validTypes = ['image/png', 'image/jpeg', 'image/webp'];
    if (!validTypes.includes(file.type)) {
        showAlert('Unsupported file type. Please upload PNG, JPEG, or WebP.');
        return;
    }
    if (file.size > 8 * 1024 * 1024) {
        showAlert('File size exceeds 8 MB limit.');
        return;
    }

    selectedFile = file;
    const reader = new FileReader();
    reader.onload = (e) => {
        document.getElementById('imagePreview').src = e.target.result;
        document.getElementById('dropzoneContent').classList.add('hidden');
        document.getElementById('previewContainer').classList.remove('hidden');
    };
    reader.readAsDataURL(file);
    hideAlert();
}

function removeImage(e) {
    if (e) e.stopPropagation();
    selectedFile = null;
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';

    document.getElementById('imagePreview').src = '';
    document.getElementById('dropzoneContent').classList.remove('hidden');
    document.getElementById('previewContainer').classList.add('hidden');
}

// Main Action: Trigger Analysis
async function performAnalysis() {
    hideAlert();
    const btn = document.getElementById('analyzeBtn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');

    let endpoint = '';
    let options = {};

    if (activeTab === 'message') {
        const text = document.getElementById('messageInput').value.trim();
        if (!text) { showAlert('Message text must not be empty.'); return; }
        endpoint = `${API_BASE}/analyze/message`;
        options = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        };
    } else if (activeTab === 'url') {
        const url = document.getElementById('urlInput').value.trim();
        if (!url) { showAlert('URL string must not be empty.'); return; }
        endpoint = `${API_BASE}/analyze/url`;
        options = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        };
    } else if (activeTab === 'screenshot') {
        if (!selectedFile) { showAlert('Please select or drop a screenshot file first.'); return; }
        endpoint = `${API_BASE}/analyze/screenshot`;
        const formData = new FormData();
        formData.append('file', selectedFile);
        options = { method: 'POST', body: formData };
    }

    // UI Loading State
    btn.disabled = true;
    btnText.textContent = 'Analyzing Threat...';
    btnLoader.classList.remove('hidden');

    try {
        const response = await fetch(endpoint, options);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Analysis request failed.');
        }

        renderResult(data);
        fetchHistory(); // Refresh history panel
    } catch (err) {
        showAlert(err.message);
    } finally {
        btn.disabled = false;
        btnText.textContent = 'RUN DIAGNOSTIC';
        btnLoader.classList.add('hidden');
    }
}

// Render Results with Gauge & Animations
function renderResult(data) {
    const section = document.getElementById('resultSection');
    section.classList.remove('hidden');

    // Score Animation
    const targetScore = data.risk_score || 0;
    animateScoreDisplay(targetScore);

    // Gauge Arc Calculation
    const arc = document.getElementById('gaugeArc');
    const circumference = 2 * Math.PI * 50; // r=50 -> ~314
    const offset = circumference - (targetScore / 100) * circumference;
    arc.style.strokeDashoffset = offset;

    // Dynamic Level Badges & Colors
    const level = (data.risk_level || 'LOW').toUpperCase();
    const badge = document.getElementById('riskLevelBadge');
    badge.textContent = `${level} RISK`;
    badge.className = `badge badge-${level.toLowerCase()}`;

    let strokeColor = 'var(--level-low)';
    if (level === 'MEDIUM') strokeColor = 'var(--level-medium)';
    if (level === 'HIGH') strokeColor = 'var(--level-high)';
    if (level === 'CRITICAL') strokeColor = 'var(--level-critical)';
    arc.style.stroke = strokeColor;

    document.getElementById('categoryConfidence').textContent = `Confidence: ${(data.category_confidence || 'High').toUpperCase()}`;
    document.getElementById('scamCategoryTitle').textContent = data.category || 'Uncategorized Event';
    document.getElementById('analysisTime').textContent = new Date(data.created_at || Date.now()).toLocaleTimeString();

    // OCR Text Display
    const ocrContainer = document.getElementById('ocrTextContainer');
    if (data.extracted_text) {
        document.getElementById('ocrExtractedText').textContent = data.extracted_text;
        ocrContainer.classList.remove('hidden');
    } else {
        ocrContainer.classList.add('hidden');
    }

    // Indicators Chips
    const indGrid = document.getElementById('indicatorsList');
    indGrid.innerHTML = '';
    if (data.indicators && data.indicators.length > 0) {
        data.indicators.forEach(ind => {
            const chip = document.createElement('div');
            chip.className = 'chip';
            chip.innerHTML = `<span>${ind.description || ind.name}</span> <span class="weight-tag">+${ind.weight}</span>`;
            indGrid.appendChild(chip);
        });
    } else {
        indGrid.innerHTML = '<span class="chip">No significant scam indicators detected</span>';
    }

    // AI Explanation & Recommendations
    document.getElementById('explanationText').textContent = data.explanation || 'No detailed explanation provided.';

    const recList = document.getElementById('recommendationsList');
    recList.innerHTML = '';
    if (data.recommendations && data.recommendations.length > 0) {
        data.recommendations.forEach(rec => {
            const li = document.createElement('li');
            li.innerHTML = `<span>🛡️</span> <span>${rec}</span>`;
            recList.appendChild(li);
        });
    }

    if (data.disclaimer) {
        document.getElementById('disclaimerText').textContent = data.disclaimer;
    }

    // Smooth Scroll
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Smooth Number Counter Animation
function animateScoreDisplay(target) {
    const scoreElem = document.getElementById('scoreValue');
    let current = 0;
    const duration = 1000;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = target / steps;

    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            scoreElem.textContent = target;
            clearInterval(timer);
        } else {
            scoreElem.textContent = Math.floor(current);
        }
    }, stepTime);
}

// History Fetching
async function fetchHistory() {
    try {
        const res = await fetch(`${API_BASE}/history?limit=10`);
        if (!res.ok) return;
        const history = await res.json();
        const container = document.getElementById('historyContainer');

        if (!history || history.length === 0) {
            container.innerHTML = '<p class="empty-log">No past scans recorded yet.</p>';
            return;
        }

        container.innerHTML = '';
        history.forEach(item => {
            const row = document.createElement('div');
            row.className = 'history-row';
            row.onclick = () => loadHistoryDetail(item.id);

            const iconMap = { message: '💬', url: '🌐', screenshot: '🖼️' };
            const icon = iconMap[item.input_type] || '🔍';

            row.innerHTML = `
                <div>
                    <strong>${icon} [${item.input_type.toUpperCase()}]</strong> ${item.scam_category || 'Uncategorized'}
                </div>
                <div>
                    <span class="badge badge-${(item.risk_level || 'low').toLowerCase()}">${item.risk_level} (${item.risk_score})</span>
                </div>
            `;
            container.appendChild(row);
        });
    } catch (e) {
        // Silent failure for history
    }
}

async function loadHistoryDetail(id) {
    try {
        const res = await fetch(`${API_BASE}/history/${id}`);
        if (res.ok) {
            const data = await res.json();
            renderResult(data);
        }
    } catch (e) {
        showAlert('Could not load scan detail.');
    }
}

// Helper Notifications
function showAlert(msg) {
    const alert = document.getElementById('inlineAlert');
    if (alert) {
        alert.textContent = `⚠️ ${msg}`;
        alert.style.color = 'var(--level-critical)';
        alert.style.marginTop = '1rem';
        alert.classList.remove('hidden');
    }
}

function hideAlert() {
    const alert = document.getElementById('inlineAlert');
    if (alert) alert.classList.add('hidden');
}