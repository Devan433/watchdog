document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const formError = document.getElementById('form-error');

    const heroSection = document.getElementById('hero-section');
    const scanningSection = document.getElementById('scanning-section');
    const resultsSection = document.getElementById('results-section');

    const scanStepsContainer = document.querySelector('.scan-steps');

    const steps = [
        "Resolving domain and checking HTTPS",
        "Analyzing security headers",
        "Probing sensitive endpoints",
        "Evaluating CORS policy",
        "Checking cookie security",
        "Scanning for leaked secrets",
        "Testing authentication routes"
    ];

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();

        if (!url) {
            showError("Please enter a valid URL.");
            return;
        }

        formError.classList.add('hidden');
        startScanUI();

        try {
            const [scanData] = await Promise.all([
                fetchScanData(url),
                simulateScanningSteps()
            ]);

            if (scanData.error) {
                showError(scanData.error);
                resetUI();
            } else {
                renderResults(scanData);
            }
        } catch (error) {
            showError(error.message || "Failed to connect to the scanning service.");
            resetUI();
        }
    });

    function showError(msg) {
        formError.textContent = msg;
        formError.classList.remove('hidden');
    }

    function startScanUI() {
        heroSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
        scanningSection.classList.remove('hidden');

        scanStepsContainer.innerHTML = '';
        steps.forEach((step, index) => {
            const el = document.createElement('div');
            el.className = 'scan-step';
            el.id = `step-${index}`;
            el.innerHTML = `
                <svg class="step-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                </svg>
                <span>${escapeHtml(step)}</span>
            `;
            scanStepsContainer.appendChild(el);
        });
    }

    function resetUI() {
        scanningSection.classList.add('hidden');
        heroSection.classList.remove('hidden');
    }

    async function simulateScanningSteps() {
        for (let i = 0; i < steps.length; i++) {
            const el = document.getElementById(`step-${i}`);
            if (!el) continue;
            el.classList.add('active');

            const waitTime = Math.floor(Math.random() * 800) + 400;
            await new Promise(r => setTimeout(r, waitTime));

            el.classList.remove('active');
            el.classList.add('done');
            el.querySelector('.step-icon').innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>';
            el.querySelector('.step-icon').style.color = 'var(--text-primary)';
        }
    }

    async function fetchScanData(url) {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || `Scan failed (HTTP ${res.status})`);
        }
        return data;
    }

    function isActionableFinding(f) {
        if (f.passed) return false;
        if (f.severity === 'info') return false;
        if (f.confidence === 'low') return false;
        return true;
    }

    function renderResults(data) {
        scanningSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');

        document.getElementById('score-value').textContent = data.score;
        document.getElementById('score-grade').textContent = `Grade: ${data.grade}`;

        const statusEl = document.getElementById('deployment-status');
        if (data.score >= 90) {
            statusEl.textContent = "Ready for Deployment";
            statusEl.className = "status-badge status-ready";
        } else if (data.score >= 60) {
            statusEl.textContent = "Needs Review";
            statusEl.className = "status-badge status-review";
        } else {
            statusEl.textContent = "High Risk";
            statusEl.className = "status-badge status-risk";
        }

        document.getElementById('stat-critical').textContent = data.breakdown.critical;
        document.getElementById('stat-high').textContent = data.breakdown.high;
        document.getElementById('stat-medium').textContent = data.breakdown.medium;
        document.getElementById('stat-low').textContent = data.breakdown.low;

        const allFindings = [];
        for (const cat in data.categories) {
            allFindings.push(...data.categories[cat]);
        }

        const checklistContainer = document.getElementById('checklist-container');
        checklistContainer.innerHTML = '';

        const checklistRules = [
            { match: f => f.check_name === 'HTTPS Enforcement' && f.passed, label: 'HTTPS Enabled' },
            { match: f => f.check_name === 'Content-Security-Policy' && f.passed, label: 'Content Security Policy' },
            { match: f => f.category === 'cookies' && f.check_name.includes('HttpOnly') && f.passed && f.severity !== 'info', label: 'Secure Cookies' },
            { match: f => f.category === 'cookies' && !f.passed && f.severity === 'high', label: 'Secure Cookies', passed: false },
            { match: f => f.category === 'secret_leak' && f.passed, label: 'No Leaked Secrets' },
            { match: f => f.category === 'secret_leak' && !f.passed && f.severity !== 'info', label: 'No Leaked Secrets', passed: false },
        ];

        const checklistState = {};
        checklistRules.forEach(rule => {
            allFindings.forEach(f => {
                if (rule.match(f)) {
                    const passed = rule.passed !== undefined ? rule.passed : f.passed;
                    if (!(rule.label in checklistState) || (checklistState[rule.label] && passed === false)) {
                        checklistState[rule.label] = passed;
                    }
                }
            });
        });

        Object.entries(checklistState).forEach(([label, passed]) => {
            checklistContainer.innerHTML += renderChecklistItem(label, passed);
        });

        const failedFindings = allFindings.filter(isActionableFinding).sort((a, b) => {
            const weights = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
            return weights[b.severity] - weights[a.severity];
        });

        const lowConfidenceFindings = allFindings.filter(f => !f.passed && (f.severity === 'info' || f.confidence === 'low'));

        const recsContainer = document.getElementById('recommendations-list');
        recsContainer.innerHTML = '';
        if (failedFindings.length === 0) {
            recsContainer.innerHTML = '<li style="color: var(--text-secondary); list-style: none;">No major issues found. You are good to go!</li>';
        } else {
            const uniqueFixes = new Set();
            failedFindings.forEach(f => {
                if (!uniqueFixes.has(f.fix) && uniqueFixes.size < 5) {
                    uniqueFixes.add(f.fix);
                    const li = document.createElement('li');
                    li.textContent = f.fix;
                    recsContainer.appendChild(li);
                }
            });
        }

        const findingsContainer = document.getElementById('findings-container');
        findingsContainer.innerHTML = '';
        if (failedFindings.length === 0 && lowConfidenceFindings.length === 0) {
            findingsContainer.innerHTML = '<div style="color: var(--text-secondary);">No issues to display.</div>';
        } else {
            failedFindings.forEach(f => {
                findingsContainer.appendChild(renderFindingCard(f, false));
            });
            lowConfidenceFindings.forEach(f => {
                findingsContainer.appendChild(renderFindingCard(f, true));
            });
        }

        const routesContainer = document.getElementById('routes-container');
        routesContainer.innerHTML = '';
        const endpointFindings = allFindings.filter(f => f.category === 'endpoints' && !f.passed && f.severity !== 'info');

        if (endpointFindings.length === 0) {
            routesContainer.innerHTML = '<span class="route-chip">No exposed routes found</span>';
        } else {
            endpointFindings.forEach(f => {
                const routeMatch = f.check_name.replace("Exposed Endpoint: ", "").replace("Restricted Endpoint: ", "");
                const isRisky = f.severity === 'critical' || f.severity === 'high';
                const chip = document.createElement('span');
                chip.className = `route-chip${isRisky ? ' risky' : ''}`;
                chip.textContent = routeMatch;
                routesContainer.appendChild(chip);
            });
        }
    }

    function renderFindingCard(f, isLowConfidence) {
        const card = document.createElement('div');
        card.className = `finding-card${isLowConfidence ? ' finding-low-confidence' : ''}`;

        const confidenceBadge = f.confidence && f.confidence !== 'high'
            ? `<span class="confidence-badge">${escapeHtml(f.confidence)} confidence</span>`
            : '';

        card.innerHTML = `
            <div class="finding-header">
                <span class="severity-badge bg-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
                <span class="finding-title">${escapeHtml(f.check_name)}</span>
                ${confidenceBadge}
            </div>
            <div class="finding-body">
                <p><strong>Issue:</strong> ${escapeHtml(f.detail)}</p>
                <p><strong>Recommended Fix:</strong> ${escapeHtml(f.fix)}</p>
                ${f.evidence ? `<div class="finding-evidence">${escapeHtml(f.evidence)}</div>` : ''}
                ${f.fix_prompt ? `<button type="button" class="copy-prompt-btn">Copy AI Fix Prompt</button>` : ''}
            </div>
        `;

        if (f.fix_prompt) {
            const btn = card.querySelector('.copy-prompt-btn');
            btn.addEventListener('click', () => copyFixPrompt(f.fix_prompt, btn));
        }

        return card;
    }

    async function copyFixPrompt(text, btn) {
        try {
            await navigator.clipboard.writeText(text);
            const original = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = original; }, 2000);
        } catch {
            btn.textContent = 'Copy failed';
        }
    }

    function renderChecklistItem(label, passed) {
        const icon = passed
            ? `<svg class="checklist-icon icon-pass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`
            : `<svg class="checklist-icon icon-fail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;

        return `<li class="checklist-item" data-label="${escapeHtml(label)}" data-passed="${passed}">${icon} <span>${escapeHtml(label)}</span></li>`;
    }

    function escapeHtml(unsafe) {
        return (unsafe || '').toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
