document.addEventListener('DOMContentLoaded', () => {
    // --- TAB SWITCHING ---
    const tabs = document.querySelectorAll('.tab');
    const inputSections = {
        'url': document.getElementById('url-input'),
        'email': document.getElementById('email-input'),
        'file': document.getElementById('file-input')
    };
    const resultContainer = document.getElementById('result-container');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.getAttribute('data-tab');
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            Object.keys(inputSections).forEach(key => {
                inputSections[key].style.display = key === tabName ? 'flex' : 'none';
            });
            resultContainer.innerHTML = '';
        });
    });

    // --- SCAN LOGIC ---
    const scanningState = document.getElementById('scanning-state');
    const showLoading = (show) => {
        scanningState.style.display = show ? 'flex' : 'none';
        if (show) resultContainer.innerHTML = '';
    };

    function renderResult(data) {
        const resultContainer = document.getElementById('result-container');
        const verdict = data.verdict;
        
        let labelText = 'PHISHING RISK';
        let displayScore = data.score;
        let verdictText = verdict;
        let badgeColor = '#dc2626';
        let badgeBg = '#fef2f2';
        let badgeBorder = '1px solid #fee2e2';
        let badgeIcon = 'alert-triangle';

        if (verdict === 'Safe' || verdict === 'Likely Safe') {
            badgeColor = '#16a34a';
            badgeBg = '#f0fdf4';
            badgeBorder = '1px solid #dcfce7';
            badgeIcon = 'shield-check';
            verdictText = 'Safe to Open';
        } else if (verdict === 'Suspicious') {
            badgeColor = '#d97706';
            badgeBg = '#fffbeb';
            badgeBorder = '1px solid #fef3c7';
            badgeIcon = 'alert-circle';
            verdictText = 'Suspicious';
        } else if (verdict === 'High Risk' || verdict === 'threat-detected') {
            badgeColor = '#dc2626';
            badgeBg = '#fef2f2';
            badgeBorder = '1px solid #fee2e2';
            badgeIcon = 'alert-triangle';
            verdictText = 'Threat Detected';
        }

        let stepsHtml = '';
        data.steps.forEach(step => {
            let icon = 'alert-triangle';
            let iconColor = '#dc2626';
            if (step.status === 'safe') {
                icon = 'check-circle';
                iconColor = '#16a34a';
            } else if (step.status === 'warning') {
                icon = 'alert-circle';
                iconColor = '#d97706';
            }

            stepsHtml += `
            <div class="resultBox" style="background: #f8fafc; padding: 1.25rem; border-radius: 8px; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 1rem; border: 1px solid #f1f5f9;">
                <i data-lucide="${icon}" style="color: ${iconColor}; width: 24px; height: 24px; flex-shrink: 0;"></i>
                <div>
                    <h4 style="margin: 0; font-size: 1.05rem; font-weight: 700; color: #1e293b;">${step.name}</h4>
                    <p style="margin: 0.15rem 0 0 0; font-size: 0.875rem; color: #64748b;">${step.details}</p>
                </div>
            </div>`;
        });

        const html = `
        <div class="resultWrapper" style="margin-top: 2rem; border: 1px solid #e2e8f0; border-radius: 12px; padding: 2.5rem; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.05); max-width: 850px; margin-left: auto; margin-right: auto;">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 2rem; border-bottom: 1px solid #f1f5f9; padding-bottom: 1.5rem;">
                <div>
                    <h2 style="margin: 0; font-size: 1.5rem; font-weight: 800; color: #0f172a;">Analysis Complete</h2>
                    <p style="margin: 0.25rem 0 0 0; color: #64748b; font-size: 0.9rem;">${new Date().toLocaleString()}</p>
                </div>
                <div style="background: ${badgeBg}; border: ${badgeBorder}; color: ${badgeColor}; padding: 0.4rem 0.8rem; border-radius: 6px; display: flex; align-items: center; gap: 0.35rem; font-weight: 700; font-size: 0.95rem;">
                    <i data-lucide="${badgeIcon}" style="width: 18px; height: 18px;"></i>
                    ${verdictText}
                </div>
            </div>

            <div style="display: flex; justify-content: center; margin: 2rem 0;">
                <div style="position: relative; width: 140px; height: 140px; display: flex; align-items: center; justify-content: center;">
                    <svg viewBox="0 0 36 36" style="width: 100%; height: 100%; transform: rotate(-90deg);">
                        <path stroke="#f1f5f9" stroke-width="2.5" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path id="score-path" stroke="#2563eb" stroke-width="2.5" stroke-linecap="round" fill="none" stroke-dasharray="0, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                    </svg>
                    <div style="position: absolute; display: flex; flex-direction: column; align-items: center; text-align: center;">
                        <span id="score-text" style="font-size: 2.25rem; font-weight: 800; color: #1e293b; line-height: 1;">0</span>
                        <span id="score-label" style="font-size: 0.65rem; font-weight: 800; color: #64748b; letter-spacing: 0.05em; margin-top: 2px;">${labelText}</span>
                    </div>
                </div>
            </div>

            <div class="steps-list">
                ${stepsHtml}
            </div>

            <div style="margin-top: 2rem;">
                <button class="btn btn-primary" style="width: 100%; padding: 0.875rem; font-weight: 700; font-size: 1rem; border-radius: 8px;" onclick="window.location.href='/dashboard'">
                    View Detailed Report
                </button>
            </div>
        </div>`;

        resultContainer.innerHTML = html;
        lucide.createIcons();
        resultContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });

        // Score animation
        const scorePath = document.getElementById('score-path');
        const scoreText = document.getElementById('score-text');
        
        let strokeColor = '#16a34a'; // Default safe green
        if (displayScore >= 51) strokeColor = '#dc2626'; // High risk red
        else if (displayScore >= 31) strokeColor = '#f59e0b'; // Suspicious orange

        let current = 0;
        const duration = 1200;
        const start = performance.now();

        function animate(time) {
            const elapsed = time - start;
            const progress = Math.min(elapsed / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 4);
            current = ease * displayScore;
            
            if (scorePath) {
                scorePath.setAttribute('stroke-dasharray', `${current}, 100`);
                scorePath.setAttribute('stroke', strokeColor);
            }
            if (scoreText) scoreText.innerText = Math.round(current) + '%';
            
            if (progress < 1) requestAnimationFrame(animate);
        }
        requestAnimationFrame(animate);
    }

    // --- EVENT LISTENERS ---
    document.getElementById('scan-url-btn').addEventListener('click', async () => {
        const url = document.getElementById('url-field').value;
        if (!url) return;
        showLoading(true);
        try {
            const res = await fetch('/api/scan/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            showLoading(false);
            renderResult(data);
        } catch (err) { showLoading(false); alert('Error scanning URL'); }
    });

    document.getElementById('scan-email-btn').addEventListener('click', async () => {
        const text = document.getElementById('email-field').value;
        if (!text) return;
        showLoading(true);
        try {
            const res = await fetch('/api/scan/email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text })
            });
            const data = await res.json();
            showLoading(false);
            renderResult(data);
        } catch (err) { showLoading(false); alert('Error scanning email'); }
    });

    const fileField = document.getElementById('file-field');
    const fileNameDisplay = document.getElementById('file-name-display');
    const scanFileBtn = document.getElementById('scan-file-btn');

    fileField.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            fileNameDisplay.textContent = e.target.files[0].name;
            scanFileBtn.disabled = false;
        }
    });

    scanFileBtn.addEventListener('click', async () => {
        const fileName = fileNameDisplay.textContent;
        if (fileName === 'Click to select a file') return;
        showLoading(true);
        try {
            const res = await fetch('/api/scan/file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fileName })
            });
            const data = await res.json();
            showLoading(false);
            renderResult(data);
        } catch (err) { showLoading(false); alert('Error scanning file'); }
    });

    const emailFileField = document.getElementById('email-file-field');
    const emailFileNameDisplay = document.getElementById('email-file-name-display');
    const scanEmailFileBtn = document.getElementById('scan-email-file-btn');

    emailFileField.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            emailFileNameDisplay.textContent = e.target.files[0].name;
            scanEmailFileBtn.disabled = false;
        }
    });

    scanEmailFileBtn.addEventListener('click', async () => {
        const file = emailFileField.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        showLoading(true);
        try {
            const res = await fetch('/api/scan/email-file', { method: 'POST', body: formData });
            const data = await res.json();
            showLoading(false);
            if (data.error) alert(data.error); else renderResult(data);
        } catch (err) { showLoading(false); alert('Error scanning email file'); }
    });
});
