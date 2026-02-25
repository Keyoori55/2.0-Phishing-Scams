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

            // Update active tab UI
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Show relevant input section
            Object.keys(inputSections).forEach(key => {
                inputSections[key].style.display = key === tabName ? (key === 'url' ? 'flex' : 'flex') : 'none';
                // Note: dropzone uses flex for column layout, inputGroup uses flex for row
                if (key !== 'url' && key === tabName) inputSections[key].style.display = 'flex';
                if (key === 'url' && key === tabName) inputSections[key].style.display = 'flex';
            });

            // Clear previous results
            resultContainer.innerHTML = '';
        });
    });

    // --- SCAN LOGIC ---
    const scanningState = document.getElementById('scanning-state');

    const showLoading = (show) => {
        scanningState.style.display = show ? 'block' : 'none';
        if (show) resultContainer.innerHTML = '';
    };

    const renderResult = (data) => {
        const isSafe = data.verdict === 'safe';
        const isWarning = data.verdict === 'warning';

        let verdictClass = 'verdictSafe';
        let verdictText = 'Safe to Open';
        let lucideIcon = 'shield';

        if (isWarning) {
            verdictClass = 'verdictWarning';
            verdictText = 'Caution Recommended';
            lucideIcon = 'alert-circle';
        } else if (!isSafe) {
            verdictClass = 'verdictDanger';
            verdictText = 'Threat Detected';
            lucideIcon = 'alert-triangle';
        }

        let stepsHtml = '';
        data.steps.forEach(step => {
            let stepIcon = 'check-circle';
            let statusClass = 'textSafe';
            if (step.status === 'warning') {
                stepIcon = 'alert-circle';
                statusClass = 'textWarning';
            } else if (step.status === 'danger') {
                stepIcon = 'alert-triangle';
                statusClass = 'textDanger';
            }

            stepsHtml += `
            <div class="step">
                <div class="stepIcon">
                    <i data-lucide="${stepIcon}" class="${statusClass}"></i>
                </div>
                <div class="stepContent">
                    <h4>${step.name}</h4>
                    <p>${step.details}</p>
                </div>
            </div>`;
        });

        const html = `
        <div class="resultContainer">
            <div class="resultHeader">
                <div>
                    <h3 class="resultTitle">Analysis Complete</h3>
                    <p class="resultDate">${new Date().toLocaleString()}</p>
                </div>
                <div class="verdict ${verdictClass}">
                    <i data-lucide="${lucideIcon}"></i>
                    ${verdictText}
                </div>
            </div>

            <div class="scoreContainer">
                <div class="scoreCircle">
                    <svg viewBox="0 0 36 36" class="circularChart">
                        <path class="circleBg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path class="circle" stroke-dasharray="${data.score}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                    </svg>
                    <div class="percentage">
                        <span class="number">${data.score}</span>
                        <span class="scoreLabel">Safety Score</span>
                    </div>
                </div>
            </div>

            <div class="timeline">
                ${stepsHtml}
            </div>

            <div class="resultFooter">
                <button class="btn btn-primary" style="width: 100%">View Detailed Report</button>
            </div>
        </div>`;

        resultContainer.innerHTML = html;
        lucide.createIcons();
        resultContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
    };

    // 1. URL Scan
    document.getElementById('scan-url-btn').addEventListener('click', async () => {
        const url = document.getElementById('url-field').value;
        if (!url) return;

        showLoading(true);
        try {
            const response = await fetch('/api/scan/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await response.json();
            showLoading(false);
            renderResult(data);
        } catch (err) {
            showLoading(false);
            alert('Error scanning URL');
        }
    });

    // 2. Email Scan
    document.getElementById('scan-email-btn').addEventListener('click', async () => {
        const text = document.getElementById('email-field').value;
        if (!text) return;

        showLoading(true);
        try {
            const response = await fetch('/api/scan/email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text })
            });
            const data = await response.json();
            showLoading(false);
            renderResult(data);
        } catch (err) {
            showLoading(false);
            alert('Error scanning email');
        }
    });

    // 3. File Scan
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
            const response = await fetch('/api/scan/file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fileName })
            });
            const data = await response.json();
            showLoading(false);
            renderResult(data);
        } catch (err) {
            showLoading(false);
            alert('Error scanning file');
        }
    });

    // --- FEEDBACK LOGIC ---
    const feedbackForm = document.getElementById('feedback-form');
    if (feedbackForm) {
        const emojiButtons = document.querySelectorAll('.emojiButton');
        const submitBtn = document.getElementById('submit-feedback-btn');
        let selectedRating = null;

        emojiButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                selectedRating = btn.getAttribute('data-val');
                emojiButtons.forEach(b => b.classList.remove('activeEmoji'));
                btn.classList.add('activeEmoji');
                submitBtn.disabled = false;
            });
        });

        feedbackForm.addEventListener('submit', (e) => {
            e.preventDefault();
            document.getElementById('feedback-form-container').style.display = 'none';
            document.getElementById('feedback-success').style.display = 'block';
        });

        document.getElementById('restart-feedback-btn').addEventListener('click', () => {
            document.getElementById('feedback-form-container').style.display = 'block';
            document.getElementById('feedback-success').style.display = 'none';
            feedbackForm.reset();
            emojiButtons.forEach(b => b.classList.remove('activeEmoji'));
            submitBtn.disabled = true;
            selectedRating = null;
        });
    }
});
