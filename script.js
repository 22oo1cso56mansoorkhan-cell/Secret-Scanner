// ----- script.js -----
(function() {
    // State
    let scanResults = [];
    let totalFiles = 0;
    let totalSecrets = 0;

    // DOM Elements
    const fileUpload = document.getElementById('fileUpload');
    const uploadArea = document.getElementById('uploadArea');
    const repoInput = document.getElementById('repoInput');
    const scanRepoBtn = document.getElementById('scanRepoBtn');
    const codeInput = document.getElementById('codeInput');
    const scanCodeBtn = document.getElementById('scanCodeBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const totalFilesEl = document.getElementById('totalFiles');
    const totalSecretsEl = document.getElementById('totalSecrets');
    const riskLevelEl = document.getElementById('riskLevel');
    const clearResultsBtn = document.getElementById('clearResults');
    const exportResultsBtn = document.getElementById('exportResults');

    // Modal
    const resultModal = document.getElementById('resultModal');
    const modalBody = document.getElementById('modalBody');
    const closeModal = document.getElementById('closeModal');
    const closeModalBtn = document.getElementById('closeModalBtn');

    // Secret Detection Patterns
    const secretPatterns = [
        // API Keys
        {
            name: 'OpenAI API Key',
            pattern: /sk-[A-Za-z0-9-_]{48,}/g,
            severity: 'high',
            description: 'OpenAI API secret key detected'
        },
        {
            name: 'Stripe API Key',
            pattern: /(sk_live|sk_test)_[A-Za-z0-9]{24,}/g,
            severity: 'high',
            description: 'Stripe API secret key detected'
        },
        {
            name: 'AWS Access Key',
            pattern: /AKIA[0-9A-Z]{16}/g,
            severity: 'high',
            description: 'AWS Access Key ID detected'
        },
        {
            name: 'AWS Secret Key',
            pattern: /[A-Za-z0-9/+=]{40}/g,
            severity: 'high',
            description: 'AWS Secret Access Key detected'
        },
        {
            name: 'GitHub Token',
            pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/g,
            severity: 'high',
            description: 'GitHub personal access token detected'
        },
        {
            name: 'Slack Webhook',
            pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
            severity: 'high',
            description: 'Slack webhook URL detected'
        },
        // Passwords and Tokens
        {
            name: 'Password in Code',
            pattern: /(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]/gi,
            severity: 'high',
            description: 'Hardcoded password detected'
        },
        {
            name: 'JWT Token',
            pattern: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g,
            severity: 'high',
            description: 'JWT token detected'
        },
        {
            name: 'Bearer Token',
            pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
            severity: 'high',
            description: 'Bearer token detected'
        },
        // Database and Services
        {
            name: 'MongoDB URI',
            pattern: /mongodb(?:\+srv)?:\/\/[A-Za-z0-9]+:[A-Za-z0-9]+@[A-Za-z0-9.-]+\/[A-Za-z0-9]+/g,
            severity: 'high',
            description: 'MongoDB connection string detected'
        },
        {
            name: 'PostgreSQL URI',
            pattern: /postgresql:\/\/[A-Za-z0-9]+:[A-Za-z0-9]+@[A-Za-z0-9.-]+\/[A-Za-z0-9]+/g,
            severity: 'high',
            description: 'PostgreSQL connection string detected'
        },
        {
            name: 'Redis URI',
            pattern: /redis:\/\/:[A-Za-z0-9]+@[A-Za-z0-9.-]+:[0-9]+/g,
            severity: 'high',
            description: 'Redis connection string detected'
        },
        // Other Secrets
        {
            name: 'Private Key',
            pattern: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g,
            severity: 'high',
            description: 'Private key detected'
        },
        {
            name: 'API Key in URL',
            pattern: /[?&](api[_-]?key|apikey|token|secret)=[A-Za-z0-9\-_]+/gi,
            severity: 'medium',
            description: 'API key in URL parameters detected'
        },
        {
            name: 'Environment Variable',
            pattern: /(export\s+)?[A-Z_]+_(KEY|SECRET|TOKEN|PASSWORD|PASS)\s*=\s*['"]?[A-Za-z0-9\-_]+['"]?/gi,
            severity: 'medium',
            description: 'Potential secret in environment variable'
        }
    ];

    // Scan text for secrets
    function scanText(text, filename = 'unknown') {
        const foundSecrets = [];
        
        secretPatterns.forEach(secretType => {
            const matches = text.match(secretType.pattern);
            if (matches) {
                matches.forEach(match => {
                    // Get context (surrounding lines)
                    const lines = text.split('\n');
                    let context = '';
                    let lineNumber = -1;
                    
                    lines.forEach((line, index) => {
                        if (line.includes(match)) {
                            lineNumber = index + 1;
                            context = line.trim();
                        }
                    });
                    
                    foundSecrets.push({
                        type: secretType.name,
                        match: match,
                        severity: secretType.severity,
                        description: secretType.description,
                        filename: filename,
                        lineNumber: lineNumber,
                        context: context,
                        timestamp: new Date().toISOString()
                    });
                });
            }
        });

        return foundSecrets;
    }

    // Handle file upload
    function handleFileUpload(files) {
        const results = [];
        const fileList = Array.from(files);
        
        fileList.forEach(file => {
            const reader = new FileReader();
            reader.onload = function(e) {
                const content = e.target.result;
                const secrets = scanText(content, file.name);
                if (secrets.length > 0) {
                    results.push(...secrets);
                }
                displayResults(results);
                updateStats(results);
            };
            reader.readAsText(file);
        });
        
        totalFiles += fileList.length;
        totalFilesEl.textContent = totalFiles;
    }

    // Scan GitHub repository
    async function scanRepository(repo) {
        try {
            const [owner, name] = repo.split('/');
            if (!owner || !name) {
                alert('Please enter repository in format: owner/repo');
                return;
            }

            // Show loading state
            scanRepoBtn.textContent = 'Scanning...';
            scanRepoBtn.disabled = true;

            const response = await fetch(`https://api.github.com/repos/${owner}/${name}/contents`);
            
            if (!response.ok) {
                throw new Error('Repository not found or API rate limit exceeded');
            }

            const files = await response.json();
            const allResults = [];

            for (const file of files) {
                if (file.type === 'file' && isTextFile(file.name)) {
                    try {
                        const fileResponse = await fetch(file.download_url);
                        const content = await fileResponse.text();
                        const secrets = scanText(content, file.name);
                        allResults.push(...secrets);
                    } catch (e) {
                        console.log(`Could not scan ${file.name}`);
                    }
                }
            }

            displayResults(allResults);
            updateStats(allResults);
            totalFilesEl.textContent = allResults.length > 0 ? files.filter(f => f.type === 'file').length : 0;

        } catch (error) {
            alert('Error scanning repository: ' + error.message);
        } finally {
            scanRepoBtn.textContent = 'Scan';
            scanRepoBtn.disabled = false;
        }
    }

    // Check if file is text-based
    function isTextFile(filename) {
        const textExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.c', '.cpp', '.h', '.cs', '.go', '.rs',
            '.rb', '.php', '.html', '.css', '.scss', '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg',
            '.conf', '.txt', '.md', '.sh', '.bash', '.zsh', '.ps1', '.vim', '.env'];
        
        return textExtensions.some(ext => filename.endsWith(ext));
    }

    // Display results
    function displayResults(results) {
        if (results.length === 0) {
            resultsContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-check-circle" style="font-size: 3rem; color: #00b894;"></i>
                    <p style="color: #00b894;">No secrets found!</p>
                    <p class="empty-hint">Your code is secure</p>
                </div>
            `;
            return;
        }

        // Sort by severity
        const severityOrder = { high: 0, medium: 1, low: 2 };
        results.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        let html = '';
        results.forEach((result, index) => {
            const severityClass = result.severity;
            html += `
                <div class="result-item" data-index="${index}" onclick="window.showResultDetail(${index})">
                    <div class="result-header">
                        <span class="result-type">${result.type}</span>
                        <span class="result-severity ${severityClass}">${result.severity.toUpperCase()}</span>
                    </div>
                    <div class="result-file">📁 ${result.filename}${result.lineNumber > 0 ? ` (line ${result.lineNumber})` : ''}</div>
                    <div class="result-preview">${result.context || result.match}</div>
                </div>
            `;
        });

        resultsContainer.innerHTML = html;
        scanResults = results;
    }

    // Show result detail in modal
    window.showResultDetail = function(index) {
        const result = scanResults[index];
        if (!result) return;

        modalBody.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">Type</span>
                <span class="detail-value">${result.type}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Severity</span>
                <span class="detail-value highlight">${result.severity.toUpperCase()}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">File</span>
                <span class="detail-value">${result.filename}</span>
            </div>
            ${result.lineNumber > 0 ? `
            <div class="detail-row">
                <span class="detail-label">Line</span>
                <span class="detail-value">${result.lineNumber}</span>
            </div>
            ` : ''}
            <div class="detail-row" style="flex-direction: column; align-items: flex-start; gap: 0.5rem;">
                <span class="detail-label">Matched Secret</span>
                <span class="detail-value highlight" style="max-width: 100%; word-break: break-all; text-align: left; background: rgba(225,112,85,0.1); padding: 0.5rem; border-radius: 6px; width: 100%;">
                    ${result.match}
                </span>
            </div>
            <div class="detail-row" style="flex-direction: column; align-items: flex-start; gap: 0.5rem;">
                <span class="detail-label">Context</span>
                <span class="detail-value" style="max-width: 100%; text-align: left; font-size: 0.85rem; word-break: break-word;">
                    ${result.context || 'No context available'}
                </span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Description</span>
                <span class="detail-value" style="max-width: 100%; text-align: right;">${result.description}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Found</span>
                <span class="detail-value">${new Date(result.timestamp).toLocaleString()}</span>
            </div>
        `;

        resultModal.classList.add('active');
    };

    // Update stats
    function updateStats(results) {
        totalSecrets = results.length;
        totalSecretsEl.textContent = totalSecrets;

        const highCount = results.filter(r => r.severity === 'high').length;
        if (totalSecrets === 0) {
            riskLevelEl.textContent = 'Safe ✅';
            riskLevelEl.style.color = '#00b894';
        } else if (highCount > 0) {
            riskLevelEl.textContent = 'Critical ⚠️';
            riskLevelEl.style.color = '#e17055';
        } else {
            riskLevelEl.textContent = 'Medium ⚠️';
            riskLevelEl.style.color = '#fdcb6e';
        }
    }

    // Clear results
    function clearResults() {
        scanResults = [];
        totalFiles = 0;
        totalSecrets = 0;
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-shield-alt" style="font-size: 3rem; color: #b2bec3;"></i>
                <p>No secrets found yet</p>
                <p class="empty-hint">Upload a file, scan a repository, or paste code to start scanning</p>
            </div>
        `;
        totalFilesEl.textContent = '0';
        totalSecretsEl.textContent = '0';
        riskLevelEl.textContent = 'Safe';
        riskLevelEl.style.color = 'white';
    }

    // Export results
    function exportResults() {
        if (scanResults.length === 0) {
            alert('No results to export');
            return;
        }

        const data = {
            scanDate: new Date().toISOString(),
            totalSecrets: scanResults.length,
            secrets: scanResults
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan-results-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // Event listeners
    fileUpload.addEventListener('change', function(e) {
        if (this.files && this.files.length > 0) {
            handleFileUpload(this.files);
        }
    });

    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            handleFileUpload(files);
        }
    });

    scanRepoBtn.addEventListener('click', function() {
        const repo = repoInput.value.trim();
        if (repo) {
            scanRepository(repo);
        } else {
            alert('Please enter a repository in format: owner/repo');
        }
    });

    scanCodeBtn.addEventListener('click', function() {
        const code = codeInput.value;
        if (code.trim()) {
            const results = scanText(code, 'pasted-code');
            displayResults(results);
            updateStats(results);
        } else {
            alert('Please paste some code to scan');
        }
    });

    clearResultsBtn.addEventListener('click', clearResults);
    exportResultsBtn.addEventListener('click', exportResults);

    // Modal controls
    closeModal.addEventListener('click', () => resultModal.classList.remove('active'));
    closeModalBtn.addEventListener('click', () => resultModal.classList.remove('active'));
    resultModal.addEventListener('click', function(e) {
        if (e.target === this) resultModal.classList.remove('active');
    });

    // Enter key for repo input
    repoInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            scanRepoBtn.click();
        }
    });

    console.log('🔒 Secret Scanner initialized');
})();