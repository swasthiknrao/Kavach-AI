document.addEventListener('DOMContentLoaded', () => {
    // Get URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const url = urlParams.get('url');
    const tabId = parseInt(urlParams.get('tabId'));
    
    // Get DOM elements
    const loadingElement = document.getElementById('loading');
    const warningContainer = document.getElementById('warning-container');
    const siteUrlElement = document.getElementById('site-url');
    const riskFill = document.getElementById('risk-fill');
    const riskValue = document.getElementById('risk-value');
    const confidenceFill = document.getElementById('confidence-fill');
    const confidenceValue = document.getElementById('confidence-value');
    const findingsList = document.getElementById('findings-list');
    
    // Set up event listeners
    document.getElementById('back-btn').addEventListener('click', goBack);
    document.getElementById('details-btn').addEventListener('click', () => viewDetailedReport(url, tabId));
    document.getElementById('proceed-btn').addEventListener('click', () => proceedAnyway(url, tabId));
    
    // Display site URL
    if (url) {
        try {
            const urlObj = new URL(url);
            siteUrlElement.textContent = urlObj.toString();
        } catch (e) {
            siteUrlElement.textContent = url;
        }
    }
    
    // Get analysis data
    getAnalysisData(url);
    
    // Function to get analysis data
    function getAnalysisData(url) {
        chrome.runtime.sendMessage({
            action: 'get_analysis_result',
            url: url
        }, response => {
            if (response && response.success && response.result) {
                displayWarning(response.result);
            } else {
                showError('Could not retrieve security analysis for this site.');
            }
        });
    }
    
    // Function to display warning with analysis data
    function displayWarning(data) {
        // Update risk score
        riskValue.textContent = data.risk_score.toFixed(1);
        riskFill.style.width = `${data.risk_score * 10}%`;
        
        // Update confidence
        const confidencePercent = (data.confidence * 100).toFixed(0);
        confidenceValue.textContent = `${confidencePercent}%`;
        confidenceFill.style.width = `${confidencePercent}%`;
        
        // Display findings
        if (data.findings && data.findings.length > 0) {
            findingsList.innerHTML = '';
            
            data.findings
                .sort((a, b) => b.severity - a.severity)
                .forEach(finding => {
                    const item = document.createElement('div');
                    item.className = 'finding-item';
                    
                    item.innerHTML = `
                        <div class="finding-type">${finding.type}</div>
                        <div class="finding-description">${finding.description}</div>
                    `;
                    
                    findingsList.appendChild(item);
                });
        } else {
            findingsList.innerHTML = '<p>No specific issues were identified, but the overall risk score is high.</p>';
        }
        
        // Show warning container
        loadingElement.style.display = 'none';
        warningContainer.style.display = 'block';
    }
    
    // Function to go back to previous page
    function goBack() {
        window.history.back();
    }
    
    // Function to view detailed report
    function viewDetailedReport(url, tabId) {
        const reportUrl = chrome.runtime.getURL(`detailed_report.html?url=${encodeURIComponent(url)}&tabId=${tabId}`);
        chrome.tabs.create({ url: reportUrl });
    }
    
    // Function to proceed to the site anyway
    function proceedAnyway(url, tabId) {
        chrome.runtime.sendMessage({
            action: 'proceed_anyway',
            url: url,
            tabId: tabId
        }, () => {
            // Close this warning page
            window.close();
        });
    }
    
    // Function to show error
    function showError(message) {
        loadingElement.innerHTML = `
            <div style="color: #e74c3c; font-weight: bold; margin-bottom: 10px;">Error</div>
            <div>${message}</div>
            <button onclick="window.history.back()" style="margin-top: 20px; padding: 8px 16px;">Go Back</button>
        `;
    }
}); 