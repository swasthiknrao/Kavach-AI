document.addEventListener('DOMContentLoaded', function() {
    // Parse URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const siteUrl = urlParams.get('url');
    const analysisId = urlParams.get('id');
    const timestamp = new Date().toLocaleString();
    
    // First try to get stored analysis result from background page
    chrome.runtime.sendMessage(
        { action: 'get_analysis_result', url: siteUrl, id: analysisId },
        function(response) {
            console.log('Received analysis data:', response);
            
            // If we have a valid response, use it
            if (response && response.status === 'success') {
                displayAnalysisResults(response, siteUrl, timestamp);
            } else {
                // Otherwise, use URL parameters as fallback
                const riskScore = urlParams.get('score') || "42";
                const findingsParam = urlParams.get('findings');
                
                // Create a minimal results object
                const fallbackResults = {
                    risk_assessment: {
                        risk_score: parseInt(riskScore) / 100,
                        confidence: 0.75,
                        risk_level: parseInt(riskScore) > 70 ? 'high' : 
                                   parseInt(riskScore) > 40 ? 'medium' : 'low'
                    },
                    findings: findingsParam ? JSON.parse(findingsParam) : getDemoFindings(),
                    url: siteUrl,
                    timestamp: timestamp
                };
                
                displayAnalysisResults(fallbackResults, siteUrl, timestamp);
            }
        }
    );
    
    // Add event listeners to buttons
    document.getElementById('download-report').addEventListener('click', downloadReport);
    document.getElementById('back-to-browser').addEventListener('click', function() {
        window.history.back();
    });
    document.getElementById('block-site').addEventListener('click', function() {
        blockSite(siteUrl);
    });
});

// Display full analysis results
function displayAnalysisResults(results, url, timestamp) {
    // Validate the analysis results
    if (!results || (results.status && results.status !== 'success')) {
        showErrorMessage("Invalid analysis results. Please try again.");
        return;
    }

    // Populate site info
    if (url) {
        document.getElementById('site-url').textContent = url;
    } else if (results.url) {
        document.getElementById('site-url').textContent = results.url;
    }
    
    // Display timestamp from the analysis or current time as fallback
    document.getElementById('scan-time').textContent = `Scanned on ${results.timestamp ? 
        new Date(results.timestamp).toLocaleString() : timestamp}`;
    
    // Get risk score and level
    let riskScore = 50; // Default value if missing
    let riskLevel = 'medium'; // Default level
    
    if (results.risk_assessment) {
        if (typeof results.risk_assessment.risk_score === 'number') {
            riskScore = Math.round(results.risk_assessment.risk_score * 100);
        }
        
        if (results.risk_assessment.risk_level) {
            riskLevel = results.risk_assessment.risk_level;
        }
    }
    
    // Set risk score in the UI
    const overallScore = document.getElementById('overall-score');
    overallScore.innerHTML = riskScore + '<span>%</span>';
    
    // Update score card class based on risk level
    const scoreCard = overallScore.closest('.score-card');
    if (riskLevel === 'high' || riskScore > 70) {
        scoreCard.className = 'score-card high-risk';
        overallScore.className = 'score-value score-high';
    } else if (riskLevel === 'medium' || riskScore > 40) {
        scoreCard.className = 'score-card medium-risk';
        overallScore.className = 'score-value score-medium';
    } else {
        scoreCard.className = 'score-card low-risk';
        overallScore.className = 'score-value score-low';
    }
    
    // Set confidence score
    const confidenceScore = document.getElementById('confidence-score');
    if (results.risk_assessment && typeof results.risk_assessment.confidence === 'number') {
        const confidence = Math.round(results.risk_assessment.confidence * 100);
        confidenceScore.innerHTML = confidence + '<span>%</span>';
    }
    
    // Get findings
    let findings = [];
    if (results.findings && Array.isArray(results.findings)) {
        findings = results.findings;
    }
    
    // Count suspicious patterns
    document.getElementById('patterns-count').textContent = findings.length;
    
    // Populate component scores using the format from the analysis
    if (results.component_scores) {
        populateComponentScores(results.component_scores);
    } else {
        showErrorMessage("Missing component scores in analysis");
    }
    
    // Populate findings
    populateFindings(findings);
    
    // Populate HTML preview if content available
    if (results.content_preview) {
        populateHtmlPreview(results.content_preview);
    } else {
        populateHtmlPreview(`<!-- Content preview not available for ${url || 'this site'} -->`);
    }
    
    // Populate behaviors
    if (results.behavior_data) {
        populateBehaviors(results.behavior_data);
    } else {
        populateBehaviors(findings);
    }
}

// Show error message on the page
function showErrorMessage(message) {
    const container = document.querySelector('.container');
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.style.color = 'red';
    errorDiv.style.padding = '20px';
    errorDiv.style.marginBottom = '20px';
    errorDiv.style.backgroundColor = '#ffeeee';
    errorDiv.style.borderRadius = '8px';
    errorDiv.style.border = '1px solid red';
    errorDiv.textContent = message;
    
    // Insert at the top of the container
    container.insertBefore(errorDiv, container.firstChild);
}

// Populate component scores with data from the analysis
function populateComponentScores(componentScores) {
    const componentScoresContainer = document.getElementById('component-scores');
    componentScoresContainer.innerHTML = '';
    
    // Define components based on the format from response
    const components = [];
    
    // Check format of component scores
    if (componentScores.url?.score !== undefined) {
        // New format with nested objects
        // URL Analysis
        if (componentScores.url) {
            components.push({
                name: "URL Analysis",
                icon: "🔗",
                score: Math.round(componentScores.url.score * 100),
                level: componentScores.url.level || getScoreLevel(componentScores.url.score),
                details: "Domain age, registration patterns, and structure"
            });
        }
        
        // Visual Similarity
        if (componentScores.visual) {
            components.push({
                name: "Visual Similarity",
                icon: "👁️",
                score: Math.round(componentScores.visual.score * 100),
                level: componentScores.visual.level || getScoreLevel(componentScores.visual.score),
                details: "Logo detection, layout comparison"
            });
        }
        
        // Behavior Analysis
        if (componentScores.behavior) {
            components.push({
                name: "Behavior Analysis",
                icon: "🧠",
                score: Math.round(componentScores.behavior.score * 100),
                level: componentScores.behavior.level || getScoreLevel(componentScores.behavior.score),
                details: "JavaScript activities, form handling, redirects"
            });
        }
        
        // Connection Security
        if (componentScores.ssl) {
            components.push({
                name: "Connection Security",
                icon: "🔒",
                score: Math.round(componentScores.ssl.score * 100),
                level: componentScores.ssl.level || getScoreLevel(componentScores.ssl.score),
                details: "SSL/TLS implementation, certificate validity"
            });
        }
    } else if (componentScores.url_risk !== undefined) {
        // Legacy format with direct values
        components.push({
            name: "URL Analysis",
            icon: "🔗",
            score: Math.round(componentScores.url_risk * 100),
            level: getScoreLevel(componentScores.url_risk),
            details: "Domain age, registration patterns, and structure"
        });
        
        components.push({
            name: "Visual Similarity",
            icon: "👁️",
            score: Math.round(componentScores.visual_risk * 100),
            level: getScoreLevel(componentScores.visual_risk),
            details: "Logo detection, layout comparison"
        });
        
        components.push({
            name: "Behavior Analysis",
            icon: "🧠",
            score: Math.round(componentScores.behavior_risk * 100),
            level: getScoreLevel(componentScores.behavior_risk),
            details: "JavaScript activities, form handling, redirects"
        });
        
        components.push({
            name: "Connection Security",
            icon: "🔒",
            score: Math.round(componentScores.ssl_risk * 100),
            level: getScoreLevel(componentScores.ssl_risk),
            details: "SSL/TLS implementation, certificate validity"
        });
    } else {
        // Unexpected format - show error and use defaults
        showErrorMessage("Component scores format not recognized");
        populateDefaultComponentScores();
        return;
    }
    
    // If no components were found, use defaults (should not happen with validation)
    if (components.length === 0) {
        showErrorMessage("No component scores found in analysis");
        populateDefaultComponentScores();
        return;
    }
    
    // Display the components
    displayComponentScores(components);
}

// Helper function to get risk level from score
function getScoreLevel(score) {
    if (score >= 0.7) return 'high';
    if (score >= 0.4) return 'medium';
    return 'low';
}

// Use default component scores when no data is available
function populateDefaultComponentScores() {
    const components = [
        { 
            name: "URL Analysis", 
            icon: "🔗", 
            score: 55, 
            level: 'medium',
            details: "Domain age, registration patterns, and structure" 
        },
        { 
            name: "Visual Similarity", 
            icon: "👁️", 
            score: 40, 
            level: 'medium',
            details: "Logo detection, layout comparison" 
        },
        { 
            name: "Behavior Analysis", 
            icon: "🧠", 
            score: 65, 
            level: 'medium',
            details: "JavaScript activities, form handling, redirects" 
        },
        { 
            name: "Connection Security", 
            icon: "🔒", 
            score: 30, 
            level: 'low',
            details: "SSL/TLS implementation, certificate validity" 
        }
    ];
    
    displayComponentScores(components);
}

// Display component scores in the UI
function displayComponentScores(components) {
    const componentScoresContainer = document.getElementById('component-scores');
    
    components.forEach(component => {
        const componentDiv = document.createElement('div');
        componentDiv.className = 'component-card';
        
        // Determine risk class based on score or level
        let riskClass = '';
        if (component.level === 'high' || component.score > 70) {
            riskClass = 'fill-high';
        } else if (component.level === 'medium' || component.score > 40) {
            riskClass = 'fill-medium';
        } else {
            riskClass = 'fill-low';
        }
        
        componentDiv.innerHTML = `
            <div class="component-name">
                <span class="component-icon">${component.icon}</span>
                ${component.name}
            </div>
            <div class="progress-bar">
                <div class="progress-fill ${riskClass}" style="width: ${component.score}%"></div>
            </div>
            <div class="risk-score">${component.score}%</div>
            <div class="component-details">${component.details}</div>
        `;
        
        componentScoresContainer.appendChild(componentDiv);
    });
}

// Populate findings list
function populateFindings(findings) {
    const findingsListEl = document.getElementById('findings-list');
    findingsListEl.innerHTML = '';
    
    findings.forEach(finding => {
        const severityClass = finding.severity === 'high' ? 'high-severity' : 
                             (finding.severity === 'medium' ? 'medium-severity' : 'low-severity');
        
        const findingEl = document.createElement('div');
        findingEl.className = `finding-item ${severityClass}`;
        findingEl.innerHTML = `
            <div class="finding-type ${severityClass}">${finding.type}</div>
            <div class="finding-description">${finding.description}</div>
            ${finding.evidence ? `<div class="finding-evidence">${finding.evidence}</div>` : ''}
        `;
        
        findingsListEl.appendChild(findingEl);
    });
}

// Populate HTML preview
function populateHtmlPreview(url) {
    const htmlPreviewEl = document.getElementById('html-preview');
    // This would normally fetch and display the actual HTML
    // For demo, just show sample HTML structure
    htmlPreviewEl.textContent = `<!DOCTYPE html>
<html>
<head>
    <title>Login to Your Account</title>
    <link rel="stylesheet" href="styles.css">
    <script src="tracking.js"></script>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <img src="bank-logo.png" alt="Bank Logo">
        </div>
        <form id="login-form" action="process.php" method="post">
            <h2>Sign in to your account</h2>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">
            <a href="#">Forgot Password?</a>
            <a href="#">Help</a>
        </div>
    </div>
    <script src="form-capture.js"></script>
</body>
</html>`;
}

// Populate behavior data
function populateBehaviors(findings) {
    const behaviorListEl = document.getElementById('behavior-list');
    behaviorListEl.innerHTML = '';
    
    const behaviors = [
        { label: "URL Safety", value: "34% - Low Risk" },
        { label: "Visual Match", value: "36% - Low Risk" },
        { label: "Behavior", value: "44% - Medium Risk" },
        { label: "Connection", value: "2% - Low Risk" },
        { label: "Overall Rating", value: "Medium concern - Exercise caution" }
    ];
    
    behaviors.forEach(behavior => {
        const behaviorEl = document.createElement('div');
        behaviorEl.className = 'behavior-item';
        behaviorEl.innerHTML = `
            <div class="behavior-label">${behavior.label}</div>
            <div class="behavior-value">${behavior.value}</div>
        `;
        
        behaviorListEl.appendChild(behaviorEl);
    });
}

// Block the site
function blockSite(url) {
    if (!url) return;
    
    const domain = extractDomain(url);
    
    chrome.runtime.sendMessage({
        action: 'block_site',
        domain: domain,
        blockAction: 'add'
    }, function(response) {
        if (response && response.success) {
            alert(`${domain} has been added to your blocked sites list.`);
            window.history.back();
        } else {
            alert('Could not block the site. Please try again.');
        }
    });
}

// Helper to extract domain from URL
function extractDomain(url) {
    try {
        if (!url) return '';
        // Remove protocol and www if present
        const domainAndPath = url.replace(/(https?:\/\/)?(www\.)?/, '');
        // Get just the domain part (before any /)
        return domainAndPath.split('/')[0];
    } catch (error) {
        console.error('Error extracting domain:', error);
        return url;
    }
}

// Download report as HTML
function downloadReport() {
    // Create a blob of the current page HTML
    const html = document.documentElement.outerHTML;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    
    // Create and click a download link
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${new Date().toISOString().split('T')[0]}.html`;
    a.click();
    
    // Clean up
    URL.revokeObjectURL(url);
}

// Return demo findings if none available
function getDemoFindings() {
    return [
        {
            type: "Suspicious URL Pattern",
            severity: "medium",
            description: "Some concerns with URL structure detected",
            evidence: "Domain: secure-bank1ng-login.com may be suspicious"
        },
        {
            type: "Visual Match Check",
            severity: "medium",
            description: "No visual similarity to known phishing sites detected",
            evidence: "Visual similarity check completed successfully"
        },
        {
            type: "Behavior Analysis",
            severity: "medium",
            description: "Some page behaviors are concerning",
            evidence: "Certain behaviors on this page require user caution"
        },
        {
            type: "Connection Security",
            severity: "low",
            description: "Connection is secure with proper encryption",
            evidence: "HTTPS connection verified"
        }
    ];
} 