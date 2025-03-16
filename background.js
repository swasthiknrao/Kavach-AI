// Kavach AI Security - Background Service Worker

// Configuration
const API_ENDPOINT = 'http://127.0.0.1:9000/api';
const ANALYSIS_CACHE_TIME = 60 * 60 * 1000; // 1 hour in milliseconds
let MAX_RETRIES = 2;  // Maximum number of API retries

// Cache and state
let analysisInProgress = {};  // Track URLs being analyzed to prevent duplicate requests

// Initialize
console.log('Kavach AI Security background service worker initialized');

// Set up listeners
chrome.runtime.onInstalled.addListener(handleInstallation);
chrome.webNavigation.onCompleted.addListener(handleNavigation);
chrome.runtime.onMessage.addListener(handleMessage);

// Add mock data function to the top of the file
function generateMockAnalysisData(url) {
  console.log("Generating mock analysis data for:", url);
  
  // Generate random risk scores for components
  const urlRisk = Math.random() * 0.6;  // Lower URL risk for demo
  const visualRisk = Math.random() * 0.5; // Lower visual risk for demo
  const behaviorRisk = Math.random() * 0.4; // Lower behavior risk for demo
  const sslRisk = url.startsWith('https') ? Math.random() * 0.3 : Math.random() * 0.8; // Higher risk for non-HTTPS
  
  // Overall risk is weighted average
  const overallRisk = (urlRisk * 0.3 + visualRisk * 0.25 + behaviorRisk * 0.3 + sslRisk * 0.15);
  
  // Determine risk level
  let riskLevel;
  if (overallRisk >= 0.7) {
    riskLevel = "high";
  } else if (overallRisk >= 0.4) {
    riskLevel = "medium";
  } else {
    riskLevel = "low";
  }
  
  return {
    status: 'success',
    risk_assessment: {
      risk_score: overallRisk,
      confidence: 0.85,
      risk_level: riskLevel
    },
    component_scores: {
      url_risk: urlRisk,
      visual_risk: visualRisk,
      behavior_risk: behaviorRisk,
      ssl_risk: sslRisk
    },
    findings: [],
    recommendations: []
  };
}

// Handle installation
function handleInstallation(details) {
    if (details.reason === 'install') {
        console.log('Installing Kavach AI Security Extension');
        // Initialize default settings
        chrome.storage.local.set({
            protection_enabled: true,
            notification_level: 'medium', // low, medium, high
            auto_block_high_risk: true,
            share_anonymous_data: true,
            whitelist: [],
            apiEndpoint: API_ENDPOINT
        });
    }
}

// Handle navigation to a new page
function handleNavigation(details) {
    // Only process main frame navigations
    if (details.frameId !== 0) return;
    
    const url = details.url;
    
    // Skip non-HTTP URLs
    if (!url.startsWith('http')) return;
        
        // Check if protection is enabled
    chrome.storage.local.get('protection_enabled', result => {
        if (!result.protection_enabled) {
            updateBadge('disabled', details.tabId);
            return;
        }
        
        // Check if URL has been analyzed recently
        checkAnalysisCache(url).then(cachedResult => {
            if (cachedResult) {
                updateBadge(cachedResult.risk_level, details.tabId);
                processAnalysisResult(url, cachedResult, details.tabId);
            } else {
                // Set badge to scanning state
                updateBadge('scanning', details.tabId);
            }
        }).catch(error => {
            console.error('Kavach: Error checking analysis cache:', error);
        });
    });
}

// Handle messages from content scripts or popup
async function handleMessage(message, sender, sendResponse) {
    console.log('Received message:', message.action);

    // Immediately respond to acknowledge receipt
    if (message.expectsResponse) {
        sendResponse({ status: 'received' });
    }
    
    try {
        if (!message || !message.action) {
            console.error('Kavach: Received message without action');
            sendResponse({ status: 'error', error: 'No action specified' });
            return;
        }
        
        console.log('Kavach: Received action:', message.action);
        
        switch (message.action) {
            case 'analyze_data':
                // Process data from content script
                try {
                    const result = await analyzeData(message.data, sender.tab.id);
                    sendResponse({ status: 'success', result: result });
                } catch (error) {
                    console.error('Kavach: Error analyzing data:', error);
                    sendResponse({ status: 'error', error: error.message });
                    // Notify content script about the failure
                    notifyAnalysisFailed(message.data.url, error.message, sender.tab.id);
                }
                break;
                
            case 'analysis_complete':
                // Content script is notifying that analysis is complete
                processAnalysisResult(message.result, message.url, sender.tab.id);
                break;
                
            case 'whitelist_site':
                if (!message.domain) {
                    console.error('Kavach: Invalid whitelist_site request, missing domain');
                    sendResponse({ success: false, error: 'Invalid request. Missing domain.' });
                    return true;
                }
                
                // Get current whitelist and blocklist
                chrome.storage.local.get(['whitelist', 'blocklist'], function(data) {
                    let whitelist = data.whitelist || [];
                    let blocklist = data.blocklist || [];
                    const domain = message.domain;
                    const action = message.whitelistAction || 'add';
                    
                    if (action === 'add') {
                        // Add domain to whitelist if not already present
                        if (!whitelist.includes(domain)) {
                            whitelist.push(domain);
                        }
                        
                        // Remove from blocklist if present
                        blocklist = blocklist.filter(d => d !== domain);
                    } else if (action === 'remove') {
                        // Remove domain from whitelist
                        whitelist = whitelist.filter(d => d !== domain);
                    }
                    
                    // Save updated whitelist and blocklist
                    chrome.storage.local.set({ 
                        whitelist: whitelist,
                        blocklist: blocklist 
                    }, function() {
                        if (chrome.runtime.lastError) {
                            console.error('Kavach: Error saving whitelist:', chrome.runtime.lastError);
                            sendResponse({ success: false, error: chrome.runtime.lastError.message });
                        } else {
                            console.log('Kavach: Updated whitelist:', whitelist);
                            console.log('Kavach: Updated blocklist:', blocklist);
                            sendResponse({ 
                                success: true, 
                                whitelist: whitelist,
                                blocklist: blocklist
                            });
                        }
                    });
                });
                
                return true; // Indicates we'll respond asynchronously
                
            case 'block_site':
                if (!message.domain) {
                    console.error('Kavach: Invalid block_site request, missing domain');
                    sendResponse({ success: false, error: 'Invalid request. Missing domain.' });
                    return true;
                }
                
                // Get current blocklist and whitelist
                chrome.storage.local.get(['blocklist', 'whitelist'], function(data) {
                    let blocklist = data.blocklist || [];
                    let whitelist = data.whitelist || [];
                    const domain = message.domain;
                    const action = message.blockAction || 'add';
                    
                    if (action === 'add') {
                        // Add domain to blocklist if not already present
                        if (!blocklist.includes(domain)) {
                            blocklist.push(domain);
                            
                            // Redirect current tab to blocked page if this is the domain being viewed
                            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                                if (tabs[0]) {
                                    try {
                                        const tabUrl = new URL(tabs[0].url);
                                        if (tabUrl.hostname === domain) {
                                            // Redirect to blocked page
                                            chrome.tabs.update(tabs[0].id, {
                                                url: chrome.runtime.getURL('blocked.html') + `?domain=${encodeURIComponent(domain)}`
                                            });
                                        }
                                    } catch (error) {
                                        console.error('Kavach: Error checking tab URL:', error);
                                    }
                                }
                            });
                        }
                        
                        // Remove from whitelist if present
                        whitelist = whitelist.filter(d => d !== domain);
                    } else if (action === 'remove') {
                        // Remove domain from blocklist
                        blocklist = blocklist.filter(d => d !== domain);
                        
                        // Check if we need to reload any tabs showing the blocked page for this domain
                        chrome.tabs.query({}, function(tabs) {
                            tabs.forEach(tab => {
                                if (tab.url && tab.url.startsWith(chrome.runtime.getURL('blocked.html'))) {
                                    try {
                                        // Check if this blocked page is for the domain we're unblocking
                                        const url = new URL(tab.url);
                                        const params = new URLSearchParams(url.search);
                                        const blockedDomain = params.get('domain');
                                        
                                        if (blockedDomain === domain) {
                                            // This is the domain we just unblocked, restore the original URL if possible
                                            console.log('Kavach: Unblocked domain detected in tab, reloading:', domain);
                                            
                                            // Construct a URL to the actual site
                                            const siteProtocol = 'https://'; // Default to https
                                            const siteUrl = siteProtocol + domain;
                                            
                                            // Navigate back to the site
                                            chrome.tabs.update(tab.id, { url: siteUrl });
                                        }
                                    } catch (error) {
                                        console.error('Kavach: Error processing blocked page URL:', error);
                                    }
                                }
                            });
                        });
                    }
                    
                    // Save updated blocklist and whitelist
                    chrome.storage.local.set({ 
                        blocklist: blocklist,
                        whitelist: whitelist 
                    }, function() {
                        if (chrome.runtime.lastError) {
                            console.error('Kavach: Error saving blocklist:', chrome.runtime.lastError);
                            sendResponse({ success: false, error: chrome.runtime.lastError.message });
                        } else {
                            console.log('Kavach: Updated blocklist:', blocklist);
                            console.log('Kavach: Updated whitelist:', whitelist);
                            sendResponse({ 
                                success: true, 
                                blocklist: blocklist,
                                whitelist: whitelist
                            });
                        }
                    });
                });
                
                return true; // Indicates we'll respond asynchronously
                
            case 'remove_from_whitelist':
                if (message.domain) {
                    const success = await removeFromWhitelist(message.domain);
                    sendResponse({ status: success ? 'success' : 'error' });
                } else {
                    sendResponse({ status: 'error', error: 'No domain provided' });
                }
                break;
                
            case 'store_analysis_result':
                await storeAnalysisResult(message.url, message.data);
                sendResponse({ status: 'success' });
                return true;
                
            case 'get_analysis_result':
                const result = await getAnalysisResult(message.url);
                sendResponse({ status: 'success', data: result });
                return true;
                
            case 'protection_status_changed':
                // Update the protection status
                console.log('Kavach: Protection status changed:', message.enabled);
                break;
                
            case 'proceed_anyway':
                // User wants to proceed to a high-risk site
                if (message.url) {
                    allowProceedForSession(message.url);
                    sendResponse({ status: 'success' });
                } else {
                    sendResponse({ status: 'error', error: 'No URL provided' });
                }
                break;
                
            case 'trust_site':
                if (!message.domain) {
                    console.error('Kavach: Invalid trust_site request, missing domain');
                    sendResponse({ success: false, error: 'Invalid request. Missing domain.' });
                    return true;
                }
                
                // Get current whitelist and blocklist
                chrome.storage.local.get(['whitelist', 'blocklist'], function(data) {
                    let whitelist = data.whitelist || [];
                    let blocklist = data.blocklist || [];
                    const domain = message.domain;
                    const action = message.trustAction || 'add';
                    
                    if (action === 'add') {
                        // Add domain to whitelist if not already present
                        if (!whitelist.includes(domain)) {
                            whitelist.push(domain);
                        }
                        
                        // Remove from blocklist if present
                        blocklist = blocklist.filter(d => d !== domain);
                    } else if (action === 'remove') {
                        // Remove domain from whitelist
                        whitelist = whitelist.filter(d => d !== domain);
                    }
                    
                    // Save updated whitelist and blocklist
                    chrome.storage.local.set({ 
                        whitelist: whitelist, 
                        blocklist: blocklist 
                    }, function() {
                        if (chrome.runtime.lastError) {
                            console.error('Kavach: Error saving whitelist/blocklist:', chrome.runtime.lastError);
                            sendResponse({ success: false, error: chrome.runtime.lastError.message });
                        } else {
                            console.log('Kavach: Updated whitelist:', whitelist);
                            console.log('Kavach: Updated blocklist:', blocklist);
                            sendResponse({ success: true, whitelist: whitelist, blocklist: blocklist });
                        }
                    });
                });
                
                return true; // Indicates we'll respond asynchronously
                
            case 'open_detailed_report':
                const reportUrl = chrome.runtime.getURL(`report.html?url=${encodeURIComponent(message.url)}`);
                chrome.tabs.create({ url: reportUrl });
                sendResponse({ status: 'success' });
                return true;
                
            default:
                console.warn('Kavach: Unknown action:', message.action);
                sendResponse({ status: 'error', error: 'Unknown action' });
        }
    } catch (error) {
        console.error('Kavach: Error handling message:', error);
        sendResponse({ status: 'error', error: 'Internal error processing request' });
    }
}

// Analyze data from content script
async function analyzeData(data, tabId) {
    // Check if analysis is already in progress for this URL
    if (analysisInProgress[data.url]) {
        console.log('Kavach: Analysis already in progress for:', data.url);
        return { status: 'in_progress' };
    }
    
    // Mark as in progress
    analysisInProgress[data.url] = true;
    
    try {
        // First check if the API server is available
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout
            
            const statusResponse = await fetch(`${API_ENDPOINT}/status`, {
                method: 'GET',
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!statusResponse.ok) {
                console.error('Kavach: API server is not available');
                // Update badge to error state
                updateBadge('error', tabId);
                delete analysisInProgress[data.url];
                return { 
                    status: 'error',
                    message: 'Security service is currently unavailable. Please try again later.',
                    timestamp: new Date().toISOString()
                };
            }
        } catch (error) {
            console.error('Kavach: API server check failed:', error);
            // Update badge to error state
            updateBadge('error', tabId);
            delete analysisInProgress[data.url];
            return { 
                status: 'error',
                message: 'Security service is currently unavailable. Please try again later.',
                timestamp: new Date().toISOString()
            };
        }
        
        // Retrieve whitelist and blocklist
        const storage = await chrome.storage.local.get(['whitelist', 'blocklist', 'protection_enabled', 'apiEndpoint']);
        const whitelist = storage.whitelist || [];
        const blocklist = storage.blocklist || [];
        const protectionEnabled = storage.protection_enabled !== undefined ? storage.protection_enabled : true;
        const apiEndpoint = storage.apiEndpoint || API_ENDPOINT;
        
        // Check if protection is disabled
        if (!protectionEnabled) {
            delete analysisInProgress[data.url];
            return { 
                risk_score: 0,
                confidence: 100,
                timestamp: new Date().toISOString(),
                message: 'Protection disabled',
                findings: []
            };
        }
        
        // Parse URL
        let domain = "";
        try {
            const urlObj = new URL(data.url);
            domain = urlObj.hostname;
        } catch (error) {
            console.error('Kavach: Error parsing URL:', error);
        }
        
        // Check if the domain is whitelisted
        if (domain && whitelist.includes(domain)) {
            console.log('Kavach: Domain is whitelisted:', domain);
            delete analysisInProgress[data.url];
            return { 
                risk_score: 0,
                risk_level: 'Safe',
                confidence: 100,
                timestamp: new Date().toISOString(),
                message: 'Domain is whitelisted',
                findings: [],
                component_scores: {
                    url_risk: 0,
                    visual_risk: 0,
                    behavior_risk: 0,
                    ssl_risk: 0
                }
            };
        }
        
        // Check if the domain is blocklisted
        if (domain && blocklist.includes(domain)) {
            console.log('Kavach: Domain is blocklisted:', domain);
            updateBadge('danger', tabId);
            delete analysisInProgress[data.url];
            return { 
                risk_score: 1.0,
                risk_level: 'High',
                confidence: 100,
                timestamp: new Date().toISOString(),
                message: 'Domain is blocked',
                findings: [{
                    type: "Blocked Site",
                    description: "This site has been blocked by your configuration",
                    severity: 1.0
                }],
                component_scores: {
                    url_risk: 1.0,
                    visual_risk: 1.0,
                    behavior_risk: 1.0,
                    ssl_risk: 1.0
                }
            };
        }
        
        // Update badge to indicate analysis in progress
        updateBadge('progress', tabId);
        
        // Send data to API for analysis
        console.log('Kavach: Sending data to API for analysis:', data.url);
        let retries = 0;
        let apiResult = null;
        let lastError = null;
        
        while (retries <= MAX_RETRIES && !apiResult) {
            try {
                const response = await fetch(`${apiEndpoint}/analyze`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                if (!response.ok) {
                    throw new Error(`API responded with status: ${response.status}`);
                }
                
                apiResult = await response.json();
                
            } catch (error) {
                console.error(`Kavach: API request failed (attempt ${retries + 1}/${MAX_RETRIES + 1}):`, error);
                lastError = error;
                retries++;
                
                // Only wait if we're going to retry
                if (retries <= MAX_RETRIES) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * retries)); // Exponential backoff
                }
            }
        }
        
        if (!apiResult) {
            // All retries failed
            delete analysisInProgress[data.url];
            const errorMsg = `API request failed after ${MAX_RETRIES + 1} attempts: ${lastError ? lastError.message : 'Unknown error'}`;
            console.error('Kavach: ' + errorMsg);
            notifyAnalysisFailed(data.url, errorMsg, tabId);
            throw new Error(errorMsg);
        }
        
        // Add a recommendations array if not present
        if (!apiResult.recommendations) {
            apiResult.recommendations = [];
        }
        
        // Add a recommendation to block if high risk
        if (apiResult.risk_score > 0.7) {
            apiResult.recommendations.push({
                type: 'action',
                priority: 'high',
                message: 'Consider blocking this high-risk website for your safety.'
            });
        }
        
        // Store analysis result in local storage
        await storeAnalysisResult(data.url, apiResult);
        
        // Update badge based on risk score
        updateBadge(apiResult.risk_level, tabId);
        
        // Mark as completed
        delete analysisInProgress[data.url];
        
        return apiResult;
    } catch (error) {
        // Clean up in case of error
        delete analysisInProgress[data.url];
        updateBadge('error', tabId);
        console.error('Kavach: Error in analyzeData:', error);
        throw error;
    }
}

// Process the analysis result
function processAnalysisResult(result, url, tabId) {
    if (!result) {
        console.error('Kavach: Received empty analysis result');
        return;
    }
    
    // Store the result
    storeAnalysisResult(url, result);
    
    // Update badge
    updateBadge(result.risk_level, tabId);
    
    // Check if we should display a warning for high-risk sites
    chrome.storage.local.get(['auto_block_high_risk'], function(data) {
        const blockHighRisk = data.auto_block_high_risk !== undefined ? data.auto_block_high_risk : true;
        
        if (blockHighRisk && result.risk_level === 'high') {
            // Display warning page for high-risk sites
            displayWarningPage(url, result, tabId);
        }
    });
    
    // Clean up
    if (analysisInProgress[url]) {
        delete analysisInProgress[url];
    }
}

// Notify that analysis has failed
function notifyAnalysisFailed(url, error, tabId) {
    // Update badge to show error
    updateBadge('error', tabId);
    
    // Notify content script and popup about the failure
    chrome.tabs.sendMessage(tabId, {
        action: 'analysis_failed',
        url: url,
        error: error
    }).catch(err => {
        console.error('Kavach: Failed to notify content script about analysis failure:', err);
    });
    
    // Also broadcast to the popup if open
    chrome.runtime.sendMessage({
        action: 'analysis_failed',
        url: url,
        error: error
    }).catch(err => {
        // This may fail if popup is not open, which is expected
        console.log('Kavach: Failed to notify popup about analysis failure:', err);
    });
    
    // Clean up
    if (analysisInProgress[url]) {
        delete analysisInProgress[url];
    }
}

// Store analysis result in local storage
async function storeAnalysisResult(url, result) {
    console.log('Storing analysis result for URL:', url);
    
    try {
        // Get existing analysis cache
        const data = await chrome.storage.local.get(['analysis_cache']);
        const cache = data.analysis_cache || {};
        
        // Add to cache with timestamp
        cache[url] = {
            timestamp: new Date().toISOString(),
            data: result
        };
        
        // Store updated cache
        await chrome.storage.local.set({ analysis_cache: cache });
        console.log('Analysis result stored successfully');
        
        return true;
    } catch (error) {
        console.error('Error storing analysis result:', error);
        return false;
    }
}

// Check if URL has been analyzed recently
async function checkAnalysisCache(url) {
    try {
        // Get current analysis results
        const storage = await chrome.storage.local.get(['analysis_cache']);
        const results = storage.analysis_cache || {};
        
        // Check if we have a recent result for this URL
        if (results[url] && (Date.now() - results[url].timestamp < ANALYSIS_CACHE_TIME)) {
            return results[url];
        }
        
        return null;
    } catch (error) {
        console.error('Kavach: Error checking analysis cache:', error);
        return null;
    }
}

// Get analysis result from local storage
async function getAnalysisResult(url) {
    console.log('Getting analysis result for URL:', url);
    
    try {
        // Get analysis cache
        const data = await chrome.storage.local.get(['analysis_cache']);
        const cache = data.analysis_cache || {};
        
        // Check if we have a cached result for this URL
        if (cache[url]) {
            const timestamp = new Date(cache[url].timestamp);
            const now = new Date();
            const ageInMinutes = (now - timestamp) / (1000 * 60);
            
            // If the cached result is less than 5 minutes old, use it
            if (ageInMinutes < 5) {
                console.log('Using cached analysis result from', timestamp);
                return cache[url].data;
            } else {
                console.log('Cached result is too old:', ageInMinutes.toFixed(2), 'minutes');
            }
        } else {
            console.log('No cached result found for URL:', url);
        }
        
        return null;
    } catch (error) {
        console.error('Error getting analysis result:', error);
        return null;
    }
}

// Add domain to whitelist
async function addToWhitelist(domain) {
    try {
        // Get current whitelist
        const storage = await chrome.storage.local.get(['whitelist']);
        let whitelist = storage.whitelist || [];
        
        // Check if domain is already in whitelist
        if (!whitelist.includes(domain)) {
            whitelist.push(domain);
            await chrome.storage.local.set({ whitelist: whitelist });
        }
        
        return { success: true, message: `Added ${domain} to whitelist` };
    } catch (error) {
        console.error('Kavach: Error adding to whitelist:', error);
        throw error;
    }
}

// Remove domain from whitelist
async function removeFromWhitelist(domain) {
    return new Promise((resolve, reject) => {
        if (!domain) {
            reject(new Error('No domain provided'));
            return;
        }
        
        chrome.storage.local.get('whitelist', result => {
            let whitelist = result.whitelist || [];
            
            // Check if domain is in whitelist
            if (!whitelist.includes(domain)) {
                resolve(whitelist);
                return;
            }
            
            // Remove domain from whitelist
            whitelist = whitelist.filter(d => d !== domain);
            
            chrome.storage.local.set({ whitelist }, () => {
                resolve(whitelist);
            });
        });
    });
}

// Update protection status
function handleProtectionStatusChange(enabled) {
    if (!enabled) {
        // Clear all badges when protection is disabled
        chrome.tabs.query({}, tabs => {
            tabs.forEach(tab => {
                updateBadge('disabled', tab.id);
            });
        });
    } else {
        // Reanalyze current tab when protection is enabled
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            if (tabs.length > 0) {
                const tab = tabs[0];
                if (tab.url.startsWith('http')) {
                    updateBadge('scanning', tab.id);
                }
            }
        });
    }
}

// Allow proceeding to a risky site for the current session
function allowProceedForSession(url) {
    // Implementation of allowing proceeding to a risky site for the current session
    // This is a placeholder and should be implemented based on your specific requirements
    console.warn('Proceeding to risky site:', url);
}

// Show warning page
function displayWarningPage(url, result, tabId) {
    const warningUrl = chrome.runtime.getURL('warning.html') + 
                      `?url=${encodeURIComponent(url)}` +
                      `&score=${encodeURIComponent(result.risk_score)}` +
                      `&findings=${encodeURIComponent(JSON.stringify(result.findings || []))}`;
    
    chrome.tabs.update(tabId, { url: warningUrl });
}

// Update badge based on risk level
function updateBadge(riskLevel, tabId) {
    let color, text;
    
    switch (riskLevel) {
        case 'high':
            color = '#e74c3c';
            text = '!';
            break;
        case 'medium':
            color = '#f39c12';
            text = '?';
            break;
        case 'low':
            color = '#2ecc71';
            text = '✓';
            break;
        case 'scanning':
            color = '#3498db';
            text = '...';
            break;
        case 'disabled':
            color = '#95a5a6';
            text = 'OFF';
            break;
        case 'progress':
            color = '#3498db';
            text = '...';
            break;
        case 'error':
            color = '#e74c3c';
            text = '!';
            break;
        case 'danger':
            color = '#e74c3c';
            text = '!';
            break;
        default:
            color = '#95a5a6';
            text = '?';
    }
    
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    chrome.action.setBadgeText({ text: text, tabId: tabId });
}

// Add domain to blocklist
async function addToBlocklist(domain) {
    try {
        // Get current blocklist
        const storage = await chrome.storage.local.get(['blocklist']);
        let blocklist = storage.blocklist || [];
        
        // Check if domain is already in blocklist
        if (!blocklist.includes(domain)) {
            blocklist.push(domain);
            await chrome.storage.local.set({ blocklist: blocklist });
        }
        
        return { success: true, message: `Added ${domain} to blocklist` };
    } catch (error) {
        console.error('Kavach: Error adding to blocklist:', error);
        throw error;
    }
}

// Check for blocked sites when tabs are updated
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    // Only check when the page is loaded
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        try {
            const url = new URL(tab.url);
            const domain = url.hostname;
            
            // Check if the domain is in the blocklist
            chrome.storage.local.get(['blocklist'], function(data) {
                const blocklist = data.blocklist || [];
                
                if (blocklist.includes(domain)) {
                    console.log('Kavach: Blocked site detected:', domain);
                    
                    // Redirect to the blocked page
                    chrome.tabs.update(tabId, {
                        url: chrome.runtime.getURL('blocked.html') + `?domain=${encodeURIComponent(domain)}`
                    });
                }
            });
        } catch (error) {
            console.error('Kavach: Error checking if site is blocked:', error);
        }
    }
}); 