// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('Kavach AI Security Extension installed');
  
  // Initialize storage with empty blocked and trusted sites
  chrome.storage.local.get(['blockedSites', 'trustedSites'], result => {
    if (!result.blockedSites) {
      chrome.storage.local.set({ 'blockedSites': {} });
    }
    if (!result.trustedSites) {
      chrome.storage.local.set({ 'trustedSites': {} });
    }
  });
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    try {
      // Check if site is blocked
      const url = new URL(tab.url);
      const domain = url.hostname;
      
      chrome.storage.local.get(['blockedSites'], result => {
        if (result.blockedSites && result.blockedSites[domain]) {
          // Site is blocked, redirect to blocked page
          console.log(`Blocked site detected: ${domain}`);
          
          // Redirect to blocked page
          chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL('blocked.html') + `?domain=${encodeURIComponent(domain)}`
          });
        } else {
          // Send message to content script to analyze the page
          chrome.tabs.sendMessage(tabId, {
            type: 'ANALYZE_PAGE',
            url: tab.url
          }, response => {
            // Handle possible errors with messaging
            const lastError = chrome.runtime.lastError;
            if (lastError) {
              console.log('Error sending message to content script:', lastError.message);
            }
          });
        }
      });
    } catch (e) {
      console.error('Error processing URL:', e);
    }
  }
});

// Listen for messages from content script or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYSIS_RESULT') {
    // Update extension icon/badge based on risk level
    const risk = request.data.overall_risk;
    const color = risk > 0.7 ? '#ff0000' : risk > 0.4 ? '#ffa500' : '#00ff00';
    
    chrome.action.setBadgeBackgroundColor({ color });
    chrome.action.setBadgeText({
      text: `${Math.round(risk * 100)}%`,
      tabId: sender.tab.id
    });
    
    // Auto-block extremely high risk sites
    if (risk > 0.85) {
      try {
        const url = new URL(sender.tab.url);
        const domain = url.hostname;
        
        chrome.storage.local.get(['blockedSites', 'trustedSites'], result => {
          // Don't block if already trusted
          if (result.trustedSites && result.trustedSites[domain]) {
            return;
          }
          
          // Add to blocked sites with AI-generated reason
          const blockedSites = result.blockedSites || {};
          
          if (!blockedSites[domain]) {
            blockedSites[domain] = {
              url: url.href,
              timestamp: Date.now(),
              risk_factors: {
                url_risk: request.data.url_risk,
                visual_risk: request.data.visual_risk,
                behavior_risk: request.data.behavior_risk,
                overall_risk: request.data.overall_risk
              },
              patterns: request.data.analysis_details?.suspicious_patterns || [],
              ai_block_reason: "Automatically blocked due to extremely high security risk"
            };
            
            chrome.storage.local.set({ 'blockedSites': blockedSites });
            
            // Redirect to blocked page
            chrome.tabs.update(sender.tab.id, {
              url: chrome.runtime.getURL('blocked.html') + `?domain=${encodeURIComponent(domain)}&auto=true`
            });
          }
        });
      } catch (e) {
        console.error('Error auto-blocking site:', e);
      }
    }
  } else if (request.type === 'SITE_BLOCKED') {
    // Handle site blocked from popup
    console.log('Site blocked:', request.data);
    
    // Update browser icon to show blocked status
    chrome.tabs.query({active: true, currentWindow: true}, tabs => {
      if (tabs[0]) {
        chrome.action.setBadgeBackgroundColor({ color: '#ff0000' });
        chrome.action.setBadgeText({
          text: 'BLOCK',
          tabId: tabs[0].id
        });
      }
    });
  } else if (request.type === 'SITE_TRUSTED') {
    // Handle site trusted from popup
    console.log('Site trusted:', request.data);
    
    // Update browser icon to show trusted status
    chrome.tabs.query({active: true, currentWindow: true}, tabs => {
      if (tabs[0]) {
        chrome.action.setBadgeBackgroundColor({ color: '#00C853' });
        chrome.action.setBadgeText({
          text: 'SAFE',
          tabId: tabs[0].id
        });
      }
    });
  }
  
  return true;
});

// Store analysis results
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.analysisResults) {
    const results = changes.analysisResults.newValue;
    console.log('Analysis results updated:', results);
  }
  
  if (namespace === 'local' && changes.blockedSites) {
    console.log('Blocked sites updated:', changes.blockedSites.newValue);
  }
  
  if (namespace === 'local' && changes.trustedSites) {
    console.log('Trusted sites updated:', changes.trustedSites.newValue);
  }
});