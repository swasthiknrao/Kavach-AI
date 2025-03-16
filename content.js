// Kavach AI Security - Content Script
console.log('Kavach: Content script loaded for', window.location.href);

// Configuration
const MAX_RETRIES = 2;
const BACKGROUND_TIMEOUT = 10000; // 10 seconds timeout for background requests
const API_TIMEOUT = 15000; // 15 seconds timeout for direct API requests
let isAnalyzing = false;
let analysisComplete = false;

// Initialize - Set up event listeners and run initial analysis
function initialize() {
    // Listen for messages from popup or background
    chrome.runtime.onMessage.addListener(handleMessage);
    
    // Automatically analyze page after a delay to ensure full page loading
    setTimeout(function() {
        if (!analysisComplete && document.readyState === 'complete') {
            console.log('Kavach: Auto-analyzing page after load');
            collectAndSendPageData();
        }
    }, 2500); // Extended delay to ensure page is fully loaded
}

// Handle messages from popup or background
function handleMessage(message, sender, sendResponse) {
    if (!message || !message.action) {
        console.error('Kavach: Received message without action');
        sendResponse({ status: 'error', error: 'No action specified' });
        return;
    }
    
    console.log('Kavach: Content script received action:', message.action);
    
    switch (message.action) {
        case 'analyze_page':
            // Check if analysis is already in progress or complete
            if (isAnalyzing) {
                console.log('Kavach: Analysis already in progress, ignoring duplicate request');
                sendResponse({ status: 'collecting', message: 'Analysis already in progress' });
                return;
            }
            
            if (analysisComplete && !message.forceNew) {
                console.log('Kavach: Analysis already complete, not reanalyzing');
                sendResponse({ status: 'complete', message: 'Analysis already complete' });
                return;
            }
            
            // Perform analysis
            console.log('Kavach: Starting page analysis');
            collectAndSendPageData()
                .then(() => sendResponse({ status: 'collecting' }))
                .catch(error => {
                    console.error('Kavach: Error in analyze_page:', error);
                    sendResponse({ status: 'error', error: error.message });
                });
            
            // Return true to indicate async response
            return true;
            
        case 'analysis_failed':
            console.error('Kavach: Analysis failed:', message.error);
            analysisComplete = false;
            isAnalyzing = false;
            sendResponse({ status: 'acknowledged' });
            break;
            
        case 'GET_PAGE_CONTENT':
            console.log("Kavach: Received request for page content");
            
            // Collect page data
            const pageData = collectPageData();
            
            // Send response back to popup
            sendResponse({
                content: document.documentElement.outerHTML,
                behavior: pageData
            });
            
            return true; // Required for async response
            
        default:
            console.warn('Kavach: Unknown action:', message.action);
    }
}

// Collect page data and send to background script
async function collectAndSendPageData() {
    if (isAnalyzing) {
        console.log('Kavach: Already analyzing, skipping duplicate collection');
    return;
  }
  
    isAnalyzing = true;
    console.log('Kavach: Collecting page data...');
    
    try {
        // Collect data from the page
        const pageData = {
      url: window.location.href,
      domain: window.location.hostname,
            timestamp: new Date().toISOString(),
            content: {
                title: document.title,
                metaTags: extractMetaTags(),
                links: extractLinks(),
                images: extractImages(),
                formCount: document.forms.length,
                inputFields: extractInputFields(),
                scripts: extractScripts(),
                iframe_count: document.getElementsByTagName('iframe').length
            },
            behavior: {
                hasLoginForm: hasLoginForm(),
                externalLinks: countExternalLinks(),
                redirectCount: countRedirects(),
                hasPasswordField: document.querySelector('input[type="password"]') !== null,
                suspiciousEventListeners: captureEventListeners(),
                potentialKeyloggers: detectKeyloggers(),
                loadTime: performance.timing ? (performance.timing.loadEventEnd - performance.timing.navigationStart) : null,
                certificateInfo: getCertificateInfo()
            }
        };
        
        console.log('Kavach: Data collection complete');
        
        // Send data to background script
        let retryCount = 0;
        let success = false;
        
        while (retryCount <= MAX_RETRIES && !success) {
            try {
                console.log(`Kavach: Sending data to background script (attempt ${retryCount + 1}/${MAX_RETRIES + 1})`);
                
                // Use a promise with timeout to send data to background script
                const result = await sendDataToBackgroundWithTimeout(pageData);
                
                if (result && result.status === 'success') {
                    success = true;
                    console.log('Kavach: Analysis completed successfully:', result);
                    analysisComplete = true;
                    notifyAnalysisComplete(result.result);
                } else {
                    console.warn('Kavach: Background script returned error or no result', result);
                    throw new Error('Background script error: ' + (result?.error || 'No response'));
                }
            } catch (error) {
                console.error(`Kavach: Error sending to background script (attempt ${retryCount + 1}):`, error);
                retryCount++;
                
                if (retryCount <= MAX_RETRIES) {
                    console.log(`Kavach: Retrying in ${retryCount} second(s)...`);
                    await new Promise(resolve => setTimeout(resolve, retryCount * 1000));
                }
            }
        }
        
        // If all background script attempts failed, try direct API call
        if (!success) {
            console.log('Kavach: All background script attempts failed, trying direct API');
            await sendDirectApiRequest(pageData);
        }
    } catch (error) {
        console.error('Kavach: Error in collectAndSendPageData:', error);
        isAnalyzing = false;
        throw error;
    } finally {
        isAnalyzing = false;
    }
}

// Send data to background script with timeout
function sendDataToBackgroundWithTimeout(data) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error('Background script request timed out'));
        }, BACKGROUND_TIMEOUT);
        
        chrome.runtime.sendMessage(
            { action: 'analyze_data', data: data, expectsResponse: true },
            function(response) {
                clearTimeout(timeout);
                
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
    return;
  }
  
                if (!response) {
                    reject(new Error('No response from background script'));
                    return;
                }
                
                resolve(response);
            }
        );
    });
}

// Fallback: Send data directly to API
async function sendDirectApiRequest(data) {
    console.log('Kavach: Attempting direct API call...');
    
    try {
        // Get API endpoint from storage, or use default
        const storage = await chrome.storage.local.get(['apiEndpoint']);
        const apiEndpoint = storage.apiEndpoint || 'http://127.0.0.1:9000/api';
        
        // First check if the server is available
        try {
            const statusResponse = await fetch(`${apiEndpoint}/status`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (!statusResponse.ok) {
                throw new Error(`API status check failed: ${statusResponse.status}`);
            }
            
            console.log('Kavach: API server is available');
        } catch (error) {
            console.error('Kavach: API server is not available:', error);
            notifyAnalysisFailed('Server unavailable. Please make sure the backend is running.');
            return null;
        }
        
        // Try quick-scan endpoint first (faster)
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);
            
            const response = await fetch(`${apiEndpoint}/quick-scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: data.url,
                    domain: data.domain,
                    timestamp: data.timestamp,
                    basic_info: {
                        title: data.content.title,
                        has_login_form: data.behavior.hasLoginForm,
                        has_password_field: data.behavior.hasPasswordField,
                        external_links: data.behavior.externalLinks,
                        protocol: window.location.protocol
                    }
                }),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`API responded with status: ${response.status}`);
            }
            
            const result = await response.json();
            console.log('Kavach: Quick-scan successful:', result);
            
            // Notify about analysis completion
            analysisComplete = true;
            notifyAnalysisComplete(result);
            
            return result;
        } catch (error) {
            console.warn('Kavach: Quick-scan failed, trying full analysis:', error);
            
            // Try the full analysis endpoint as fallback
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);
            
            const response = await fetch(`${apiEndpoint}/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`API responded with status: ${response.status}`);
            }
            
            const result = await response.json();
            console.log('Kavach: Full analysis successful:', result);
            
            // Notify about analysis completion
            analysisComplete = true;
            notifyAnalysisComplete(result);
            
            return result;
        }
    } catch (error) {
        console.error('Kavach: Direct API request failed:', error);
        
        // Notify about analysis failure
        notifyAnalysisFailed(error.message);
        
        throw error;
    }
}

// Notify background script and popup about analysis completion
function notifyAnalysisComplete(result) {
    chrome.runtime.sendMessage({
        action: 'analysis_complete',
        url: window.location.href,
        result: result
    }).catch(error => {
        console.error('Kavach: Error notifying about analysis completion:', error);
    });
}

// Notify about analysis failure
function notifyAnalysisFailed(error) {
    chrome.runtime.sendMessage({
        action: 'analysis_failed',
        url: window.location.href,
        error: error
    }).catch(err => {
        console.error('Kavach: Error notifying about analysis failure:', err);
    });
}

// Helper Functions for Data Collection

// Extract meta tags
function extractMetaTags() {
    const metaTags = {};
    const tags = document.getElementsByTagName('meta');
    
    for (let i = 0; i < tags.length; i++) {
        const name = tags[i].getAttribute('name') || tags[i].getAttribute('property');
        if (name) {
            metaTags[name] = tags[i].getAttribute('content');
        }
    }
    
    return metaTags;
}

// Extract links
function extractLinks() {
    const links = [];
    const allLinks = document.getElementsByTagName('a');
    
    // Limit to first 50 links to avoid excessive data
    const limit = Math.min(allLinks.length, 50);
    
    for (let i = 0; i < limit; i++) {
        const href = allLinks[i].getAttribute('href');
        if (href) {
            links.push({
                text: allLinks[i].textContent.trim().substring(0, 100),
                href: href
            });
        }
    }
    
    return links;
}

// Extract images
function extractImages() {
    const images = [];
    const allImages = document.getElementsByTagName('img');
    
    // Limit to first 20 images to avoid excessive data
    const limit = Math.min(allImages.length, 20);
    
    for (let i = 0; i < limit; i++) {
        const src = allImages[i].getAttribute('src');
        if (src) {
            images.push({
                alt: allImages[i].getAttribute('alt') || '',
                src: src
            });
        }
    }
    
    return images;
}

// Extract input fields
function extractInputFields() {
    const inputs = [];
    const allInputs = document.getElementsByTagName('input');
    
    for (let i = 0; i < allInputs.length; i++) {
        inputs.push({
            type: allInputs[i].getAttribute('type') || 'text',
            name: allInputs[i].getAttribute('name'),
            id: allInputs[i].getAttribute('id'),
            placeholder: allInputs[i].getAttribute('placeholder')
        });
    }
    
    return inputs;
}

// Extract script information
function extractScripts() {
    const scripts = [];
    const allScripts = document.getElementsByTagName('script');
    
    // Limit to 30 scripts to avoid excessive data
    const limit = Math.min(allScripts.length, 30);
    
    for (let i = 0; i < limit; i++) {
        const src = allScripts[i].getAttribute('src');
        if (src) {
            scripts.push({
                src: src,
                type: allScripts[i].getAttribute('type') || 'text/javascript'
            });
        }
    }
    
    return scripts;
}

// Check if the page has a login form
function hasLoginForm() {
    // Check for password fields
    if (document.querySelector('input[type="password"]')) {
        return true;
    }
    
    // Check for common login form attributes
    const forms = document.getElementsByTagName('form');
    for (let i = 0; i < forms.length; i++) {
        const formAction = forms[i].getAttribute('action') || '';
        const formId = forms[i].getAttribute('id') || '';
        const formClass = forms[i].getAttribute('class') || '';
        
        if (
            formAction.toLowerCase().includes('login') ||
            formAction.toLowerCase().includes('signin') ||
            formId.toLowerCase().includes('login') ||
            formId.toLowerCase().includes('signin') ||
            formClass.toLowerCase().includes('login') ||
            formClass.toLowerCase().includes('signin')
        ) {
            return true;
        }
    }
    
    return false;
}

// Count external links
function countExternalLinks() {
    const currentDomain = window.location.hostname;
    const links = document.getElementsByTagName('a');
    let externalCount = 0;
    
    for (let i = 0; i < links.length; i++) {
        try {
            const href = links[i].getAttribute('href');
            if (href && !href.startsWith('#') && !href.startsWith('/')) {
                const linkUrl = new URL(href, window.location.href);
                if (linkUrl.hostname !== currentDomain) {
                externalCount++;
                }
            }
  } catch (e) {
            // Invalid URL, ignore
        }
    }
    
    return externalCount;
}

// Count redirects
function countRedirects() {
    if (!performance || !performance.navigation) {
        return 0;
    }
    return performance.navigation.redirectCount || 0;
}

// Capture event listeners that may be suspicious
function captureEventListeners() {
    const suspicious = [];
    
    // Check for keypress, keydown, keyup listeners
    if (getEventListeners && typeof getEventListeners === 'function') {
        try {
            const documentListeners = getEventListeners(document);
            const bodyListeners = getEventListeners(document.body);
            
            const keyEvents = ['keydown', 'keypress', 'keyup'];
            
            keyEvents.forEach(event => {
                if (documentListeners[event] && documentListeners[event].length > 0) {
                    suspicious.push(`document:${event}`);
                }
                if (bodyListeners[event] && bodyListeners[event].length > 0) {
                    suspicious.push(`body:${event}`);
                }
            });
        } catch (e) {
            // getEventListeners only works in devtools console
        }
    }
    
    // Check for paste event listeners on inputs
    const inputs = document.getElementsByTagName('input');
    for (let i = 0; i < inputs.length; i++) {
        if (inputs[i].onpaste) {
            suspicious.push('input:paste');
            break;
        }
    }
    
    return suspicious;
}

// Detect potential keyloggers
function detectKeyloggers() {
    // This is a simplified check - in a real implementation, this would be more sophisticated
    const scripts = document.getElementsByTagName('script');
    const keyloggerPatterns = [
        'keypress',
        'keydown',
        'keyup',
        'addEventListener\\([\'"]key',
        'onkeypress',
        'onkeydown',
        'onkeyup'
    ];
    
    const detected = [];
    
    for (let i = 0; i < scripts.length; i++) {
        if (!scripts[i].textContent) continue;
        
        const scriptContent = scripts[i].textContent;
        for (const pattern of keyloggerPatterns) {
            if (new RegExp(pattern, 'i').test(scriptContent)) {
                detected.push(pattern);
            }
        }
    }
    
    return detected.length > 0;
}

// Get certificate info
function getCertificateInfo() {
    // Basic security properties
    return {
        protocol: window.location.protocol,
        isSecure: window.location.protocol === 'https:',
        referrer: document.referrer
    };
}

// Collect page data for security analysis
function collectPageData() {
  try {
    console.log("Kavach: Collecting page data");
    
    const pageData = {
      url: window.location.href,
      domain: window.location.hostname,
      title: document.title,
      hasLoginForm: detectLoginForm(),
      hasPasswordField: document.querySelector('input[type="password"]') !== null,
      forms: document.forms.length,
      iframes: document.getElementsByTagName('iframe').length,
      scripts: collectScripts(),
      externalLinks: collectExternalLinks(),
      hiddenElements: document.querySelectorAll('[style*="display:none"], [style*="display: none"], [hidden]').length,
      eventListeners: captureEventListeners(),
      potentialKeyloggers: detectKeyloggers()
    };
    
    console.log("Kavach: Page data collected successfully");
    return pageData;
  } catch (error) {
    console.error("Kavach: Error collecting page data:", error);
    return {
      url: window.location.href,
      domain: window.location.hostname,
      error: true,
      errorMessage: error.message
    };
  }
}

// Detect if page has login form
function detectLoginForm() {
  // Check for password fields
  const hasPasswordField = document.querySelector('input[type="password"]') !== null;
  
  // Check for login/signin in form action or ID/class
  const forms = Array.from(document.forms);
  const loginFormDetected = forms.some(form => {
    const formHTML = form.outerHTML.toLowerCase();
    return formHTML.includes('login') || 
           formHTML.includes('signin') || 
           formHTML.includes('sign-in') ||
           formHTML.includes('log-in') ||
           formHTML.includes('auth');
  });
  
  // Check for login buttons
  const buttons = Array.from(document.querySelectorAll('button, input[type="submit"]'));
  const loginButtonDetected = buttons.some(btn => {
    const btnText = (btn.textContent || btn.value || '').toLowerCase();
    const btnHTML = btn.outerHTML.toLowerCase();
    return btnText.includes('login') || 
           btnText.includes('sign in') ||
           btnText.includes('log in') || 
           btnHTML.includes('login') || 
           btnHTML.includes('signin');
  });
  
  return hasPasswordField || loginFormDetected || loginButtonDetected;
}

// Collect scripts from the page
function collectScripts() {
  try {
    const scripts = Array.from(document.scripts);
    
    // Extract inline script content (limited to first 50 chars per script)
    return scripts
      .filter(script => script.textContent && script.textContent.trim().length > 0)
      .map(script => script.textContent.trim().substring(0, 50))
      .slice(0, 10); // Limit to 10 scripts to avoid excessive data
  } catch (error) {
    console.error("Kavach: Error collecting scripts:", error);
    return [];
  }
}

// Collect external links from the page
function collectExternalLinks() {
  try {
    const links = Array.from(document.links);
    const currentDomain = window.location.hostname;
    
    return links
      .filter(link => {
        try {
          const linkUrl = new URL(link.href);
          return linkUrl.hostname !== currentDomain;
        } catch {
          return false;
        }
      })
      .map(link => link.href)
      .slice(0, 20); // Limit to 20 links
  } catch (error) {
    console.error("Kavach: Error collecting external links:", error);
    return [];
  }
}

// Capture event listeners on the page
function captureEventListeners() {
  const eventTypes = ['keydown', 'keyup', 'keypress', 'mousemove', 'click', 'submit'];
  const listenersData = {};
  
  try {
    // Count form submission handlers
    const forms = document.forms;
    let formListeners = 0;
    
    for (let i = 0; i < forms.length; i++) {
      if (forms[i].onsubmit || forms[i].getAttribute('onsubmit')) {
        formListeners++;
      }
    }
    
    listenersData.formSubmit = formListeners;
    
    // Count key event handlers
    const inputFields = document.querySelectorAll('input, textarea');
    let keyListeners = 0;
    
    for (let i = 0; i < inputFields.length; i++) {
      const field = inputFields[i];
      if (field.onkeydown || field.onkeyup || field.onkeypress || 
          field.getAttribute('onkeydown') || field.getAttribute('onkeyup') || field.getAttribute('onkeypress')) {
        keyListeners++;
      }
    }
    
    listenersData.keyEvents = keyListeners;
    
    return listenersData;
  } catch (error) {
    console.error("Kavach: Error capturing event listeners:", error);
    return {};
  }
}

// Detect potential keyloggers
function detectKeyloggers() {
  try {
    // Look for suspicious patterns in scripts
    const scripts = Array.from(document.scripts);
    
    for (const script of scripts) {
      if (!script.textContent) continue;
      
      const scriptText = script.textContent.toLowerCase();
      
      // Check for suspicious keylogging patterns
      if ((scriptText.includes('keydown') || scriptText.includes('keyup') || scriptText.includes('keypress')) &&
          (scriptText.includes('fetch(') || scriptText.includes('xmlhttp') || 
           scriptText.includes('ajax') || scriptText.includes('post'))) {
        return true;
      }
      
      // Check for clipboard monitoring
      if ((scriptText.includes('clipboard') || scriptText.includes('oncopy') || scriptText.includes('onpaste')) &&
          (scriptText.includes('fetch(') || scriptText.includes('xmlhttp') || 
           scriptText.includes('ajax') || scriptText.includes('post'))) {
        return true;
      }
    }
    
    return false;
  } catch (error) {
    console.error("Kavach: Error detecting keyloggers:", error);
    return false;
  }
}

// Initialize the content script
initialize(); 