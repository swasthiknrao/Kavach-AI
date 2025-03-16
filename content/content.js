// Kavach Security Content Script
console.log("Kavach Security extension activated");

// Configuration
const ANALYSIS_DELAY = 1000; // Wait 1 second after page load before analyzing

// Track page behavior
let behavior = {
  redirectCount: 0,
  forms: 0,
  links: 0,
  scripts: [],
  hasPasswordField: false,
  hasLoginForm: false,
  iframes: 0,
  hiddenElements: 0,
  externalLinks: [],
  eventListeners: {},
  metadata: {}
};

// Store original methods to prevent manipulation
const originalWindowOpen = window.open;
const originalLocationAssign = window.location.assign;
const originalLocationReplace = window.location.replace;
const originalSetTimeout = window.setTimeout;
const originalSetInterval = window.setInterval;
const originalAddEventListener = EventTarget.prototype.addEventListener;
const originalFetch = window.fetch;
const originalXHR = XMLHttpRequest.prototype.open;

// Track redirects
let redirectInitiated = false;
function trackRedirect() {
  if (!redirectInitiated) {
    behavior.redirectCount++;
    redirectInitiated = true;
    // Reset after a short delay to catch multiple fast redirects
    setTimeout(() => { redirectInitiated = false; }, 500);
  }
}

// Override window.open to track popups
window.open = function() {
  behavior.popups = (behavior.popups || 0) + 1;
  return originalWindowOpen.apply(this, arguments);
};

// Override location methods to track redirects
window.location.assign = function() {
  trackRedirect();
  return originalLocationAssign.apply(this, arguments);
};

window.location.replace = function() {
  trackRedirect();
  return originalLocationReplace.apply(this, arguments);
};

// Track event listeners for keylogging and input monitoring
EventTarget.prototype.addEventListener = function(type, listener, options) {
  // Track the event type
  if (!behavior.eventListeners[type]) {
    behavior.eventListeners[type] = [];
  }
  
  // Store a sanitized version with just the function name or "anonymous"
  const functionName = listener.name || "anonymous";
  behavior.eventListeners[type].push(functionName);
  
  // Call original method
  return originalAddEventListener.apply(this, arguments);
};

// Track network requests for potential data exfiltration
window.fetch = function(url, options) {
  try {
    const method = options?.method || 'GET';
    if (method.toUpperCase() === 'POST') {
      behavior.postRequests = (behavior.postRequests || 0) + 1;
    }
  } catch (e) {}
  return originalFetch.apply(this, arguments);
};

XMLHttpRequest.prototype.open = function(method, url) {
  try {
    if (method.toUpperCase() === 'POST') {
      behavior.postRequests = (behavior.postRequests || 0) + 1;
    }
  } catch (e) {}
  return originalXHR.apply(this, arguments);
};

// Function to extract inline script content
function extractScriptContent() {
  try {
    const scriptElements = document.querySelectorAll('script:not([src])');
    const scriptContent = [];
    
    scriptElements.forEach(script => {
      if (script.textContent && script.textContent.trim().length > 0) {
        // Limit script size to prevent excessive data
        const content = script.textContent.substring(0, 1000);
        scriptContent.push(content);
      }
    });
    
    return scriptContent;
  } catch (e) {
    console.error("Error extracting script content:", e);
    return [];
  }
}

// Function to get external links
function getExternalLinks() {
  try {
    const currentDomain = window.location.hostname;
    const externalLinks = [];
    
    document.querySelectorAll('a[href]').forEach(link => {
      try {
        const href = link.href;
        if (href.startsWith('http') && !href.includes(currentDomain)) {
          externalLinks.push(href);
        }
      } catch (e) {}
    });
    
    return externalLinks.slice(0, 20); // Limit to 20 links
  } catch (e) {
    return [];
  }
}

// Function to check for hidden elements that might be deceptive
function detectHiddenElements() {
  try {
    const elements = document.querySelectorAll('div, span, form, input');
    let hiddenCount = 0;
    
    elements.forEach(element => {
      const style = window.getComputedStyle(element);
      if ((style.display === 'none' || style.visibility === 'hidden' || 
           style.opacity === '0' || element.hasAttribute('hidden')) && 
          element.textContent.trim().length > 0) {
        hiddenCount++;
      }
    });
    
    return hiddenCount;
  } catch (e) {
    return 0;
  }
}

// Function to detect password fields and login forms
function checkForSensitiveFields() {
  try {
    // Check for password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    behavior.hasPasswordField = passwordFields.length > 0;
    
    // Check for login forms
    const loginKeywords = ['login', 'log-in', 'signin', 'sign-in', 'auth'];
    const forms = document.querySelectorAll('form');
    
    behavior.hasLoginForm = false;
    forms.forEach(form => {
      // Check form action/id/class for login keywords
      const formText = (form.action || '') + ' ' + (form.id || '') + ' ' + (form.className || '');
      const formTextLower = formText.toLowerCase();
      
      // Check if form contains both username/email and password fields
      const hasUserField = form.querySelector('input[type="text"], input[type="email"]');
      const hasPasswordField = form.querySelector('input[type="password"]');
      
      if ((loginKeywords.some(keyword => formTextLower.includes(keyword)) || 
          (hasUserField && hasPasswordField))) {
        behavior.hasLoginForm = true;
      }
    });
    
    behavior.forms = forms.length;
  } catch (e) {
    console.error("Error checking for sensitive fields:", e);
  }
}

// Function to take screenshot for visual analysis
async function captureVisualData() {
  try {
    // We can't take actual screenshots from content scripts
    // Instead, we'll create a canvas representation of the page
    
    // Get page metadata for visual analysis
    behavior.metadata = {
      title: document.title,
      metaDescription: document.querySelector('meta[name="description"]')?.content || '',
      h1Text: Array.from(document.querySelectorAll('h1')).map(h => h.innerText).join(' '),
      logoCount: document.querySelectorAll('img[src*="logo"]').length,
      colorScheme: getColorScheme()
    };
    
    // Check if the page has a favicon
    const favicon = document.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
    behavior.metadata.hasFavicon = !!favicon;
    
  } catch (e) {
    console.error("Error capturing visual data:", e);
  }
}

// Function to extract dominant colors from the page
function getColorScheme() {
  try {
    const elements = document.querySelectorAll('body, header, nav, .logo, .brand');
    const colors = {};
    
    elements.forEach(el => {
      const style = window.getComputedStyle(el);
      const bgColor = style.backgroundColor;
      const textColor = style.color;
      
      if (bgColor && bgColor !== 'rgba(0, 0, 0, 0)' && bgColor !== 'transparent') {
        colors[bgColor] = (colors[bgColor] || 0) + 1;
      }
      
      if (textColor) {
        colors[textColor] = (colors[textColor] || 0) + 1;
      }
    });
    
    // Get top 3 most common colors
    return Object.entries(colors)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(entry => entry[0]);
  } catch (e) {
    return [];
  }
}

// Add DOM monitoring
function monitorDOMChanges() {
  try {
    // Setup mutation observer to track DOM changes
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        // Check if elements are being added
        if (mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach(node => {
            // Check if the added node is an iframe
            if (node.nodeName === 'IFRAME') {
              behavior.iframes++;
            }
            
            // Check if scripts are being dynamically added
            if (node.nodeName === 'SCRIPT') {
              behavior.dynamicScriptInsertions = (behavior.dynamicScriptInsertions || 0) + 1;
              
              // Capture inline script content if available
              if (!node.src && node.textContent) {
                behavior.scripts.push(node.textContent.substring(0, 500)); // Limit size
              }
            }
          });
        }
      });
    });
    
    // Start observing
    observer.observe(document.body, { 
      childList: true, 
      subtree: true 
    });
    
  } catch (e) {
    console.error("Error setting up DOM monitoring:", e);
  }
}

// Main function to analyze the page
function analyzePage() {
  try {
    console.log("Kavach Security: Analyzing page...");
    
    // Count links
    behavior.links = document.querySelectorAll('a[href]').length;
    
    // Capture external links
    behavior.externalLinks = getExternalLinks();
    
    // Check for iframes
    behavior.iframes = document.querySelectorAll('iframe').length;
    
    // Check for hidden elements
    behavior.hiddenElements = detectHiddenElements();
    
    // Check for password fields and login forms
    checkForSensitiveFields();
    
    // Extract inline scripts
    behavior.scripts = extractScriptContent();
    
    // Record if page uses HTTPS
    behavior.ssl_status = window.location.protocol === 'https:';
    
    // Capture visual data
    captureVisualData();
    
    // Monitor DOM for changes
    monitorDOMChanges();
    
    console.log("Kavach Security: Analysis complete", behavior);
    
    // Send data to background script
    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYZED',
      data: {
        behavior,
        url: window.location.href
      }
    });
  } catch (e) {
    console.error("Kavach Security: Error analyzing page", e);
  }
}

// Function to get page content for analysis
function getPageContent() {
  try {
    // Get page text content
    const textContent = document.body.innerText.substring(0, 10000); // Limit size
    
    // Get behavior data
    const behaviorData = behavior;

    return {
      content: {
        text: textContent,
        title: document.title,
        url: window.location.href
      },
        behavior: behaviorData
    };
  } catch (e) {
    console.error("Error getting page content:", e);
    return {
      content: { text: "", title: "", url: window.location.href },
      behavior: {}
    };
  }
}

// Run analysis after page loads
window.addEventListener('load', () => {
  setTimeout(analyzePage, ANALYSIS_DELAY);
});

// Listen for messages from popup or background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'ANALYZE_PAGE') {
        analyzePage();
    sendResponse({ success: true });
    } else if (request.type === 'GET_PAGE_CONTENT') {
    const pageContent = getPageContent();
    sendResponse(pageContent);
    }
  return true; // Keep message channel open for async response
}); 