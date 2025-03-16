// Content script for Kavach AI Security
console.log("Kavach: Content script loaded");

// Initialize message listener
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.type === 'GET_PAGE_CONTENT') {
    console.log("Kavach: Received request for page content");
    
    // Collect page data
    const pageData = collectPageData();
    
    // Send response back to popup
    sendResponse({
      content: document.documentElement.outerHTML,
      behavior: pageData
    });
    
    return true; // Required for async response
  }
});

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