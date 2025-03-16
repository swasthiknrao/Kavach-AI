// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "blockSite") {
        // Create a div that covers the entire page
        const blockOverlay = document.createElement('div');
        blockOverlay.id = 'kavach-block-overlay';
        blockOverlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: #f44336;
            color: white;
            z-index: 9999999;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
            padding: 20px;
            box-sizing: border-box;
        `;
        
        blockOverlay.innerHTML = `
            <h1 style="font-size: 28px; margin-bottom: 20px;">⚠️ Site Blocked</h1>
            <p style="font-size: 16px; margin-bottom: 30px;">This site has been blocked for your security by Kavach AI Security.</p>
            <button id="kavach-unblock-btn" style="
                background-color: white;
                color: #f44336;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                cursor: pointer;
                font-size: 14px;
            ">Unblock Site</button>
        `;
        
        document.body.appendChild(blockOverlay);
        
        // Add event listener to the unblock button
        document.getElementById('kavach-unblock-btn').addEventListener('click', () => {
            // Send message to background script to unblock the site
            chrome.runtime.sendMessage({
                type: 'updateBlockedSites',
                url: window.location.href,
                action: 'remove'
            });
            
            // Remove the overlay
            document.getElementById('kavach-block-overlay').remove();
        });
        
        // Prevent scrolling on the page
        document.body.style.overflow = 'hidden';
    } else if (request.action === "trustSite") {
        // If there's a block overlay, remove it
        const blockOverlay = document.getElementById('kavach-block-overlay');
        if (blockOverlay) {
            blockOverlay.remove();
            document.body.style.overflow = 'auto'; // Restore scrolling
        }
        
        // Show a temporary trust notification
        const trustNotification = document.createElement('div');
        trustNotification.id = 'kavach-trust-notification';
        trustNotification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background-color: #00c853;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            font-family: Arial, sans-serif;
            font-size: 14px;
            z-index: 9999999;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            animation: kavach-fade-in 0.3s ease-in-out;
        `;
        
        trustNotification.innerHTML = `
            <div style="display: flex; align-items: center;">
                <span style="font-size: 20px; margin-right: 10px;">✓</span>
                <div>
                    <div style="font-weight: bold; margin-bottom: 5px;">Site Trusted</div>
                    <div>This site has been added to your trusted sites list.</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(trustNotification);
        
        // Create and add the CSS animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes kavach-fade-in {
                from { opacity: 0; transform: translateY(-20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            @keyframes kavach-fade-out {
                from { opacity: 1; transform: translateY(0); }
                to { opacity: 0; transform: translateY(-20px); }
            }
            .kavach-fade-out {
                animation: kavach-fade-out 0.3s ease-in-out forwards;
            }
        `;
        document.head.appendChild(style);
        
        // Remove the notification after 3 seconds
        setTimeout(() => {
            const notification = document.getElementById('kavach-trust-notification');
            if (notification) {
                notification.classList.add('kavach-fade-out');
                setTimeout(() => notification.remove(), 300);
            }
        }, 3000);
    }
});

// Check if the site is blocked when the page loads
chrome.storage.sync.get(['blockedSites'], (result) => {
    const blockedSites = result.blockedSites || [];
    if (blockedSites.includes(window.location.href)) {
        // Trigger the block action
        chrome.runtime.sendMessage({
            type: 'analyzePageContent',
            action: 'blockSite'
        });
    }
});

// Send page data to backend for analysis
document.addEventListener('DOMContentLoaded', () => {
    const pageData = {
        url: window.location.href,
        content: document.documentElement.outerHTML,
        timestamp: Date.now()
    };

    // Send data to background script for analysis
    chrome.runtime.sendMessage({
        type: 'analyzePageContent',
        data: pageData
    });

    // Try to connect to backend if available
    fetch('http://localhost:5000/api/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(pageData)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Backend API error: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // Send analysis results to background script
        chrome.runtime.sendMessage({
            type: 'backendAnalysisResult',
            data: data
        });
    })
    .catch(error => {
        console.warn('Backend connection error:', error);
        // Continue with local analysis only
    });
}); 