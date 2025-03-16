// Kavach AI Security - Options Page
document.addEventListener('DOMContentLoaded', loadOptions);

// Save references to DOM elements
const elements = {
    enabledProtection: document.getElementById('enabledProtection'),
    notificationLevel: document.getElementById('notificationLevel'),
    autoBlockHighRisk: document.getElementById('autoBlockHighRisk'),
    collectAnonymousStats: document.getElementById('collectAnonymousStats'),
    whitelistContainer: document.getElementById('whitelist-container'),
    addSiteBtn: document.getElementById('add-site-btn'),
    resetBtn: document.getElementById('reset-btn'),
    saveBtn: document.getElementById('save-btn')
};

// Load options from storage
function loadOptions() {
    chrome.storage.local.get(['settings', 'whitelist'], (data) => {
        const settings = data.settings || getDefaultSettings();
        const whitelist = data.whitelist || [];
        
        // Apply settings to form
        elements.enabledProtection.checked = settings.enabledProtection;
        elements.notificationLevel.value = settings.notificationLevel;
        elements.autoBlockHighRisk.checked = settings.autoBlockHighRisk;
        elements.collectAnonymousStats.checked = settings.collectAnonymousStats;
        
        // Render whitelist
        renderWhitelist(whitelist);
        
        // Set up event listeners
        elements.addSiteBtn.addEventListener('click', addCurrentSite);
        elements.resetBtn.addEventListener('click', resetOptions);
        elements.saveBtn.addEventListener('click', saveOptions);
    });
}

// Get default settings
function getDefaultSettings() {
    return {
        enabledProtection: true,
        notificationLevel: 'medium',
        autoBlockHighRisk: true,
        collectAnonymousStats: false
    };
}

// Render whitelist
function renderWhitelist(whitelist) {
    if (!whitelist || whitelist.length === 0) {
        elements.whitelistContainer.innerHTML = '<div class="empty-list">No websites have been whitelisted yet.</div>';
        return;
    }
    
    let html = '';
    whitelist.forEach(domain => {
        html += `
            <div class="whitelist-item">
                <span>${domain}</span>
                <button class="remove-btn" data-domain="${domain}">Remove</button>
            </div>
        `;
    });
    
    elements.whitelistContainer.innerHTML = html;
    
    // Add event listeners to remove buttons
    document.querySelectorAll('.remove-btn').forEach(button => {
        button.addEventListener('click', (e) => {
            removeFromWhitelist(e.target.dataset.domain);
        });
    });
}

// Add current site to whitelist
function addCurrentSite() {
    // Get current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length === 0) return;
        
        try {
            const url = new URL(tabs[0].url);
            const domain = url.hostname;
            
            if (!domain) return;
            
            // Add to whitelist
            chrome.storage.local.get('whitelist', (data) => {
                const whitelist = data.whitelist || [];
                
                if (whitelist.includes(domain)) {
                    alert(`${domain} is already whitelisted.`);
                    return;
                }
                
                whitelist.push(domain);
                chrome.storage.local.set({ whitelist }, () => {
                    renderWhitelist(whitelist);
                    
                    // Show success message
                    const messageDiv = document.createElement('div');
                    messageDiv.textContent = `Added ${domain} to whitelist`;
                    messageDiv.style = `
                        position: fixed;
                        bottom: 20px;
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: #2ecc71;
                        color: white;
                        padding: 10px 20px;
                        border-radius: 4px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                    `;
                    document.body.appendChild(messageDiv);
                    
                    // Remove after 3 seconds
                    setTimeout(() => {
                        messageDiv.remove();
                    }, 3000);
                });
            });
        } catch (e) {
            console.error('Error adding current site to whitelist:', e);
        }
    });
}

// Remove domain from whitelist
function removeFromWhitelist(domain) {
    chrome.storage.local.get('whitelist', (data) => {
        const whitelist = data.whitelist || [];
        const index = whitelist.indexOf(domain);
        
        if (index !== -1) {
            whitelist.splice(index, 1);
            chrome.storage.local.set({ whitelist }, () => {
                renderWhitelist(whitelist);
            });
        }
    });
}

// Reset options to defaults
function resetOptions() {
    if (confirm('Are you sure you want to reset all settings to default values?')) {
        const defaultSettings = getDefaultSettings();
        
        chrome.storage.local.set({
            settings: defaultSettings,
            whitelist: []
        }, () => {
            // Reload the page to apply changes
            location.reload();
        });
    }
}

// Save options
function saveOptions() {
    const settings = {
        enabledProtection: elements.enabledProtection.checked,
        notificationLevel: elements.notificationLevel.value,
        autoBlockHighRisk: elements.autoBlockHighRisk.checked,
        collectAnonymousStats: elements.collectAnonymousStats.checked
    };
    
    chrome.storage.local.set({ settings }, () => {
        // Show success message
        const messageDiv = document.createElement('div');
        messageDiv.textContent = 'Settings saved successfully';
        messageDiv.style = `
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background-color: #3498db;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        `;
        document.body.appendChild(messageDiv);
        
        // Remove after 3 seconds
        setTimeout(() => {
            messageDiv.remove();
        }, 3000);
    });
} 