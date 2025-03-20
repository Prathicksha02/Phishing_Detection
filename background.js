const API_URL = 'http://localhost:5000/api/check-url';

// Store checked URLs in memory to avoid redundant API calls
const urlCache = {};

// Check URL against our API
async function checkURL(url) {
  // Check cache first
  if (urlCache[url]) {
    return urlCache[url];
  }
  
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url })
    });
    
    const result = await response.json();
    
    // Cache the result
    urlCache[url] = result;
    
    return result;
  } catch (error) {
    console.error('Error checking URL:', error);
    return { error: true, message: error.toString() };
  }
}

// Listen for web navigation events
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigation (not iframes, etc)
  if (details.frameId !== 0) {
    return;
  }

  const url = details.url;
  
  // Skip internal browser pages and non-HTTP URLs
  if (!url.startsWith('http')) {
    return;
  }
  
  // Check if URL is malicious
  const result = await checkURL(url);
  
  if (result.is_malicious) {
    // Block the navigation by redirecting to warning page
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL('warning.html') + '?url=' + encodeURIComponent(url)
    });
    
    // Show notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Phishing URL Detected',
      message: `The URL ${url} appears to be malicious and has been blocked.`
    });
  }
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    checkURL(request.url)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: true, message: error.toString() }));
    return true; // Keep the message channel open for async response
  }
});

// Listen for QR code scanning requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanQRCode') {
    const imageData = request.imageData;
    
    // Send to API for QR code processing
    fetch('http://localhost:5000/api/scan-qr', {
      method: 'POST',
      body: imageData
    })
    .then(response => response.json())
    .then(result => sendResponse(result))
    .catch(error => sendResponse({ error: true, message: error.toString() }));
    
    return true; // Keep the message channel open for async response
  }
});
