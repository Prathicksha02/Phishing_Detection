function findLinks() {
    const links = document.querySelectorAll('a[href^="http"]');
    return Array.from(links).map(link => link.href);
  }
  
  // Analyze links in batches to avoid overwhelming the API
  async function analyzeLinks() {
    const links = findLinks();
    const uniqueLinks = [...new Set(links)];
    
    // Process in batches of 10
    const batchSize = 10;
    for (let i = 0; i < uniqueLinks.length; i += batchSize) {
      const batch = uniqueLinks.slice(i, i + batchSize);
      
      // Check each URL in the batch
      for (const url of batch) {
        chrome.runtime.sendMessage(
          { action: 'checkURL', url },
          function(response) {
            if (response && response.is_malicious) {
              // Find and mark all links with this URL
              document.querySelectorAll(`a[href="${url}"]`).forEach(link => {
                // Mark the link as dangerous
                link.style.color = 'red';
                link.style.border = '2px solid red';
                link.style.padding = '2px';
                link.setAttribute('data-phishing', 'true');
                
                // Add warning icon
                const warningIcon = document.createElement('span');
                warningIcon.textContent = '⚠️ ';
                link.prepend(warningIcon);
                
                // Add event listener to prevent clicking
                link.addEventListener('click', function(e) {
                  e.preventDefault();
                  e.stopPropagation();
                  alert(`Warning: This link appears to be malicious and has been blocked.`);
                });
              });
            }
          }
        );
      }
      
      // Simple delay between batches to avoid API rate limits
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }
  
  // Scan for QR codes in images
  function scanForQRCodes() {
    const images = document.querySelectorAll('img');
    
    images.forEach(img => {
      // Skip small images unlikely to be QR codes
      if (img.width < 100 || img.height < 100) return;
      
      // Create a canvas to extract image data
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      
      try {
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        
        // Get image data
        const imageData = canvas.toDataURL('image/png');
        
        // Send to background script for QR processing
        chrome.runtime.sendMessage(
          { action: 'scanQRCode', imageData },
          function(response) {
            if (response && response.url) {
              // If QR contains URL and it's malicious, mark the image
              if (response.is_malicious) {
                img.style.border = '3px solid red';
                
                // Create an overlay warning
                const overlay = document.createElement('div');
                overlay.style.position = 'absolute';
                overlay.style.top = `${img.offsetTop}px`;
                overlay.style.left = `${img.offsetLeft}px`;
                overlay.style.width = `${img.width}px`;
                overlay.style.height = `${img.height}px`;
                overlay.style.backgroundColor = 'rgba(255, 0, 0, 0.5)';
                overlay.style.display = 'flex';
                overlay.style.justifyContent = 'center';
                overlay.style.alignItems = 'center';
                overlay.style.zIndex = '1000';
                
                const warningText = document.createElement('div');
                warningText.textContent = '⚠️ Malicious QR Code Detected';
                warningText.style.color = 'white';
                warningText.style.fontWeight = 'bold';
                warningText.style.textAlign = 'center';
                
                overlay.appendChild(warningText);
                img.parentNode.style.position = 'relative';
                img.parentNode.appendChild(overlay);
              }
            }
          }
        );
      } catch (error) {
        // Ignore errors - likely due to cross-origin restrictions
      }
    });
  }
  
  // Run our analysis when the page is fully loaded
  window.addEventListener('load', () => {
    analyzeLinks();
    scanForQRCodes();
  });
  
  // Also check for new links added to the page dynamically
  const observer = new MutationObserver((mutations) => {
    let hasNewLinks = false;
    
    mutations.forEach(mutation => {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === 1) { // Element node
            if (node.tagName === 'A' || node.querySelector('a')) {
              hasNewLinks = true;
              break;
            }
          }
        }
      }
    });
    
    if (hasNewLinks) {
      analyzeLinks();
    }
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Listen for clicks on links to handle potential issues
  document.addEventListener('click', (e) => {
    // Check if the click was on an anchor element or its child
    let target = e.target;
    while (target && target !== document) {
      if (target.tagName === 'A' && target.href && target.href.startsWith('http')) {
        // Prevent default action temporarily
        e.preventDefault();
        
        // Check the URL
        chrome.runtime.sendMessage(
          { action: 'checkURL', url: target.href },
          function(response) {
            if (response && response.is_malicious) {
              // Block navigation and show warning
              alert(`Warning: This link may be malicious and has been blocked.\n\nSuspicious elements: ${response.suspicious_elements.join(', ')}`);
            } else {
              // If safe, continue to the URL
              window.location.href = target.href;
            }
          }
        );
        return;
      }
      target = target.parentElement;
    }
  });