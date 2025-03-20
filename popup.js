document.addEventListener('DOMContentLoaded', function() {
    const statusEl = document.getElementById('currentStatus');
    const safetyLevelEl = document.getElementById('safetyLevel');
    const detailsEl = document.getElementById('details');
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    
    // Check the current tab URL
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const currentTab = tabs[0];
      const url = currentTab.url;
      
      // Only check HTTP/HTTPS URLs
      if (url.startsWith('http')) {
        checkURL(url);
      } else {
        statusEl.className = "status unknown";
        statusEl.textContent = "Not applicable for this page.";
        detailsEl.innerHTML = "<p>Only HTTP/HTTPS URLs can be checked.</p>";
      }
    });
    
    // Set up check button
    checkButton.addEventListener('click', function() {
      const url = urlInput.value.trim();
      if (url && url.startsWith('http')) {
        checkURL(url);
      } else {
        alert('Please enter a valid HTTP/HTTPS URL');
      }
    });
    
    // Function to check URL using our background service
    function checkURL(url) {
      statusEl.className = "status unknown";
      statusEl.textContent = "Checking URL...";
      
      chrome.runtime.sendMessage(
        { action: 'checkURL', url },
        function(response) {
          
            if (response.error) {
                statusEl.className = "status unknown";
                statusEl.textContent = "Error checking URL";
                detailsEl.innerHTML = `An error occurred: ${response.message || 'Unknown error'}`;
                return;
                }
                
                // Update status based on results
                if (response.is_malicious) {
                statusEl.className = "status unsafe";
                statusEl.textContent = "Warning: Potential phishing URL detected!";
                
                // Update safety meter
                const safetyScore = 100 - (response.confidence * 100);
                safetyLevelEl.style.width = `${safetyScore}%`;
                safetyLevelEl.style.backgroundColor = "#dc3545";
                
                // Display details
                let detailsHTML = `
                    Confidence: ${Math.round(response.confidence * 100)}%
                    Why we think this URL is suspicious:
                    
                `;
                
                if (response.analysis && response.analysis.suspicious_elements) {
                    response.analysis.suspicious_elements.forEach(element => {
                    detailsHTML += `${formatSuspiciousElement(element)}`;
                    });
                }
                
                detailsHTML += ``;
                
                // Add decoded URL info if applicable
                if (response.is_encoded && response.decoded_url) {
                    detailsHTML += `
                    URL appears to be encoded:
                    Original: ${response.original_url}
                    Decoded: ${response.decoded_url}
                    `;
                }
                
                detailsEl.innerHTML = detailsHTML;
                } else {
                statusEl.className = "status safe";
                statusEl.textContent = "URL appears to be safe";
                
                // Update safety meter
                const safetyScore = response.analysis ? response.analysis.safety_score : 90;
                safetyLevelEl.style.width = `${safetyScore}%`;
                safetyLevelEl.style.backgroundColor = "#28a745";
                
                detailsEl.innerHTML = `
                    No suspicious elements were detected in this URL.
                    Safety score: ${safetyScore}%
                `;
                }
            }
            );
        }
        
        // Helper function to format suspicious elements in a user-friendly way
        function formatSuspiciousElement(element) {
            const elementMap = {
            'not_https': 'URL does not use HTTPS secure protocol',
            'ip_address': 'Uses IP address instead of domain name',
            'long_url': 'Unusually long URL',
            'multiple_subdomains': 'Contains multiple subdomains',
            'blacklisted': 'Domain is blacklisted'
            };
            
            // Handle keyword elements
            if (element.startsWith('keyword_')) {
            const keyword = element.replace('keyword_', '');
            return `Contains suspicious keyword: "${keyword}"`;
            }
            
            return elementMap[element] || element;
        }
        });