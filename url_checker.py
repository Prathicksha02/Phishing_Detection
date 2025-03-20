import re
import requests
import urllib.parse
import tldextract
from urllib.parse import urlparse

def is_encoded_url(url):
    """Check if URL is encoded"""
    decoded = urllib.parse.unquote(url)
    return decoded != url

def decode_url(url):
    """Decode URL if it's encoded"""
    return urllib.parse.unquote(url)

def analyze_url(url):
    """Analyze URL for phishing indicators"""
    result = {
        'is_malicious': False,
        'suspicious_elements': [],
        'safety_score': 100,
        'details': {}
    }
    
    # Initialize details
    result['details'] = {
        'domain': None,
        'ip_address': False,
        'https': False,
        'redirects': 0,
        'domain_age': None,
        'suspicious_keywords': [],
        'blacklisted': False
    }
    
    # Check if URL uses HTTPS
    if url.startswith('https://'):
        result['details']['https'] = True
    else:
        result['suspicious_elements'].append('not_https')
        result['safety_score'] -= 15
    
    # Extract domain information
    extracted = tldextract.extract(url)
    result['details']['domain'] = f"{extracted.domain}.{extracted.suffix}"
    
    # Check for IP address instead of domain name
    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url):
        result['details']['ip_address'] = True
        result['suspicious_elements'].append('ip_address')
        result['safety_score'] -= 25
    
    # Check for suspicious keywords
    suspicious_keywords = ['login', 'signin', 'account', 'secure', 'banking', 'password', 'verify']
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            result['details']['suspicious_keywords'].append(keyword)
            result['suspicious_elements'].append(f'keyword_{keyword}')
            result['safety_score'] -= 5
    
    # Check URL length (phishing URLs tend to be long)
    if len(url) > 100:
        result['suspicious_elements'].append('long_url')
        result['safety_score'] -= 10
    
    # Check for multiple subdomains
    if extracted.subdomain.count('.') > 2:
        result['suspicious_elements'].append('multiple_subdomains')
        result['safety_score'] -= 15
    
    # Check against blacklist (in real implementation, this would call an API)
    # Simulated blacklist check
    blacklisted_domains = ['evil-phish.com', 'phishing-site.net']
    if result['details']['domain'] in blacklisted_domains:
        result['details']['blacklisted'] = True
        result['suspicious_elements'].append('blacklisted')
        result['safety_score'] -= 100
    
    # Determine if malicious based on safety score
    if result['safety_score'] < 70:
        result['is_malicious'] = True

    return result

def check_url_reputation(url):
    """
    Check URL reputation using external APIs
    In a real implementation, this would integrate with services like:
    - Google Safe Browsing
    - PhishTank
    - VirusTotal
    """
    # Simulated API response
    return {
        'known_malicious': False,
        'reputation_score': 85,
        'last_scanned': '2023-10-01'
    }