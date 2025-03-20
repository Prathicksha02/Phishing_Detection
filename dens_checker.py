import socket
import re
from fuzzywuzzy import fuzz

# List of real domains (expand this list for better accuracy)
KNOWN_DOMAINS = ["google.com", "facebook.com", "flipkart.com", "instagram.com", "paypal.com", "amazon.com"]

# Regular expressions for phishing-like domains (EXCLUDING legitimate ones)
SUSPICIOUS_PATTERNS = [
    r"g[o0]{2}gle\.com",  # Matches g00gle.com (but NOT google.com)
    r"faceb[o0]{2}k\.com",  # Matches faceb00k.com
    r"inst[a4]gram\.com",  # Matches inst4gram.com
    r"paypa1\.com",  # Matches paypa1.com
]

def check_dns_security(domain):
    try:
        domain = domain.lower()  # Normalize case

        # ✅ Ensure REAL domains are NOT flagged
        if domain in KNOWN_DOMAINS:
            return f"✅ {domain} is a legitimate domain."

        # ✅ Fix fuzzy matching logic (ignore real domains)
        for real_domain in KNOWN_DOMAINS:
            similarity = fuzz.ratio(domain, real_domain)
            if similarity > 90 and domain != real_domain:  # Ensure it's NOT identical
                return f"⚠️ WARNING: {domain} looks like a fake {real_domain}!"

        # ✅ Fix regex matching (make it case-insensitive and exclude real domains)
        for pattern in SUSPICIOUS_PATTERNS:
            if re.fullmatch(pattern, domain, re.IGNORECASE) and domain not in KNOWN_DOMAINS:
                return f"⚠️ WARNING: {domain} looks like a phishing domain!"

        # Resolve IP Address
        ip = socket.gethostbyname(domain)
        print(f"🌐 IP Address of {domain}: {ip}")

        return f"✅ {domain} website name correct."

    except socket.gaierror:  # Handles invalid domain names
        return f"❌ ERROR: {domain} does not exist or cannot be resolved."

# Continuous user input loop
if __name__ == "__main__":
    while True:
        domain = input("\nEnter a domain to check (or type 'exit' to quit): ").strip()
        if domain.lower() == "exit":
            print("Exiting program. Goodbye! 👋")
            break
        result = check_dns_security(domain)
        print(result)
