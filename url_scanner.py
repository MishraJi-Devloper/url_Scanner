import re
import requests
import tldextract
from sklearn.naive_bayes import MultinomialNB
from urllib.parse import urlparse
import nmap
import socket

# List of known phishing indicators
suspicious_words = ['login', 'update', 'free', 'account', 'secure', 'bank', 'verify', 'signin']

# Whitelist for trusted domains (You can change this list as your wish like example.com)
trusted_domains = ['cuchd.in', 'google.com', 'github.com']

# Extract features from a URL
def extract_features(url):
    features = []
    
    # Feature 1: Length of the URL
    features.append(len(url))
    
    # Feature 2: Number of dots in the domain
    domain_info = tldextract.extract(url)
    features.append(domain_info.subdomain.count('.') + domain_info.domain.count('.'))
    
    # Feature 3: Check for suspicious words in the URL
    if any(word in url.lower() for word in suspicious_words):
        features.append(1)
    else:
        features.append(0)

    # Feature 4: Check if HTTPS is used (HTTPS adds a layer of security)
    if urlparse(url).scheme == "https":
        features.append(0)
    else:
        features.append(1)
    
    return features

# Check if the URL is live
def is_live(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except:
        return False

# Check if the URL domain is whitelisted
def is_whitelisted(url):
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    return domain in trusted_domains

# Check if SSL certificate is valid
def has_valid_ssl(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        ssl.get_server_certificate((hostname, 443))
        return True
    except:
        return False

# Perform an Nmap scan on the URL's IP
def perform_nmap_scan(domain):
    scanner = nmap.PortScanner()
    ip = socket.gethostbyname(domain)
    print(f"Performing Nmap scan on IP: {ip}")
    
    # Perform a basic port scan
    scan_results = scanner.scan(ip, '1-1024', '-v')
    
    # Output scan results
    open_ports = []
    if 'scan' in scan_results and ip in scan_results['scan']:
        if 'tcp' in scan_results['scan'][ip]:
            for port in scan_results['scan'][ip]['tcp']:
                port_info = scan_results['scan'][ip]['tcp'][port]
                if port_info['state'] == 'open':
                    open_ports.append({
                        'port': port,
                        'service': port_info['name'],
                        'product': port_info.get('product', 'unknown'),
                        'version': port_info.get('version', 'unknown')
                    })
    
    if open_ports:
        print("Open Ports Detected:")
        for port in open_ports:
            print(f"- Port: {port['port']}, Service: {port['service']}, Product: {port['product']}, Version: {port['version']}")
    else:
        print("No open ports detected in the scanned range (1-1024).")

# Train a simple classifier (with dummy data)
def train_model():
    urls = [
        "http://securelogin.bank.com",
        "http://freeupdate.xyz",
        "http://google.com",
        "http://mywebsite.com/secure",
        "http://freeofferbank.com",
        "https://github.com"
    ]
    
    labels = [1, 1, 0, 1, 1, 0]  # 1 = phishing, 0 = legitimate
    
    # Extract features for each URL
    feature_matrix = [extract_features(url) for url in urls]
    
    # Train the model
    model = MultinomialNB()
    model.fit(feature_matrix, labels)
    
    return model

# Function to classify a URL as phishing or legitimate
def classify_url(url, model):
    if is_whitelisted(url):
        return "Legitimate (Whitelisted)"
    
    features = extract_features(url)
    result = model.predict([features])[0]
    if result == 1:
        return "Phishing"
    else:
        return "Legitimate"

# Check for potential attacks based on URL patterns
def possible_attacks(url):
    attack_types = []
    
    # Check for XSS potential (often includes suspicious parameters in URL)
    if "<script>" in url.lower() or "%3Cscript%3E" in url.lower():
        attack_types.append("Potential XSS (Cross-Site Scripting)")
    
    # Check for SQL injection potential (common SQL keywords in URL parameters)
    sql_keywords = ["select", "insert", "drop", "delete", "update", "union", "exec"]
    if any(keyword in url.lower() for keyword in sql_keywords):
        attack_types.append("Potential SQL Injection")

    # Check for phishing potential based on structure or keywords
    if any(word in url.lower() for word in suspicious_words):
        attack_types.append("Potential Phishing Attempt")
    
    # Add more checks for other types of attacks if needed...
    
    if not attack_types:
        attack_types.append("No specific vulnerabilities detected based on URL patterns.")
    
    return attack_types

if __name__ == "__main__":
    # Train the model
    model = train_model()
    
    # Input URL for scanning
    url = input("Enter URL to scan: ")
    
    # Check if the URL is live
    if is_live(url):
        print(f"URL is live. Classifying URL: {url}")
        
        # Check SSL certificate
        if not has_valid_ssl(url):
            print("Warning: The URL does not have a valid SSL certificate.")
        
        # Classify the URL
        classification = classify_url(url, model)
        print(f"The URL is classified as: {classification}")
        
        # Check for possible attacks
        attacks = possible_attacks(url)
        print("\nPossible Attacks:")
        for attack in attacks:
            print(f"- {attack}")
        
        # Perform an Nmap scan
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        perform_nmap_scan(domain)
        
    else:
        print("URL is not live or unreachable.")
