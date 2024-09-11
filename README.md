


# Phishing URL Scanner with Deep Scanning Using Python and Nmap

## Overview

Welcome to the Phishing URL Scanner project! This tool is designed to analyze URLs for potential phishing attacks and perform deep scanning of the associated website’s infrastructure using **Python** and **Nmap**. By combining URL pattern analysis with network security scanning, this project provides a comprehensive approach to detecting and evaluating phishing threats.

## Features

- **URL Classification**: Detects phishing attempts based on URL structure, suspicious keywords, and the use of HTTPS.
- **Whitelisting**: Prevents false positives by whitelisting trusted domains.
- **SSL Certificate Validation**: Checks if the URL’s SSL certificate is valid for added security.
- **Nmap Integration**: Performs deep scanning of the server’s IP address to identify open ports, services, and potential vulnerabilities.
- **Attack Detection**: Identifies possible web application attacks such as SQL Injection and Cross-Site Scripting (XSS).

## Usage

Run the script to start scanning a URL:

```bash
python url_scanner.py
```

**Enter the URL you want to scan** when prompted. The tool will:

1. Check if the URL is live.
2. Classify the URL as phishing or legitimate.
3. Perform an Nmap scan on the domain's IP address.
4. Provide a report on potential attacks based on URL patterns.

## Code Example

Here’s a glimpse of how Nmap is integrated for deep scanning:

```python
import nmap
import socket

def perform_nmap_scan(domain):
    scanner = nmap.PortScanner()
    ip = socket.gethostbyname(domain)
    print(f"Performing Nmap scan on IP: {ip}")
    
    scan_results = scanner.scan(ip, '1-1024', '-v')
    
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
```

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Nmap](https://nmap.org/) for its powerful network scanning capabilities.
- [Python](https://www.python.org/) for being a versatile programming language.

## Contact

For any questions or feedback, please reach out to me via [LinkedIn](https://www.linkedin.com/in/arunabha-mishra-a35128245/).

## Explore My GitHub Projects

I’m constantly working on exciting projects in cybersecurity, web development, and ethical hacking. Check out my GitHub to see the latest tools and innovations I’m building, including this **Phishing URL Scanner** project. I’d love to hear your feedback and collaborate on future endeavors!

[**Visit my GitHub profile here!**](https://github.com/MishraJi-Devloper)
