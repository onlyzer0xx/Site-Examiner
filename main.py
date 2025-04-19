import requests
import time
import os
import json
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import dns.resolver
import socket

# Initialize colorama for colored output
init(autoreset=True)

# Banner
banner = """
███████╗███████╗██████╗  ██████╗ 
╚══███╔╝██╔════╝██╔══██╗██╔═████╗
  ███╔╝ █████╗  ██████╔╝██║██╔██║
 ███╔╝  ██╔══╝  ██╔══██╗████╔╝██║
███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
         Web Vulnerability Scanner
Made by zer0, edited by Raizo
"""

# Payloads for testing vulnerabilities
payloads = {
    "SQLi": ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "';--", "`", "admin' --"],
    "XSS": ["<script>alert(1)</script>", "'\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"],
    "LFI": ["../../../../etc/passwd", "../../../etc/passwd", "../../../../etc/hosts"],
    "CSRF": ["<form action='test' method='POST'><input type='submit'></form>"],
    "Traversal": ["../../", "../etc/", "../../windows/win.ini"],
    "OpenRedirect": ["http://evil.com", "//evil.com", "https://evil.com"]
}

# Common security headers to check
security_headers = {
    "Content-Security-Policy": "Prevents XSS by restricting content sources",
    "X-XSS-Protection": "Enables browser XSS filtering",
    "X-Frame-Options": "Prevents clickjacking",
    "Strict-Transport-Security": "Enforces HTTPS",
    "X-Content-Type-Options": "Prevents MIME-type sniffing"
}

# Global findings list for reporting
findings = []

# Crawl a URL to extract links
def get_links(url):
    try:
        r = requests.get(url, timeout=5, verify=False)  # Added verify=False to handle SSL errors
        soup = BeautifulSoup(r.text, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            link = urljoin(url, a['href'])
            if link.startswith('http'):
                links.append(link)
        return links
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error getting links: {str(e)}")
        return []

# Collect URLs with query parameters to test
def get_urls_to_test(target_url):
    parsed_target = urlparse(target_url)
    target_netloc = parsed_target.netloc
    urls_to_test = set()
    if parsed_target.query:
        urls_to_test.add(target_url)
    links = get_links(target_url)
    for link in links:
        parsed_link = urlparse(link)
        if parsed_link.netloc == target_netloc and parsed_link.query:
            urls_to_test.add(link)
    return list(urls_to_test)

# Check security headers and cookies
def check_security_headers(url):
    print(Fore.CYAN + f"\n[+] Checking security headers and cookies for {url}")
    try:
        r = requests.get(url, timeout=5, verify=False)  # Added verify=False
        headers = r.headers
        for header, desc in security_headers.items():
            if header in headers:
                print(Fore.GREEN + f"[*] Found {header}: {headers[header]} - {desc}")
            else:
                print(Fore.YELLOW + f"[!] Missing {header} - {desc}")
                findings.append({"type": "Missing Security Header", "header": header, "description": desc})
        if r.url.startswith("https"):
            print(Fore.GREEN + "[*] HTTPS enforced")
        else:
            print(Fore.YELLOW + "[!] No HTTPS detected")
            findings.append({"type": "No HTTPS", "url": url})

        # Check cookies
        cookies = r.cookies
        for cookie in cookies:
            cookie_name = cookie.name
            if not cookie.secure:
                print(Fore.RED + f"[!] Cookie '{cookie_name}' missing Secure flag")
                findings.append({"type": "Insecure Cookie", "cookie": cookie_name, "issue": "Secure flag not set"})
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print(Fore.RED + f"[!] Cookie '{cookie_name}' missing HttpOnly flag")
                findings.append({"type": "Insecure Cookie", "cookie": cookie_name, "issue": "HttpOnly flag not set"})
    except Exception as e:
        print(Fore.YELLOW + f"[!] Failed to retrieve headers: {str(e)}")

# Discover potential API endpoints
def discover_api_endpoints(url):
    print(Fore.CYAN + f"\n[+] Discovering potential API endpoints for {url}")
    try:
        r = requests.get(url, timeout=5, verify=False)  # Added verify=False
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        api_endpoints = set()
        for script in scripts:
            src = urljoin(url, script['src'])
            if "api" in src.lower():
                api_endpoints.add(src)
        for link in get_links(url):
            if "api" in link.lower() or "/v" in link.lower():
                api_endpoints.add(link)
        if api_endpoints:
            for endpoint in api_endpoints:
                print(Fore.GREEN + f"[*] Potential API endpoint: {endpoint}")
                findings.append({"type": "API Endpoint", "url": endpoint})
        else:
            print(Fore.YELLOW + "[!] No obvious API endpoints found")
    except Exception as e:
        print(Fore.YELLOW + f"[!] Failed to discover API endpoints: {str(e)}")

# Get subdomains from crt.sh
def get_subdomains_from_crtsh(domain):
    print(Fore.CYAN + f"[+] Querying crt.sh for subdomains of {domain}")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        # Handle empty responses
        if not r.text.strip():
            print(Fore.YELLOW + f"[!] Empty response from crt.sh for {domain}")
            return []
        
        try:
            data = r.json()
        except json.JSONDecodeError:
            print(Fore.YELLOW + f"[!] Invalid JSON response from crt.sh for {domain}")
            return []
            
        subdomains = set()
        for entry in data:
            if "common_name" in entry:
                subdomains.add(entry["common_name"])
            if "name_value" in entry:
                for name in entry["name_value"].split("\n"):
                    subdomains.add(name.strip())
        return [sub for sub in subdomains if sub.endswith(f".{domain}")]
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error querying crt.sh: {str(e)}")
        return []

# Enumerate subdomains
def enumerate_subdomains(domain):
    print(Fore.CYAN + f"\n[+] Enumerating subdomains for {domain}")
    common_subdomains = ["www", "mail", "ftp", "api", "blog", "dev", "test", "admin", "portal", "app"]
    found_subdomains = set()
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # DNS resolution
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(subdomain, 'A')
                for rdata in answers:
                    print(Fore.GREEN + f"[*] Found subdomain (DNS): {subdomain} - IP: {rdata.address}")
                    found_subdomains.add(subdomain)
                    findings.append({"type": "Subdomain", "subdomain": subdomain, "source": "DNS", "ip": str(rdata.address)})
            except Exception:
                pass
        
        # crt.sh subdomains
        crtsh_subs = get_subdomains_from_crtsh(domain)
        for sub in crtsh_subs:
            if sub not in found_subdomains:
                try:
                    answers = resolver.resolve(sub, 'A')
                    for rdata in answers:
                        print(Fore.GREEN + f"[*] Found subdomain (crt.sh): {sub} - IP: {rdata.address}")
                        found_subdomains.add(sub)
                        findings.append({"type": "Subdomain", "subdomain": sub, "source": "crt.sh", "ip": str(rdata.address)})
                except Exception:
                    print(Fore.GREEN + f"[*] Found subdomain (crt.sh): {sub} - No A record")
                    found_subdomains.add(sub)
                    findings.append({"type": "Subdomain", "subdomain": sub, "source": "crt.sh", "ip": "N/A"})
        
        if found_subdomains:
            print(Fore.GREEN + f"[*] Total subdomains found: {len(found_subdomains)}")
        else:
            print(Fore.YELLOW + "[!] No subdomains found")
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error in subdomain enumeration: {str(e)}")

# Scan a URL for vulnerabilities
def scan_url(url, vuln_types):
    parsed = urlparse(url)
    base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
    original_params = parse_qs(parsed.query, keep_blank_values=True)
    
    if not original_params and not vuln_types == ["OpenRedirect"]:
        print(Fore.YELLOW + f"[!] No parameters found to test in {url}")
        return
        
    for vuln_type in vuln_types:
        print(Fore.CYAN + f"\n[+] Testing {vuln_type} on {url}")
        
        # Handle URL with no parameters but testing for open redirect
        if not original_params and vuln_type == "OpenRedirect":
            print(Fore.YELLOW + f"[!] No parameters found, but testing {vuln_type} on path")
            try:
                for payload in payloads[vuln_type]:
                    # Try appending to path
                    test_url = base_url + "/" + payload
                    try:
                        r = requests.get(test_url, timeout=5, allow_redirects=False, verify=False)
                        if r.status_code in [301, 302, 303, 307, 308] and "Location" in r.headers and payload in r.headers["Location"]:
                            print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in path: {test_url} -> {r.headers['Location']}")
                            findings.append({"type": vuln_type, "url": test_url, "parameter": "path", "payload": payload, "redirect_to": r.headers["Location"]})
                    except Exception as e:
                        print(Fore.YELLOW + f"[!] Failed to reach: {test_url} - {str(e)}")
            except Exception as e:
                print(Fore.YELLOW + f"[!] Error testing {vuln_type}: {str(e)}")
            continue
        
        # Process parameters normally
        for param in original_params:
            for payload in payloads[vuln_type]:
                new_params = {k: v[:] for k, v in original_params.items()}
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                test_url = base_url + "?" + new_query
                
                try:
                    r = requests.get(test_url, timeout=5, allow_redirects=False, verify=False)  # Added verify=False
                    if vuln_type == "SQLi" and any(e in r.text.lower() for e in ["sql", "syntax", "mysql", "error", "oracle", "postgresql", "sqlite"]):
                        print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in '{param}': {test_url}")
                        findings.append({"type": vuln_type, "url": test_url, "parameter": param, "payload": payload})
                    elif vuln_type == "XSS" and payload.lower() in r.text.lower():
                        print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in '{param}': {test_url}")
                        findings.append({"type": vuln_type, "url": test_url, "parameter": param, "payload": payload})
                    elif vuln_type == "LFI" and any(e in r.text.lower() for e in ["root:", "nobody:", "daemon:", "ftp:"]):
                        print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in '{param}': {test_url}")
                        findings.append({"type": vuln_type, "url": test_url, "parameter": param, "payload": payload})
                    elif vuln_type == "CSRF" and "<form" in r.text.lower():
                        print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in '{param}': {test_url}")
                        findings.append({"type": vuln_type, "url": test_url, "parameter": param, "payload": payload})
                    elif vuln_type == "Traversal" and any(e in r.text.lower() for e in ["win.ini", "etc", "windows", "system32"]):
                        print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in '{param}': {test_url}")
                        findings.append({"type": vuln_type, "url": test_url, "parameter": param, "payload": payload})
                    elif vuln_type == "OpenRedirect" and r.status_code in [301, 302, 303, 307, 308] and "Location" in r.headers and payload in r.headers["Location"]:
                        print(Fore.RED + f"[!] Possible {vuln_type} vulnerability in '{param}': {test_url} -> {r.headers['Location']}")
                        findings.append({"type": vuln_type, "url": test_url, "parameter": param, "payload": payload, "redirect_to": r.headers["Location"]})
                    else:
                        print(Fore.YELLOW + f"[x] No issues with '{payload}' in '{param}': {test_url}")
                except Exception as e:
                    print(Fore.YELLOW + f"[!] Failed to reach: {test_url} - {str(e)}")

# Get user-selected vulnerability types
def get_vuln_types():
    print(Fore.MAGENTA + "\n[+] Select the vulnerabilities to scan:")
    print(Fore.GREEN + "[1] SQL Injection (SQLi)")
    print(Fore.GREEN + "[2] Cross-site Scripting (XSS)")
    print(Fore.GREEN + "[3] Local File Inclusion (LFI)")
    print(Fore.GREEN + "[4] Cross-Site Request Forgery (CSRF)")
    print(Fore.GREEN + "[5] Directory Traversal")
    print(Fore.GREEN + "[6] Open Redirect")
    print(Fore.GREEN + "[7] Scan all vulnerabilities")
    
    selected = input(Fore.CYAN + "Enter your choice (comma separated, e.g., 1,2): ")
    selected = selected.split(',')
    
    vuln_types = []
    if '1' in selected or '7' in selected:
        vuln_types.append("SQLi")
    if '2' in selected or '7' in selected:
        vuln_types.append("XSS")
    if '3' in selected or '7' in selected:
        vuln_types.append("LFI")
    if '4' in selected or '7' in selected:
        vuln_types.append("CSRF")
    if '5' in selected or '7' in selected:
        vuln_types.append("Traversal")
    if '6' in selected or '7' in selected:
        vuln_types.append("OpenRedirect")
    
    return vuln_types

# Save findings to JSON
def save_findings():
    try:
        with open("findings.json", "w") as f:
            json.dump(findings, f, indent=4)
        print(Fore.GREEN + "[*] Findings saved to 'findings.json'")
    except Exception as e:
        print(Fore.RED + f"[!] Error saving findings: {str(e)}")
        # Try saving to the current user's directory
        try:
            home_dir = os.path.expanduser("~")
            file_path = os.path.join(home_dir, "findings.json")
            with open(file_path, "w") as f:
                json.dump(findings, f, indent=4)
            print(Fore.GREEN + f"[*] Findings saved to '{file_path}'")
        except Exception as e2:
            print(Fore.RED + f"[!] Could not save findings anywhere: {str(e2)}")

# Main execution
if __name__ == "__main__":
    # Suppress warnings for unverified HTTPS requests
    import warnings
    from urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter('ignore', InsecureRequestWarning)
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.GREEN + banner)
    
    target = input(Fore.CYAN + "Enter the URL: ")
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target  # Default to HTTP if no protocol specified
    
    parsed_target = urlparse(target)
    domain = parsed_target.netloc
    
    print(Fore.YELLOW + "[!] Legal Notice: Only scan sites you have explicit permission to test!")
    print(Fore.YELLOW + "[!] Improper use may be illegal. Use at your own risk.")
    confirmation = input(Fore.RED + "Do you have permission to scan this site? (y/n): ")
    if confirmation.lower() != 'y':
        print(Fore.RED + "Scan aborted. Permission is required.")
        exit()
    
    vuln_types = get_vuln_types()
    
    # Vulnerability scanning
    print(Fore.CYAN + f"\n[+] Starting scan on {target}")
    
    # Check if the target is reachable
    try:
        r = requests.get(target, timeout=5, verify=False)
        print(Fore.GREEN + f"[*] Target is reachable: {target} (Status: {r.status_code})")
    except Exception as e:
        print(Fore.RED + f"[!] Target is not reachable: {target}")
        print(Fore.RED + f"[!] Error: {str(e)}")
        exit_choice = input(Fore.RED + "Do you want to continue anyway? (y/n): ")
        if exit_choice.lower() != 'y':
            print(Fore.RED + "Scan aborted.")
            exit()
    
    # Proceed with scanning
    urls_to_test = get_urls_to_test(target)
    if urls_to_test:
        print(Fore.GREEN + f"[*] Found {len(urls_to_test)} URLs with parameters to test")
        for url in urls_to_test:
            print(Fore.GREEN + f"[*] Scanning URL: {url}")
            scan_url(url, vuln_types)
    else:
        print(Fore.YELLOW + f"[!] No URLs with parameters found at {target}")
        print(Fore.YELLOW + f"[!] Scanning just the main target URL: {target}")
        scan_url(target, vuln_types)
    
    # Check security headers and cookies
    check_security_headers(target)
    
    # Discover API endpoints
    discover_api_endpoints(target)
    
    # Enumerate subdomains
    enumerate_subdomains(domain)
    
    # Save findings
    save_findings()
    
    print(Fore.GREEN + "\n[*] Scan completed. Thank you for using zer0!")
