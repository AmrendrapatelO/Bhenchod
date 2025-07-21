# Bhenchod
# 🛡️ Reverse Shell Scanner 1.1 - Extreme Penetration Edition

A high-performance, multithreaded reverse shell scanner written in Python 3.  
This tool is designed for ethical penetration testers and security researchers to scan web servers for potential reverse shell payloads and vulnerable endpoints.

![banner](https://img.shields.io/badge/Version-1.1-blue.svg)
![python](https://img.shields.io/badge/Language-Python3-yellow)
![license](https://img.shields.io/github/license/AmrendrapatelO/Bhenchod)
![platform](https://img.shields.io/badge/Platform-Cross--Platform-green)

---

## 🚀 Features

- ✅ Fast multithreaded scanning (up to 100 threads)
- ✅ Auto URL crawling with `BeautifulSoup`
- ✅ Reverse shell detection in real-time
- ✅ Advanced WAF bypass techniques (`X-Forwarded-For` spoofing)
- ✅ Custom payloads and endpoint detection
- ✅ Clean terminal output with progress indicators
- ✅ Supports HTTP & HTTPS protocols
- ✅ Modular and extendable code

----
### Key Advancements in BHENCHOD 1.1:

1. **Next-Gen WAF Bypass Techniques**:
   - Polymorphic payload generation with MIME-type specific evasion
   - Chunked transfer encoding support (conceptual)
   - CSRF token harvesting from SPAs and meta tags
   - Case variation and null byte injection
   - Content sniffing bypass via polyglot files

2. **API Endpoint Exploitation**:
   - Automatic discovery of API endpoints from JavaScript files
   - Direct API uploads to bypass form-based restrictions
   - REST/GraphQL endpoint fuzzing

3. **Advanced Payload Obfuscation**:
   - Base64-encoded PHP payloads with reverse string decoding
   - ROT13 and hex-encoded ASPX shells
   - SVG-based XSS payloads for cookie theft
   - Environment-variable based PHP execution

4. **XML Attack Vectors**:
   - XXE exploitation for file disclosure
   - SVG payloads with JavaScript execution
   - SOAP endpoint fuzzing

5. **Stealth Operation**:
   - Time-delayed reverse shell triggering
   - OpenSSL-encrypted listener
   - Randomized scanning patterns
   - Legal-looking filenames and extensions

6. **Global Scanning System**:
   - Automatic TLD scanning (.com, .in, .org, etc.)
   - Subdomain discovery and scanning
   - Results aggregation in JSON format
   - Continuous background scanning

7. **Alternative Exploitation Paths**:
   - Direct PUT method exploitation for SVG uploads
   - Brute-force of common management portals
   - CMS-specific upload paths (WordPress, Drupal, Joomla)

### Modern Protection Bypass Methods:

**1. Strict MIME/Extension Bypass:**
```python
# Creates valid PNG with embedded PHP payload
polyglot = b'\x89PNG\r\n\x1a\n' + php_payload
files = {'file': ('image.png', polyglot, 'image/png')}
```

**2. Content-Disposition/Re-validation:**
```python
# Uses double extensions with null bytes
filename = "shell.php%00.jpg"
```

**3. WAF/mod_security Bypass:**
```python
# Adds WAF-bypass headers
headers = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "CF-Connecting-IP": "127.0.0.1"
}
```

**4. Uploads Outside Webroot:**
```python
# Path traversal in filename
filename = "../../../public_html/shell.php"
```

**5. JavaScript-Only (SPA) Sites:**
```python
# API endpoint discovery from JavaScript files
matches = re.findall(r'["\'](/api/v\d+/[^"\'\s]+)["\']', js_code)
```

**6. Token-Protected Forms:**
```python
# CSRF token harvesting
csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']
```

### Usage Instructions:

```bash
# Scan single target
./bhenchod.py https://example.com

# Scan all TLDs (example.com, example.in, example.org, etc.)
./bhenchod.py example --global

# Discover and scan related domains
./bhenchod.py example --discover
```

### Features:

1. **Automated Global Scanning**:
   - Scans all country TLDs automatically
   - Discovers subdomains and related domains
   - Runs continuously until stopped

2. **Smart Result Handling**:
   - JSON output with full vulnerability details
   - Separate files for each scanned domain
   - Success/failure tracking

3. **Advanced Evasion**:
   - Polymorphic payloads that change with each request
   - Legal-looking traffic patterns
   - Encrypted command channels

4. **Multi-Vector Exploitation**:
   - Traditional form uploads
   - API endpoint exploitation
   - XXE and SVG vulnerabilities
   - CMS-specific backdoors

### Requirements:
- Python 3.8+
- `requests`, `beautifulsoup4`
- OpenSSL for encrypted listeners
- Ncat (from Nmap project)


## contribute 
Anyone can contribute to this project, we welcome everyone. 

## if you find this tool helpful then ⭐ This increases our motivation 🤍
