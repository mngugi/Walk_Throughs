## Secrets in Source 2

# HackDNA – Secrets in Source 2

## Challenge Overview

The application exposes sensitive information directly inside the client-side source code. Attackers commonly inspect HTML, JavaScript files, comments, hidden fields, API endpoints, and embedded configuration values to discover secrets unintentionally left by developers.

This challenge demonstrates how insecure source-code exposure can lead to information disclosure and privilege escalation.

---

# Objective

Identify hidden credentials, tokens, or sensitive information exposed within the web application's source code.

---

# Reconnaissance

The first step involves inspecting the application source.

Open the target page and view the source code:

```bash
CTRL + U
```

or

```bash
Right Click → View Page Source
```

Developers sometimes leave:

* Credentials
* API Keys
* Debug Comments
* Hidden Endpoints
* Developer Notes
* Backup URLs
* JWT Tokens
* Internal IP Addresses

inside the source.

---

# Initial Findings

While reviewing the HTML source, suspicious comments and hidden values may appear.

Example indicators:

```html
<!-- TODO: remove test credentials before production -->
```

```html
<input type="hidden" value="admin:true">
```

```javascript
const api_key = "dev-test-key-123";
```

Client-side JavaScript files are also critical.

---

# JavaScript Enumeration

Inspect loaded JavaScript files using browser developer tools.

```bash
F12 → Sources
```

or inspect script references:

```html
<script src="app.js"></script>
```

Download and review the scripts.

Useful patterns to search:

```bash
password
secret
key
token
admin
internal
backup
```

---

# Exploitation

A sensitive value exposed in the source can often be reused for:

* Authentication bypass
* Admin access
* Hidden functionality
* API interaction
* Privilege escalation

Example:

```javascript
const adminPassword = "SuperSecret123";
```

Using the discovered credential on the login page grants elevated access.

---

# Root Cause

The vulnerability exists because sensitive information was embedded directly into client-side code.

Anything sent to the browser must be considered public.

Common developer mistakes include:

* Hardcoded credentials
* Debugging leftovers
* Exposed API secrets
* Development endpoints left enabled
* Insecure comments containing operational data

---

# Security Impact

Source-code disclosure vulnerabilities can lead to:

* Unauthorized access
* Credential compromise
* Internal infrastructure exposure
* Account takeover
* API abuse
* Privilege escalation
* Full application compromise

---

# Detection Techniques

## Manual Inspection

* View page source
* Review JavaScript files
* Inspect comments
* Analyze hidden fields
* Review network requests

## Automated Discovery

Using grep:

```bash
grep -Ri "password\|secret\|token\|apikey" .
```

Using browser DevTools:

```bash
F12 → Network → JS Files
```

---

# Mitigation

## Never Store Secrets Client-Side

Sensitive credentials should remain server-side.

## Remove Debug Information

Strip comments and development notes before deployment.

## Use Environment Variables

Secrets should be managed securely using:

* Environment variables
* Vault systems
* Secret managers

## Conduct Secure Code Reviews

Implement:

* Static analysis
* CI/CD secret scanning
* Manual security audits

## Apply Principle of Least Privilege

Even exposed tokens should have minimal permissions.

---

# Example Secure Practice

Instead of:

```javascript
const db_password = "root123";
```

Use server-side authentication logic and environment variables.

---

# Real-World Relevance

Many real-world breaches originate from accidentally exposed secrets in:

* Public Git repositories
* Frontend JavaScript
* Mobile applications
* CI/CD pipelines
* Backup files

Common exposed secrets include:

* AWS Keys
* Firebase credentials
* JWT secrets
* SMTP credentials
* Database passwords
* OAuth tokens

---

# Key Takeaway

If the browser can see it, an attacker can see it.

Client-side code should never contain sensitive operational secrets.

---

# Vulnerability Classification

* CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
* CWE-798: Use of Hard-coded Credentials
* OWASP A05:2021 – Security Misconfiguration
* OWASP A02:2021 – Cryptographic Failures

---

# Conclusion

Secrets exposed in source code represent a high-risk information disclosure vulnerability. Attackers routinely inspect frontend assets during reconnaissance, making exposed credentials one of the easiest attack vectors to exploit.

Secure development practices, automated secret scanning, and proper server-side secret management are essential to prevent this class of vulnerability.

===

# HackDNA – Nmap Lab 102

## Challenge Overview

This lab introduces practical network reconnaissance using Nmap. The objective is to identify open ports, exposed services, and potentially vulnerable network-facing applications running on the target system.

Nmap is one of the most widely used reconnaissance and enumeration tools in cybersecurity and penetration testing.

---

# Objective

Perform network enumeration against the target machine and identify:

* Open ports
* Running services
* Service versions
* Operating system indicators
* Potential attack surface

---

# What is Nmap?

Nmap (Network Mapper) is an open-source utility used for:

* Host discovery
* Port scanning
* Service enumeration
* OS fingerprinting
* Vulnerability discovery
* Network inventory

It is commonly used during the reconnaissance phase of penetration testing.

---

# Basic Host Discovery

Before scanning services, confirm the host is online.

```bash
nmap -sn TARGET_IP
```

Example:

```bash
nmap -sn 54.168.1.10
```

This performs a ping sweep without port scanning.

---

# Basic Port Scan

Scan the most common TCP ports.

```bash
nmap TARGET_IP
```

Example:

```bash
nmap 54.168.1.10
```

Typical output:

```text
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
```

---

# Service Version Detection

Identify software versions running on open ports.

```bash
nmap -sV TARGET_IP
```

Example:

```bash
nmap -sV 54.168.1.10
```

Possible output:

```text
22/tcp open ssh OpenSSH 8.2p1 Ubuntu
80/tcp open http Apache httpd 2.4.41
```

Version detection is important because outdated services may contain known vulnerabilities.

---

# Operating System Detection

Attempt operating system fingerprinting.

```bash
sudo nmap -O TARGET_IP
```

Example:

```bash
sudo nmap -O 54.168.1.10
```

Possible results:

```text
OS details: Linux 5.x
```

---

# Aggressive Scan

Combine multiple reconnaissance techniques.

```bash
sudo nmap -A TARGET_IP
```

This enables:

* OS detection
* Version detection
* Script scanning
* Traceroute

Example:

```bash
sudo nmap -A 54.168.1.10
```

---

# Full Port Scan

By default, Nmap scans the top 1000 ports.

To scan all TCP ports:

```bash
nmap -p- TARGET_IP
```

Example:

```bash
nmap -p- 54.168.1.10
```

This can reveal hidden services running on uncommon ports.

---

# Faster Scanning

Adjust timing templates.

```bash
nmap -T4 TARGET_IP
```

Timing options range from:

* T0 → Paranoid
* T1 → Sneaky
* T2 → Polite
* T3 → Normal
* T4 → Aggressive
* T5 → Insane

---

# UDP Scanning

Some important services use UDP instead of TCP.

Examples include:

* DNS
* SNMP
* DHCP
* NTP

UDP scan:

```bash
sudo nmap -sU TARGET_IP
```

UDP scans are slower than TCP scans.

---

# NSE Script Scanning

Nmap includes the Nmap Scripting Engine (NSE).

Basic vulnerability scan:

```bash
nmap --script vuln TARGET_IP
```

Example:

```bash
nmap --script vuln 192.168.1.10
```

NSE scripts can detect:

* Misconfigurations
* Weak SSL/TLS
* Anonymous FTP access
* SMB vulnerabilities
* Known CVEs

---

# Banner Grabbing

Service banners often reveal software versions.

Nmap can retrieve banners automatically:

```bash
nmap -sV TARGET_IP
```

Example banner:

```text
Apache/2.4.41 (Ubuntu)
```

Attackers use this information to search for public exploits.

---

# Common Ports and Services

| Port | Service |
| ---- | ------- |
| 21   | FTP     |
| 22   | SSH     |
| 23   | Telnet  |
| 25   | SMTP    |
| 53   | DNS     |
| 80   | HTTP    |
| 110  | POP3    |
| 139  | NetBIOS |
| 143  | IMAP    |
| 443  | HTTPS   |
| 445  | SMB     |
| 3306 | MySQL   |
| 3389 | RDP     |

---

# Reconnaissance Workflow

Typical penetration testing workflow:

1. Host discovery
2. Port scanning
3. Service enumeration
4. Version detection
5. Vulnerability identification
6. Exploitation
7. Post-exploitation

Nmap plays a central role during early-stage reconnaissance.

---

# Security Impact

Improperly exposed services can lead to:

* Remote code execution
* Credential theft
* Information disclosure
* Lateral movement
* Privilege escalation
* Full system compromise

Attackers rely heavily on exposed network services.

---

# Defensive Measures

## Minimize Attack Surface

Disable unused services.

## Implement Firewalls

Restrict unnecessary inbound traffic.

## Use Network Segmentation

Separate sensitive systems from public-facing infrastructure.

## Patch Vulnerabilities

Keep software updated.

## Monitor Network Activity

Deploy:

* IDS/IPS
* SIEM solutions
* Log analysis
* Network anomaly detection

---

# Detection Indicators

Administrators can detect scanning activity through:

* Multiple connection attempts
* Sequential port probing
* Abnormal SYN packets
* IDS alerts
* Firewall logs

Tools such as:

* Snort
* Suricata
* Zeek

can help identify reconnaissance attempts.

---

# Ethical Considerations

Unauthorized network scanning may violate:

* Organizational policies
* Terms of service
* Cybercrime laws

Always obtain proper authorization before performing security testing.

---

# Key Takeaway

Network reconnaissance is the foundation of penetration testing. Understanding exposed services allows attackers and defenders alike to assess risk and identify security weaknesses.

Nmap remains one of the most essential tools in cybersecurity operations.

---

# Vulnerability Classification

* CWE-200: Exposure of Sensitive Information
* CWE-284: Improper Access Control
* OWASP A05:2021 – Security Misconfiguration

---

# Conclusion

Nmap enables deep visibility into network infrastructure and exposed services. Effective enumeration can uncover weak configurations, outdated software, and hidden attack surfaces.

Defenders should continuously audit exposed services and minimize unnecessary network exposure to reduce organizational risk.

===

# HackDNA – Hack the Cookie

## Challenge Overview

This challenge focuses on insecure client-side trust and cookie manipulation. Web applications commonly use cookies to maintain session state, authentication information, and user preferences.

When sensitive authorization logic is stored directly inside client-side cookies without proper integrity protection, attackers can manipulate values to escalate privileges or bypass authentication controls.

---

# Objective

Analyze and manipulate browser cookies to gain elevated privileges or unauthorized access.

---

# Understanding Cookies

Cookies are small pieces of data stored in the browser and sent with HTTP requests.

Common uses include:

* Session management
* Authentication
* User preferences
* Tracking
* State persistence

Example cookie:

```http
Cookie: role=user
```

If applications trust cookie values directly, attackers may tamper with them.

---

# Reconnaissance

Open browser developer tools.

```bash
F12 → Application → Cookies
```

or

```bash
Storage → Cookies
```

Inspect available cookie values.

Potential indicators:

```text
role=user
admin=false
isAdmin=0
access=basic
```

These values may control authorization.

---

# Initial Enumeration

Observe application behavior while logged in.

Questions to investigate:

* Does the cookie contain plaintext values?
* Is the cookie encoded?
* Is there any signature validation?
* Does changing the value alter permissions?

Example vulnerable cookie:

```text
user=guest
```

or:

```text
role=user
```

---

# Cookie Manipulation

Modify the cookie value manually.

Example:

```text
role=admin
```

or:

```text
admin=true
```

Refresh the application after editing the cookie.

If the application trusts the modified value without verification, administrative functionality may become accessible.

---

# Encoded Cookies

Applications sometimes Base64-encode cookies.

Example encoded value:

```text
eyJyb2xlIjoidXNlciJ9
```

Decode using:

```bash
echo 'eyJyb2xlIjoidXNlciJ9' | base64 -d
```

Decoded result:

```json
{"role":"user"}
```

Modify the value:

```json
{"role":"admin"}
```

Re-encode:

```bash
echo '{"role":"admin"}' | base64
```

Replace the cookie with the new encoded value.

---

# JWT-Based Cookies

Some applications use JSON Web Tokens (JWTs).

Structure:

```text
HEADER.PAYLOAD.SIGNATURE
```

Example decoded payload:

```json
{
  "user":"guest",
  "role":"user"
}
```

If JWT signature verification is weak or disabled, attackers may modify the payload and forge administrative tokens.

---

# Exploitation

After modifying the cookie:

* Refresh the page
* Access restricted endpoints
* Attempt admin panel access
* Test privileged functionality

Successful exploitation demonstrates insecure trust of client-side authorization data.

---

# Root Cause

The vulnerability occurs because authorization decisions are based on user-controlled data.

Applications should never trust:

* Client-side role values
* Unsigned cookies
* Weakly signed tokens
* Editable authorization parameters

All sensitive authorization logic must be validated server-side.

---

# Security Impact

Cookie tampering vulnerabilities can lead to:

* Privilege escalation
* Authentication bypass
* Administrative access
* Session hijacking
* Sensitive data exposure
* Full account compromise

---

# Detection Techniques

## Manual Testing

* Inspect cookies
* Modify values
* Observe authorization changes
* Decode Base64 values
* Analyze JWT payloads

## Proxy-Based Testing

Using Burp Suite:

```text
Proxy → Intercept → Modify Cookie Header
```

Using browser extensions:

* EditThisCookie
* Cookie Editor

---

# Example Vulnerable Scenario

Server logic:

```python
if request.cookies.get("role") == "admin":
    grant_admin_access()
```

An attacker simply changes:

```text
role=user
```

to:

```text
role=admin
```

and gains unauthorized access.

---

# Secure Design Principles

## Server-Side Authorization

Authorization decisions must be enforced on the server.

## Use Signed Tokens

Cookies containing sensitive data should be:

* Signed
* Encrypted
* Integrity protected

## Validate Sessions Securely

Use server-managed sessions instead of client-controlled roles.

## Apply HttpOnly and Secure Flags

Example:

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

## Implement Least Privilege

Users should only receive the minimum required permissions.

---

# Common Real-World Issues

Developers frequently expose:

* Role identifiers
* User IDs
* Access levels
* Feature flags
* Session metadata

inside editable cookies.

Poor JWT validation is also a recurring issue in modern web applications.

---

# Key Takeaway

Client-side data is fully under attacker control.

Any authorization mechanism relying solely on browser-stored values is fundamentally insecure.

---

# Vulnerability Classification

* CWE-565: Reliance on Cookies without Validation and Integrity Checking
* CWE-602: Client-Side Enforcement of Server-Side Security
* CWE-639: Authorization Bypass Through User-Controlled Key
* OWASP A01:2021 – Broken Access Control

---

# Conclusion

Cookie manipulation attacks demonstrate the dangers of trusting client-side authorization data. Attackers routinely inspect and tamper with cookies during web application assessments.

Proper server-side authorization, signed session management, and secure token validation are essential to prevent privilege escalation vulnerabilities.

===

# HackDNA – Secrets in Source

## Challenge Overview

This challenge demonstrates how sensitive information can accidentally be exposed within the source code of a web application. Attackers frequently inspect frontend assets during reconnaissance to discover hidden credentials, internal comments, API keys, and development artifacts.

Source-code disclosure vulnerabilities are among the most common security weaknesses found in modern web applications.

---

# Objective

Inspect the application's source code and identify hidden secrets or sensitive information exposed to the client.

---

# Understanding Source Code Exposure

Everything delivered to the browser should be considered public.

Attackers routinely analyze:

* HTML source
* JavaScript files
* CSS comments
* Hidden form fields
* API requests
* Client-side configuration files

Developers sometimes unintentionally expose:

* Passwords
* API keys
* Debug comments
* Internal endpoints
* Tokens
* Administrative functionality

---

# Reconnaissance

Open the target webpage and inspect the source code.

View source using:

```bash
CTRL + U
```

or:

```bash
Right Click → View Page Source
```

Review the entire HTML document carefully.

---

# Initial Discovery

Sensitive information may appear inside comments.

Example:

```html
<!-- Temporary admin password: admin123 -->
```

or:

```html
<!-- TODO: remove debug credentials before deployment -->
```

Hidden fields may also reveal sensitive values.

Example:

```html
<input type="hidden" value="administrator">
```

---

# JavaScript Analysis

Applications often expose logic inside JavaScript files.

Inspect loaded scripts:

```html
<script src="main.js"></script>
```

Use browser developer tools:

```bash
F12 → Sources
```

Search for sensitive keywords:

```text
password
secret
admin
token
apikey
internal
```

---

# Example Vulnerable Code

Hardcoded credential:

```javascript
const adminPassword = "SuperSecret123";
```

Exposed API token:

```javascript
const api_key = "dev-api-key-001";
```

Debug endpoint:

```javascript
const debug_url = "/admin/debug";
```

Attackers use these discoveries during exploitation.

---

# Exploitation

Discovered credentials or hidden endpoints may provide:

* Administrative access
* API interaction
* Authentication bypass
* Hidden functionality
* Privilege escalation

Example workflow:

1. Discover hidden admin credential in source
2. Navigate to login page
3. Authenticate using exposed password
4. Gain unauthorized access

---

# Root Cause

The vulnerability exists because sensitive operational data was embedded directly into client-side resources.

Common causes include:

* Poor development practices
* Debugging leftovers
* Hardcoded secrets
* Incomplete deployment sanitization
* Misconfigured frontend applications

---

# Security Impact

Source-code disclosure may lead to:

* Credential compromise
* Account takeover
* Internal infrastructure exposure
* API abuse
* Privilege escalation
* Full application compromise

Attackers heavily rely on exposed information during reconnaissance.

---

# Detection Techniques

## Manual Inspection

* View source code
* Review comments
* Analyze hidden fields
* Inspect JavaScript files
* Monitor network requests

## Automated Secret Scanning

Using grep:

```bash
grep -Ri "password\|secret\|apikey\|token" .
```

Using Git tools:

```bash
gitleaks detect
```

Using browser DevTools:

```bash
F12 → Network → JS Files
```

---

# Defensive Measures

## Never Store Secrets Client-Side

Sensitive information must remain server-side.

## Remove Debug Information

Eliminate comments and development artifacts before deployment.

## Use Environment Variables

Secrets should be managed using:

* Environment variables
* Secret managers
* Vault solutions

## Conduct Secure Code Reviews

Implement:

* Static analysis
* Secret scanning
* CI/CD security checks
* Manual audits

## Apply Principle of Least Privilege

Even leaked tokens should have restricted permissions.

---

# Secure Development Example

Instead of:

```javascript
const db_password = "root123";
```

Use secure backend authentication with protected environment variables.

---

# Real-World Examples

Numerous real-world incidents involve exposed secrets in:

* GitHub repositories
* Frontend JavaScript
* Mobile applications
* Backup files
* CI/CD pipelines

Frequently leaked secrets include:

* AWS keys
* Database passwords
* OAuth tokens
* SMTP credentials
* Firebase configurations
* JWT secrets

---

# Key Takeaway

If sensitive information is accessible in the browser, attackers can retrieve it.

Frontend code must never contain operational secrets or authorization logic.

---

# Vulnerability Classification

* CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
* CWE-798: Use of Hard-coded Credentials
* CWE-215: Information Exposure Through Debug Information
* OWASP A05:2021 – Security Misconfiguration

---

# Conclusion

Source-code inspection is one of the first reconnaissance techniques used during penetration testing. Exposed secrets significantly increase organizational risk and often enable rapid exploitation.

Secure development practices, automated scanning, and strict secret management policies are essential to prevent information disclosure vulnerabilities.

===
