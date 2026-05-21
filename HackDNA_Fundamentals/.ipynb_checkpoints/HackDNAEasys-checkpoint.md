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
nmap -sn 192.168.1.10
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
nmap 192.168.1.10
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
nmap -sV 192.168.1.10
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
sudo nmap -O 192.168.1.10
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
sudo nmap -A 192.168.1.10
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
nmap -p- 192.168.1.10
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
