# Welcome to the Walk_Throughs wiki!

### March 2024 Flash CTF

### Problem Camping Adventures

My friend went camping near some beautiful lake the other day and sent me a photo, but they refuse to tell me where it was!
![](https://metaproblems.com/f95246689bf80875673db4b3570be2ba/lake.jpg)

Can you help me figure out the name of that lake?

Simply enter the name of the lake as the flag. It does not need to be in the MetaCTF{} format.

### Solution 

First step is to run lake.png image file on analysis tool such as Exiftool on terminal.

```yaml

ExifTool Version Number         : 12.40
File Name                       : lake.jpg
Directory                       : .
File Size                       : 902 KiB
File Modification Date/Time     : 2024:08:06 12:33:56+03:00
File Access Date/Time           : 2024:08:06 12:33:53+03:00
File Inode Change Date/Time     : 2024:08:06 12:33:58+03:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Little-endian (Intel, II)
Make                            : samsung
Camera Model Name               : SM-G900V
Orientation                     : Horizontal (normal)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Modify Date                     : 2025:06:14 07:10:55
Y Cb Cr Positioning             : Centered
Exposure Time                   : 1/868
F Number                        : 2.4
Exposure Program                : Program AE
ISO                             : 50
Exif Version                    : 0220
Date/Time Original              : 2021:06:14 07:10:55
Create Date                     : 2021:06:14 07:10:55
Offset Time                     : -06:00
Offset Time Original            : -06:00
Shutter Speed Value             : 1
Aperture Value                  : 2.4
Brightness Value                : 20.88
Exposure Compensation           : 0
Max Aperture Value              : 2.4
Metering Mode                   : Spot
Flash                           : No Flash
Focal Length                    : 4.3 mm
Color Space                     : sRGB
Exif Image Width                : 2048
Exif Image Height               : 1536
Exposure Mode                   : Auto
White Balance                   : Auto
Digital Zoom Ratio              : 1
Focal Length In 35mm Format     : 26 mm
Scene Capture Type              : Standard
GPS Latitude Ref                : North
GPS Longitude Ref               : West
Image Width                     : 2048
Image Height                    : 1536
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Aperture                        : 2.4
Image Size                      : 2048x1536
Megapixels                      : 3.1
Scale Factor To 35 mm Equivalent: 6.0
Shutter Speed                   : 1/868
Date/Time Original              : 2021:06:14 07:10:55-06:00
Modify Date                     : 2025:06:14 07:10:55-06:00
GPS Latitude                    : 39 deg 9' 7.99" N
GPS Longitude                   : 106 deg 24' 20.73" W
Circle Of Confusion             : 0.005 mm
Field Of View                   : 69.4 deg
Focal Length                    : 4.3 mm (35 mm equivalent: 26.0 mm)
GPS Position                    : 39 deg 9' 7.99" N, 106 deg 24' 20.73" W
Hyperfocal Distance             : 1.55 m
Light Value                     : 13.3


``` 

> Of importance is the GPS position, `GPS Position: 39 deg 9' 7.99" N, 106 deg 24' 20.73" W`
> **Conversion to Decimal Degrees**
> **Latitude:**
> 39 degrees, 9 minutes, 7.99 seconds North
> 39 + 9/60 + 7.99/3600 = 39.152219444

> **Longitude:**
> 106 degrees, 24 minutes, 20.73 seconds West
> 106 + 24/60 + 20.73/3600
> 106+0.4+0.005758333
> 106.405758333


> Since the longitude is west, it will be negative:
> −
> 106.405758333
> −106.405758333

> Using a Mapping Service
> You can enter these decimal degrees coordinates into a mapping service like Google Maps to find the exact location.

> Decimal Degrees:
> Latitude: 39.152219444
> Longitude: -106.405758333

> Checking the Location on Google Maps
> You can simply copy and paste the decimal coordinates into the search bar of Google Maps:

Mngugi add-ons

> Create a Python script to parse and analyze these strings. Here's a script that will:

> Parse the DMS (degrees, minutes, seconds) format.
> Convert them to decimal degrees.
> Display the results.

**Code:**

```python

import re

def dms_to_decimal(dms_str):
    # Regular expression to parse the DMS format
    pattern = r'(\d+) deg (\d+)' + "'" + r' (\d+\.\d+)" ([NSEW])'
    match = re.match(pattern, dms_str)
    
    if not match:
        raise ValueError(f"Invalid DMS string: {dms_str}")
    
    degrees = int(match.group(1))
    minutes = int(match.group(2))
    seconds = float(match.group(3))
    direction = match.group(4)
    
    # Convert DMS to decimal degrees
    decimal_degrees = degrees + (minutes / 60) + (seconds / 3600)
    
    # Adjust the sign based on the direction
    if direction in ['S', 'W']:
        decimal_degrees = -decimal_degrees
    
    return decimal_degrees

# Define the strings
latitude_str = "39 deg 9' 7.99\" N"
longitude_str = "106 deg 24' 20.73\" W"

# Convert to decimal degrees
latitude_decimal = dms_to_decimal(latitude_str)
longitude_decimal = dms_to_decimal(longitude_str)

# Print the results
print(f"Latitude (decimal degrees): {latitude_decimal}")
print(f"Longitude (decimal degrees): {longitude_decimal}")

# Display the results using Streamlit
import streamlit as st

st.write("### DMS to Decimal Degrees Conversion")
st.write(f"**Latitude:** {latitude_str} -> **{latitude_decimal}**")
st.write(f"**Longitude:** {longitude_str} -> **{longitude_decimal}**")


```

---

### Problem 26 Dimensions 

> The supercomputing center just put out a program that checks physics theories for correctness. Can you figure out the answer to the universe and everything?
> Perhaps it's not as smart as they claim it is, and it has the answer hardcoded?


### Solution 
**by MetaCTF**
> Every time we run the program, it asks, Welcome to the physics checker. Enter your
> groundbreaking theory . Regardless of what we enter, it seems to always responds with
> Hmm, no, that theory doesn't seem to match the data .
> Looking closer at the binary and the challenges statement and considering the response
> talking about "matching the data", it seems likely that this is just a flag checker
> program - it checks your input against some simple logic or a predetermined string
> that determines if it's the flag or not, and we need to reverse that logic.
> In a more complicated challenge, this might mean breaking out a reverse engineering
> toolkit. But in this challenge, the flag was simply hardcoded. You can get it by
> running strings on it, a ubiquitous program that takes in a binary and prints out all
> strings of text (which it defines as long runs of printable - letters, numbers,
> spaces, etc - ASCII bytes).
> Let's try it. We are using a terminal but CyberChef has it too


```Bash
$ strings ./physics-checker
...
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
MetaCTF{wow_ther3s_lik3_littl3_str1ng5_1n_stuff}
Welcome to the physics checker. Enter your groundbreaking theory:
Congrats! The math checks out. The flag is %s.
Hmm, no, that theory doesn't seem to match the data...
:*3$"
...

```
> Most of it is just various ELF or libc-related strings, but near the middle, we see
> some stuff that got printed out earlier, and a bit above, we see something that
> clearly looks like a flag.
> We could properly reverse-engineer if we wanted to, but let's just test it.

```Bash
$ ../dist/physics-checker
Welcome to the physics checker. Enter your groundbreaking theory:
MetaCTF{wow_ther3s_lik3_littl3_str1ng5_1n_stuff}
Congrats! The math checks out. The flag is
MetaCTF{wow_ther3s_lik3_littl3_str1ng5_1n_stuff}.


```
### Mngugi Add-ons

Write a python program to further interact with the strings directly:

```python
import re

data = """
/lib64/ld-linux-x86-64.so.2
mgUa
__cxa_finalize
fgets
strcspn
__libc_start_main
strcmp
puts
stdin
__stack_chk_fail
printf
libc.so.6
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
MetaCTF{wow_ther3s_lik3_littl3_str1ng5_1n_stuff}
Welcome to the physics checker. Enter your groundbreaking theory: 
Congrats! The math checks out. The flag is %s.
Hmm, no, that theory doesn't seem to match the data...
:*3$"
GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
chal.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
_fini
__stack_chk_fail@GLIBC_2.4
printf@GLIBC_2.2.5
strcspn@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
"""

# Extract CTF flag
flag_pattern = r"MetaCTF\{.*?\}"
flag = re.search(flag_pattern, data)

# Extract GCC version
gcc_version_pattern = r"GCC: \(.*?\)"
gcc_version = re.search(gcc_version_pattern, data)

# Extract GLIBC versions
glibc_versions_pattern = r"GLIBC_\d+\.\d+"
glibc_versions = re.findall(glibc_versions_pattern, data)

print(f"CTF Flag: {flag.group() if flag else 'Not found'}")
print(f"GCC Version: {gcc_version.group() if gcc_version else 'Not found'}")
print(f"GLIBC Versions: {', '.join(glibc_versions) if glibc_versions else 'Not found'}")


```
> This script will search the provided data for the CTF flag, GCC version, and GLIBC versions and print them. You can expand this script to further analyze or process the data as needed.

---

### [Xylophone Network Graphics](https://compete.metactf.com/256/problems#problem7)

### Problem

I generated [some art](https://metaproblems.com/a200e0724f29c00c9700dcbc4c38f363/encrypted.xpng) as a PNG image, and then encrypted the file using an 8-character-long key that was repeated.

I can't remember what it was! Can you help me decrypt the image and retrieve the flag?

### Solution


---

### Feb 2024 Flash CTF Writeups

### Problem Statement

Take a look at ConnectWind's internal employee portal
`[https://metaproblems.com/71c5b42eb77639d5224be5589123de30/].` In addition to company policies & HR information, I heard it also stores flags.

Can you access the protected employee portal without knowing the password and steal
the flag?

### Solution
This is an IDOR (Insecure Direct Object References) or a CWE-306 (Missing Authentication for Critical Function) challenge.

View source of the website and take a look at the login function that is responsible for validating the username and password:

```js

function login() {
$("#result").fadeOut("fast");
// Send request with credentials
$.getJSON("login.php",
{
    "action":"login",
    "username": $("#username").val(),
    "password": $("#password").val()

}, function (r) {
 if (r.login_successful) {
   // Redirect if login successful
      set_alert('Login successful! Redirecting... <i class="fa-solid fa-spinner faspin"></i>', "success");
      setTimeout(function () {
window.location.href = "./employee_portal.php";
  }, 1500);
} else {
// Username or password incorrect
set_alert("Login failed! Please try again.", "danger");
      }
    }
  );
}



```

If the entered username and password are correct, the function redirects you to the
employee_portal.php page.
The vulnerability here is that the employee_portal.php page doesn't actually validate
if you're logged in or not. All you have to do is go to that page and look at the
flag:` https://metaproblems.com/71c5b42eb77639d5224be5589123de30/employee_portal.php`

### Mngugis' add-ons
The JavaScript code provided is vulnerable to several potential security risks. Here are the primary vulnerabilities and suggestions for securing the code:

**1. Potential Cross-Site Scripting (XSS)**

The `set_alert` function directly inserts user-provided data (txt) into the DOM without proper sanitization or escaping. If an attacker is able to inject malicious scripts, they can execute arbitrary JavaScript in the user's browser.

Mitigation: Use a secure method like textContent instead of `innerHTML or jQuery.html()`, or sanitize the input properly to prevent script injection.

**Example fix:**

```js

$("#result").text(txt); // Avoids using HTML to prevent XSS

```
2. Sensitive Data Exposure
Sending the username and password in a `GET` request is insecure, as the credentials will be exposed in the URL and potentially logged in browser history, server logs, or network traffic.

**Mitigation:** Use a POST request instead, which hides sensitive data from the URL.

**Example fix:**

```js

$.post("login.php", {
  "action": "login",
  "username": $("#username").val(),
  "password": $("#password").val()
}, function (r) {
  // Handle response
}, "json");

```

**3. Insecure Redirection**
After a successful login, the script redirects the user to `./employee_portal.php.` If the site is vulnerable to URL manipulation (e.g., open redirects), an attacker could trick users into being redirected to a malicious website.

**Mitigation:** Validate the redirection URLs on the server side. Ensure that only valid URLs are used for redirection.

**4. Client-Side Authentication Logic**
The login success logic is performed on the client side, which can be tampered with by an attacker. An attacker can modify the response or bypass the login check entirely by manipulating the JavaScript.

**Mitigation:** Ensure that authentication and authorization checks happen entirely on the server side, never trust client-side code for security-critical logic. The server should validate the credentials and return the appropriate response securely.

**5. No CSRF Protection**
The code does not implement any Cross-Site Request Forgery `(CSRF)` protection. An attacker could exploit this by tricking the user into sending a request to `login.php` without their knowledge.

**Mitigation:** Implement `CSRF` tokens to ensure that each request is coming from an authorized source.

**Suggested Improvements:**
Escape user inputs to prevent `XSS`.
Use `POST` for sending credentials to avoid URL exposure.
Perform login validation and redirection on the server side, and ensure the redirect URL is validated.
Add `CSRF` protection to prevent unauthorized requests.

With these changes, the login functionality will be more secure against common web vulnerabilities.

---

### Scenario: The Hacked Healthcare System

A small, regional healthcare provider has experienced a significant data breach. Patient records,
including sensitive health information, have been compromised and potentially leaked online.
The breach has caused widespread panic among patients and has damaged the hospital's
reputation.

### Tasks:
**1.  Identify and Analyze Attack Vectors:****
*** Question: What are the most likely attack vectors that could have been used to**
  **breach the healthcare provider's systems?**
* Task: Analyze potential attack vectors such as phishing emails, weak passwords,
  unpatched vulnerabilities, or social engineering tactics.

**3. Determine the Type of Malware:**

**Question: What kind of malware might have been used to infiltrate the system and**
**exfiltrate data?**
**Task: **
Consider malware types like ransomware, spyware, or data-stealing Trojans.
Analyze the potential impact of each type on the healthcare provider's systems and
data.
**3. Evaluate Cybersecurity Practices:**
**Question: What cybersecurity practices might have been lacking or inadequate,**
**leading to the breach?**
* Task: Evaluate the healthcare provider's policies and procedures related to:
* Password strength and complexity
* Employee training and awareness
* Network security measures (firewalls, intrusion detection systems)
* Data backup and recovery plans
* Incident response procedures
4. Develop Recommendations:
○ Question: What specific recommendations can be made to improve the healthcare
provider's cybersecurity posture and prevent future breaches?
**Task: Develop a comprehensive cybersecurity plan that includes:**
* Strong password policies
* Regular security awareness training for employees
* Network segmentation and access controls
* Regular system patching and vulnerability scanning
* Data encryption and backup
* Incident response plan
* Third-party risk management
### Ethical Considerations:
* Patient Privacy: Discuss the ethical implications of a data breach, including the potential
harm to patients and the healthcare provider's reputation.
* Data Protection Regulations: Explore the legal and regulatory requirements for
protecting patient data, such as HIPAA in the US or GDPR in the EU.
* Transparency and Communication: Consider the importance of transparent
communication with patients and other stakeholders about the breach and the steps being
taken to address it.

### Solution






