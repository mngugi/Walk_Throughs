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

