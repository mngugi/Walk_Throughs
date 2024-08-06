# Welcome to the Walk_Throughs wiki!

### March 2024 Flash CTF

### Problem 

My friend went camping near some beautiful lake the other day and sent me a photo, but they refuse to tell me where it was!
![](https://metaproblems.com/f95246689bf80875673db4b3570be2ba/lake.jpg)

Can you help me figure out the name of that lake?

Simply enter the name of the lake as the flag. It does not need to be in the MetaCTF{} format.

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
