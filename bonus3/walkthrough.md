# Bonus 3

## Answer
Our C source code generates almost the same assembly code as the original binary. Compile it as follows:
> There is a slight difference as mentioned in the comments of the source code. I'm not sure why this optimization doesn't happen with our C source code, but it doesn't change the program's behavior.
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// one line difference main+43 (extra use of eax)
int main(int argc, char **argv)
{
    char buf[132];
    FILE *file;

    file = fopen("/home/user/end/.pass", "r");

    memset(buf, 0, 132);

    if (file == 0 || argc != 2)
        return -1;

    fread(buf, 1, 66, file);
    buf[65] = 0;
    buf[atoi(argv[1])] = 0;

    fread(buf + 66, 1, 65, file);
    fclose(file);

    if (strcmp(buf, argv[1]) == 0)
        execl("/bin/sh", "sh", 0);
    else
        puts(buf + 66);

    return 0;
}
```

Let's focus on the `main` function. It reads input from the command line and then `atoi` converts it to an integer, which is used to set a null byte in the `buf` buffer. Since we're going to compare the `buf` buffer with the `argv[1]` argument, and if they are equal, we will spawn a shell, we need to find a way for them to be equal.

However there is a catch, the `buf` buffer is filled with 66 bytes from the `/home/user/end/.pass` file, and then 65 bytes from the same file are appended to the `buf` buffer. There is no way for us to know the content of the file.  
But there's a way to cheat on the `strcmp` function, indeed, if we provide an empty string as the `argv[1]` argument, the `atoi` function will return 0, which will set the first byte of the `buf` buffer to 0. And, since the string was empty, `argv[1]` will also be 0. Therefore, the `strcmp` function will return 0 and we will spawn a shell.

Let's try it:
```bash
bonus3@RainFall:~$ ./bonus3 ""
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

We are now end! The project is over, congratulations!