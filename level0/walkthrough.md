# Level0

## Foreword
In the following walkthroughs, we will frequently reference the source code we wrote. This is due to our initial step of translating the assembly code into C code.

Our aim was to align our C code closely with the original source code, a goal we largely achieved. Nonetheless, there are some deviations, which we will highlight as needed. We will also refer to the assembly code only when necessary.

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector -static source.c
```

Let's take a look at the source code:
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	if (atoi(argv[1]) == 423)
	{
		char *cmd_args[2];
		cmd_args[0] = strdup("/bin/sh");
		cmd_args[1] = 0;

		gid_t group = getegid();
		uid_t user = geteuid();
		setresgid(group, group, group);
		setresuid(user, user, user);

		execv("/bin/sh", cmd_args);
	}
	else
	{
		fwrite("No !\n", 1, 5, stderr);
	}

	return 0;
}
```

The program takes a single argument, converts it to an integer, and compares it to 423.

If the comparison is true, the program executes `/bin/sh` with the same privileges as the owner's group and user.
> Because the setuid bit is set on the binary, the program will run with the privileges of the owner, which is level1. This is true for all the binaries in this project.

Otherwise, it prints `No !\n` to stderr.

So we need to pass 423 as an argument to the program. Let's try it:
```bash
level0@RainFall:~$ ./level0 423
$ whoami
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

We are now level1! Let's move on to the next level.
