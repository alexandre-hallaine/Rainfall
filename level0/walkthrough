# Level0

## Hint

Use **gdb** and check the main function to find the exploit !

## Answer

Let's see what we have here:
```
level0@RainFall:~$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
```

When we run `level0` elf file, we get the following:
```
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)
```

Let's check why it crashes:
```
level0@RainFall:~$ gdb ./level0
(gdb) disassemble main
Dump of assembler code for function main:
[...]
   0x08048ec9 <+9>:		mov    0xc(%ebp),%eax
   0x08048ecc <+12>:	add    $0x4,%eax
   0x08048ecf <+15>:	mov    (%eax),%eax
   0x08048ed1 <+17>:	mov    %eax,(%esp)
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    $0x1a7,%eax
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
[...]
   0x08048f4a <+138>:	movl   $0x80c5348,(%esp)
   0x08048f51 <+145>:	call   0x8054640 <execv>
[...]
   0x08048f7b <+187>:	call   0x804a230 <fwrite>
[...]
End of assembler dump.
```

We can see that the first argument (**argv[1]** or 0xc(%ebp)) is used within the atoi function. That's why it crashes!

Alright, so we need to provide an argument to avoid the crash. If we check the next instruction, we see a jne instruction with 423 (0x1a7) and our **argv[1]**, which yields two result:
- if not equal, we jump to a **fwrite**:
```
level0@RainFall:~$ ./level0 42
No !
```
- if equal, we go to an **execv**:
```
level0@RainFall:~$ ./level0 423
$ whoami
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

It works! But why?

Let's place a breakpoint before the **execv** and check what it runs
```
level0@RainFall:~$ gdb level0 
(gdb) break *(main+145)
Breakpoint 1 at 0x8048f51
(gdb) run 423
Starting program: /home/user/level0/level0 423

Breakpoint 1, 0x08048f51 in main ()
(gdb) x/s 0x80c5348
0x80c5348:	 "/bin/sh"
```

It runs **/bin/sh**!
