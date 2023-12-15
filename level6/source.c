#include <stdlib.h>
#include <string.h>

void n()
{
    system("/bin/cat /home/user/level7/.pass");
}

void m()
{
    puts("Nope");
}

int main(int ac, char **argv)
{
    int *buffer;
    void (**func)(void);

    buffer = (char *)malloc(64);
    func = (void (**)(void))malloc(4);

    *func = m;
    strcpy(buffer, argv[1]);
    (*func)();
}
