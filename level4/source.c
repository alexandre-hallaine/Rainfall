#include <stdio.h>
#include <stdlib.h>

void p(char *buffer)
{
    printf(buffer);
}

int m;
void n(void)
{
    char buffer[512];
    fgets(buffer, 512, stdin);

    p(buffer);
    if (m == 16930116)
        system("/bin/cat /home/user/level5/.pass");
}

int main(void)
{
    n();
}
