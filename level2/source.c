#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void p(void)
{
    fflush(stdout);

    int buffer[16];
    gets(buffer);

    int tmp = buffer[20];
    if ((tmp & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", tmp);
        exit(1);
    }
    puts(buffer);
    strdup(buffer);
}

int main(void)
{
    p();
}
