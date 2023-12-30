#include <stdio.h>
#include <string.h>

unsigned short *a = 32;

void p(char *str, char *str2)
{
    char buf[4096];

    puts(str2);
    read(0, buf, 4096);
    *strchr(buf, '\n') = 0;
    strncpy(str, buf, 20);
}

// sub is incorrect by 4 bytes and ebx is not used
void pp(char *str)
{
    char buf[20];
    char buf2[20];

    p(buf2, " - ");
    p(buf, " - ");

    strcpy(str, buf2);

    str[strlen(str)] = *a;

    strcat(str, buf);
}

int main()
{
    char buf[42];

    pp(buf);
    puts(buf);

    return 0;
}