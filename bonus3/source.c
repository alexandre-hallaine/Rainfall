#include <stdio.h>
#include <string.h>
#include <unistd.h>

// one line difference main+43 (extra use of eax)
int main(int argc, char **argv)
{
    char buf[132];
    FILE *file;

    file = fopen("/home/user/end/.pass", "r");

    memset(buf, 0, 132);

    if (file == 0 || argc != 2)
        return -1;

    fread(buf, 1, 66, file);
    buf[65] = 0;
    buf[atoi(argv[1])] = 0;

    fread(buf + 66, 1, 65, file);
    fclose(file);

    if (strcmp(buf, argv[1]) == 0)
        execl("/bin/sh", "sh", 0);
    else
        puts(buf + 66);

    return 0;
}