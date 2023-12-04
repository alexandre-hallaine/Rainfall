#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int ret; // Can't use size_t directly because of the if condition optimization
    char buf[40];

    ret = atoi(argv[1]);
    if (ret > 9)
        return 1;

    memcpy(buf, argv[2], (size_t)ret << 2);
    if (ret == 0x574f4c46)
        execl("/bin/sh", "sh", 0);

    return 0;
}