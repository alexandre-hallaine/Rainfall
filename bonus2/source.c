#include <stdlib.h>
#include <string.h>

int language = 0;

void greetuser(char *str)
{
    char buf[64];

    switch (language)
    {
    case 0:
        strcpy(buf, "Hello ");
        break;

    case 1:
        strcpy(buf, "Hyvää päivää ");
        break;

    case 2:
        strcpy(buf, "Goedemiddag! ");
        break;
    }

    strcat(buf, str);
    puts(buf);
}

// one line difference main+31 (extra use of eax)
int main(int argc, char **argv)
{
    char buf[76];
    char *ret;
    char truc[64];

    if (argc != 3)
        return 1;

    memset(buf, 0, 76);
    strncpy(buf, argv[1], 40);
    strncpy(buf + 40, argv[2], 32);

    ret = getenv("LANG");
    if (ret != 0)
    {
        if (memcmp(ret, "fi", 2) == 0)
            language = 1;
        else if (memcmp(ret, "nl", 2) == 0)
            language = 2;
    }
    memcpy(truc, buf, 76); // This is incorrect, just to mimic the binary
    greetuser(buf);
}