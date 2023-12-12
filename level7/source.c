#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

struct s {
    int id;
    void *ptr;
};

char c[80] = "";

void m()
{
    printf("%s - %d\n", c, time(0));
}

int main(int argc, char **argv)
{
    struct s *buffer1;
    struct s *buffer2;

    buffer1 = malloc(8);
    buffer1->id = 1;
    buffer1->ptr = malloc(8);

    buffer2 = malloc(8);
    buffer2->id = 2;
    buffer2->ptr = malloc(8);

    strcpy(buffer1->ptr, argv[1]);
    strcpy(buffer2->ptr, argv[2]);

    fgets(c, 68, fopen("/home/user/level8/.pass", "r"));
    puts("~~");
    return 0;
}
