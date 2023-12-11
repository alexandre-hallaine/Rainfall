#include <stdlib.h>
#include <stdio.h>
#include <time.h>

char c[80] = "";

void m()
{
    printf("%s - %d\n", c, time(0));
}

// this one isnt too accurate for now
int main(int argc, char **argv)
{
    int *buffer;
    int *buffer2;

    buffer = (int *)malloc(8);
    *buffer = 1;
    buffer[1] = (int)malloc(8); // how to malloc before buffer[1] = and without using a variable?
    // also ebx is used for some reason ? seems to mess up the whole rest of the assembly

    buffer2 = (int *)malloc(8);
    *buffer2 = 2;
    buffer2[1] = (int)malloc(8);
    buffer2 = argv[1];

    strcpy(buffer[1], argv[1]);
    strcpy(buffer2[1], argv[2]);

    fgets(c, 68, fopen("/home/user/level8/.pass", "r"));
    puts("~~");
}
