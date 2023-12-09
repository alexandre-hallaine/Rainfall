#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int *service;
int *auth;

int main()
{
    while (1)
    {
        printf("%p, %p \n", auth, service);

        char buf[128];

        if (!(fgets(buf, 128, stdin)))
            break;

        if (!(strncmp(buf, "auth ", 5)))
        {
            auth = malloc(4);
            *auth = 0;

            if (strlen(buf + 5) <= 30)
                strcpy(auth, buf + 5);
        }

        if (!(strncmp(buf, "reset", 5)))
            free(auth);

        if (!(strncmp(buf, "service", 6)))
            service = strdup(buf + 7);

        if (!(strncmp(buf, "login", 5)))
        {
            if (auth + 32)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}
