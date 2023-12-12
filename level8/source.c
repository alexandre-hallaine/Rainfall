#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct s_user {
    int id;
    char login[28];
    int is_auth;
};

int *service;
struct s_user *user;

int main()
{
    while (1)
    {
        printf("%p, %p \n", user, service);

        char buf[128];

        if (!(fgets(buf, 128, stdin)))
            break;

        if (!(strncmp(buf, "auth ", 5)))
        {
            user = malloc(4);
            user->id = 0;

            if (strlen(buf + 5) <= 30)
                strcpy(user, buf + 5);
        }

        if (!(strncmp(buf, "reset", 5)))
            free(user);

        if (!(strncmp(buf, "service", 6)))
            service = strdup(buf + 7);

        if (!(strncmp(buf, "login", 5)))
        {
            if (user->is_auth)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}
