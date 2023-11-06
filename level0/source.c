#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	if (atoi(argv[1]) == 423)
	{
		char *cmd_args[2];
		cmd_args[0] = strdup("/bin/sh");
		cmd_args[1] = 0;

		gid_t group = getegid();
		uid_t user = geteuid();
		setresgid(group, group, group);
		setresuid(user, user, user);

		execv("/bin/sh", cmd_args);
	}
	else
	{
		fwrite("No !\n", 1, 5, stderr);
	}

	return 0;
}
