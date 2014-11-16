#define _XOPEN_SOURCE

#include <stdio.h>
#include <cs50.h>
#include <string.h>
#include <unistd.h>

int main(int argc, string argv[])
{
    printf("%s\n", crypt(argv[1], "50"));
    return 0;
}

