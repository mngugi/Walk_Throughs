
#include <stdio.h>
#include <string.h>

void vulnerable(void)
{
    char buffer[8];

    strcpy(buffer, "AAAAAAAAAAAAAAAA");

    printf("Buffer: %s\n", buffer);
}

int main(void)
{
    vulnerable();

    printf("Program continued normally.\n");

    return 0;
}
