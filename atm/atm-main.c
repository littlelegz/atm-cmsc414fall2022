/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char prompt[] = "ATM: ";

int main(int argc, char**argv)
{
    FILE *atmfile = fopen(argv[1], "r");
    if (!atmfile) {
        printf("%s", "Error opening ATM initialization file");
        exit(64);
    }

    char line[97];
    char key[65];
    char iv[33];
    fgets(line, 97, atmfile);
    strncpy(key, line, 64);
    key[64] = '\0';
    strncpy(iv, line + 64, 32);
    iv[32] = '\0';
    //printf("key: %s\n", key);
    //printf("iv: %s\n", iv);

    char user_input[1000];

    ATM *atm = atm_create(
        (unsigned char *) key,
	(unsigned char *) iv
    );

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 1000, stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        printf("%s", prompt);
        fflush(stdout);
    }
	return EXIT_SUCCESS;
}
