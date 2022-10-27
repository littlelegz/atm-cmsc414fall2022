#include "bank.h"
#include "ports.h"
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../util/hash_table.h"

typedef struct _User {
    char pin[5];
    int balance;
} User;

Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr, sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    bank->users = hash_table_create(10);
    /*(User a;
    strcpy(a.pin, "1234");
    a.balance = 10000000;
    hash_table_add(bank->users, "jerry", &a);
    User *b = hash_table_find(bank->users, "jerry");
    printf("Jerry -> %s\n", (*b).pin);*/

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    // TODO: Implement the bank's local commands
    char delimit[] = " \t\r\n\v\f";
    char *token = strtok(command, delimit);
    if (strcmp(token, "create-user") == 0) {
        char *username = strtok(NULL, delimit);
        char *pin = strtok(NULL, delimit);
        char *balance = strtok(NULL, delimit);
        char *last = strtok(NULL, delimit);
	if (strlen(username) > 250 || last) {
	    printf("Usage:  create-user <user-name> <pin> <balance>\n");
	    return;
	}

	regex_t usernameRegex;
	regcomp(&usernameRegex, "[a-zA-Z]+", REG_EXTENDED);

	regex_t pinRegex;
	regcomp(&pinRegex, "[0-9][0-9][0-9][0-9]", REG_EXTENDED);

	regex_t balanceRegex;
	regcomp(&balanceRegex, "[0-9]+", REG_EXTENDED);

	if (
	    regexec(&usernameRegex, username, 0, NULL, 0) ||
	    regexec(&pinRegex, pin, 0, NULL, 0) ||
	    regexec(&balanceRegex, balance, 0, NULL, 0)
	) {
	    printf("Usage:  create-user <user-name> <pin> <balance>\n");
	    return;
	}

	if (hash_table_find(bank->users, username) != NULL) {
	    printf("Error:  user %s already exists\n", username);
	    return;
	}

	User newUser;
	strcpy(newUser.pin, pin);
	newUser.balance = atoi(balance);
	hash_table_add(bank->users, username, &newUser);

	char filename[256];
	strncpy(filename, username, strlen(username) + 1);
	strcat(filename, ".card");

	FILE *fp = fopen(filename, "w+");
	if (!fp) {
	    printf("Error creating card file for user %s\n", username);
	    hash_table_del(bank->users, username);
	    return;
	}

	fprintf(fp, "%s\n%s\n", pin, balance);
	fclose(fp);

	printf("Created user %s\n", username);
    }
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    // TODO: Implement the bank side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply receives a
	 * string from the ATM, prepends "Bank got: " and echoes 
	 * it back to the ATM before printing it to stdout.
	 */

	/*
    char sendline[1000];
    command[len]=0;
    sprintf(sendline, "Bank got: %s", command);
    bank_send(bank, sendline, strlen(sendline));
    printf("Received the following:\n");
    fputs(command, stdout);
	*/
}
