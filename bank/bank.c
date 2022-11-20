#include "bank.h"
#include "ports.h"
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "../util/hash_table.h"

// TODO: relocate to utils
int is_safe_to_add(int a, int b)
{
    if (a >= 0)
    {
        if (b > (INT_MAX - a))
        {
            return 0;
        }
    }
    else
    {
        if (b < (INT_MIN - a))
        {
            return 0;
        }
    }

    return 1;
}

Bank *bank_create()
{
    Bank *bank = (Bank *)malloc(sizeof(Bank));
    if (bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&bank->rtr_addr, sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd, (struct sockaddr *)&bank->bank_addr, sizeof(bank->bank_addr));

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
    if (bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr *)&bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_create_user(Bank *bank, char *args)
{
    char *username = strsep(&args, " ");
    char *pin = strsep(&args, " ");
    char *balance = strsep(&args, " \n");
    char *extra = strsep(&args, " \n");

    if (
        username == NULL ||
        pin == NULL ||
        balance == NULL ||
        (extra != NULL && strcmp(extra, "") != 0))
    {
        printf("Usage:  create-user <user-name> <pin> <balance>\n");
        return;
    }

    long longBalance = strtoll(balance, NULL, 0);
    if (strlen(username) > 250 || longBalance > INT_MAX)
    {
        printf("Usage:  create-user <user-name> <pin> <balance>\n");
        return;
    }

    regex_t usernameRegex;
    regcomp(&usernameRegex, "^[a-zA-Z]+$", REG_EXTENDED);

    regex_t pinRegex;
    regcomp(&pinRegex, "^[0-9][0-9][0-9][0-9]$", REG_EXTENDED);

    regex_t balanceRegex;
    regcomp(&balanceRegex, "^[0-9]+$", REG_EXTENDED);

    if (
        regexec(&usernameRegex, username, 0, NULL, 0) ||
        regexec(&pinRegex, pin, 0, NULL, 0) ||
        regexec(&balanceRegex, balance, 0, NULL, 0))
    {
        printf("Usage:  create-user <user-name> <pin> <balance>\n");
        return;
    }

    if (hash_table_find(bank->users, username) != NULL)
    {
        printf("Error:  user %s already exists\n", username);
        return;
    }

    hash_table_add(bank->users, username, balance);

    char filename[256];
    strncpy(filename, username, strlen(username) + 1);
    strcat(filename, ".card");

    FILE *fp = fopen(filename, "w+");
    if (!fp)
    {
        printf("Error creating card file for user %s\n", username);
        hash_table_del(bank->users, username);
        return;
    }

    fprintf(fp, "%s\n", pin);
    fclose(fp);

    printf("Created user %s\n\n", username);
}

char *bank_process_balance(Bank *bank, char *args)
{
    char *username = strsep(&args, " \n");
    char *extra = strsep(&args, " \n");

    if (
        username == NULL ||
        strlen(username) > 250 ||
        (extra != NULL && strcmp(extra, "") != 0))
    {
        return "Usage:  balance <user-name>";
    }

    regex_t usernameRegex;
    regcomp(&usernameRegex, "^[a-zA-Z]+$", REG_EXTENDED);

    if (regexec(&usernameRegex, username, 0, NULL, 0))
    {
        return "Usage:  balance <user-name>";
    }

    char *balance = hash_table_find(bank->users, username);
    if (balance != NULL)
    {
        char *ret = malloc(sizeof(char) * 13);
        snprintf(ret, 13, "$%s", balance);
        return ret;
    }
    else
    {
        return "No such user";
    }
}

void bank_process_deposit(Bank *bank, char *args)
{
    char *username = strsep(&args, " ");
    char *amt = strsep(&args, " \n");
    char *extra = strsep(&args, " \n");

    if (
        username == NULL ||
        amt == NULL ||
        strlen(username) > 250 ||
        (extra != NULL && strcmp(extra, "") != 0))
    {
        printf("Usage:  deposit <user-name> <amt>\n");
        return;
    }

    regex_t usernameRegex;
    regcomp(&usernameRegex, "[a-zA-Z]+", REG_EXTENDED);

    regex_t amtRegex;
    regcomp(&amtRegex, "[0-9]+", REG_EXTENDED);

    if (
        regexec(&usernameRegex, username, 0, NULL, 0) ||
        regexec(&amtRegex, amt, 0, NULL, 0) ||
        atoi(amt) < 0)
    {
        printf("Usage:  deposit <user-name> <amt>\n");
        return;
    }

    char *balance = hash_table_find(bank->users, username);
    if (balance == NULL)
    {
        printf("No such user\n");
        return;
    }

    long longAmt = strtoll(amt, NULL, 0);
    if (
        longAmt > INT_MAX ||
        !is_safe_to_add(atoi(balance), atoi(amt)))
    {
        printf("Too rich for this program\n");
        return;
    }

    int newBalance = atoi(balance) + atoi(amt);
    char *newBalanceStr = malloc(12);
    snprintf(newBalanceStr, 12, "%d", newBalance);

    hash_table_del(bank->users, username);
    hash_table_add(bank->users, username, newBalanceStr);

    printf("$%s added to %s's account\n\n", amt, username);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    char *args = strdup(command);
    /*char *tofree = args;*/
    char *token = strsep(&args, " \n");
    if (strcmp(token, "create-user") == 0)
    {
        bank_process_create_user(bank, args);
    }
    else if (strcmp(token, "balance") == 0)
    {
        char *balance = bank_process_balance(bank, args);
        printf("%s\n\n", balance);
    }
    else if (strcmp(token, "deposit") == 0)
    {
        bank_process_deposit(bank, args);
    }
    else
    {
        printf("Invalid command\n\n");
    }

    /*if (tofree != NULL)
    {
        free(tofree);
    }*/
}

void bank_process_withdraw(Bank *bank, char *string)
{
    char *username = strsep(&string, " ");
    char *amt = strsep(&string, " \n");

    char *balance = hash_table_find(bank->users, username);
    if (balance == NULL)
    {
        // bank_send(bank, "No such user\n\n", 14);
        return;
    }

    int newBalance = atoi(balance) - atoi(amt);

    if (newBalance < 0)
    {
        bank_send(bank, "Insufficient funds\n\n", 21);
        return;
    }

    char *newBalanceStr = malloc(12);
    snprintf(newBalanceStr, 12, "%d", newBalance);

    hash_table_del(bank->users, username);
    hash_table_add(bank->users, username, newBalanceStr);

    char response[27];
    sprintf(response, "$%s dispensed\n\n", amt);
    bank_send(bank, response, strlen(response));
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    // TODO: Implement the bank side of the ATM-bank protocol

    /*
     * The following is a toy example that simply receives a
     * string from the ATM, prepends "Bank got: " and echoes
     * it back to the ATM before printing it to stdout.
     */

    // char sendline[1000];
    // command[len] = 0;
    // sprintf(sendline, "Bank got: %s\n", command);
    // bank_send(bank, sendline, strlen(sendline));
    // printf("Received the following:\n");
    // fputs(command, stdout);
    // fflush(stdout);

    char *string = strdup(command);
    char *token = strsep(&string, " \n");

    if (strcmp(token, "withdraw") == 0)
    {
        bank_process_withdraw(bank, string);
    }
    else if (strcmp(token, "balance") == 0)
    {
        char *ret = bank_process_balance(bank, string);
        char response[400];
        sprintf(response, "%s\n\n", ret);
        bank_send(bank, response, strlen(response));
    }
}
