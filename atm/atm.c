#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

ATM *atm_create()
{
    ATM *atm = (ATM *)malloc(sizeof(ATM));
    if (atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&atm->rtr_addr, sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd, (struct sockaddr *)&atm->atm_addr, sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed

    return atm;
}

void atm_free(ATM *atm)
{
    if (atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr *)&atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{
    // TODO: Implement the ATM's side of the ATM-bank protocol

    /*
     * The following is a toy example that simply sends the
     * user's command to the bank, receives a message from the
     * bank, and then prints it to stdout.
     */
    // Splitting input on space
    char delimit[] = " \t\r\b\v\f\n";
    char *token = strtok(command, delimit);

    // Handling begin-session command
    if (strcmp(command, "begin-session") == 0)
    {
        char *name = strtok(NULL, delimit);
        token = strtok(NULL, delimit);
        if (token != NULL || name == NULL)
        {
            printf("Usage:  begin-session <user-name>\n\n");
            fflush(stdout);
        }
        else
        {
            // printf("Running command begin-session with user: %s\n", token);
            begin_session(atm, name);
        }
    }
    else if (strcmp(command, "end-session") == 0 ||
             strcmp(command, "withdraw") == 0 ||
             strcmp(command, "balance") == 0)
    {
        printf("No user logged in\n\n");
    }
    else
    {
        printf("Invalid command\n\n");
    }

    /*
    char recvline[10000];
    int n;

    atm_send(atm, command, strlen(command));
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    fputs(recvline,stdout);
    */
}

void begin_session(ATM *atm, char *name)
{
    char usercard[251];
    sprintf(usercard, "%s%s", name, ".card");
    FILE *userfile;
    // Checking if file exists
    if (access(usercard, F_OK) == 0)
    {
        // file exists
        userfile = fopen(usercard, "r");
        if (!userfile)
        {
            printf("Unable to access %s's card\n\n", name);
            return;
        }
    }
    else
    {
        // file doesn't exist
        printf("No such user\n\n");
        return;
    }

    // printf("[*] Sucessfully found usercard: %s\n", usercard);

    // Read in pin (assumed to be first line of user.card)
    char *pin = NULL;
    size_t len = 0;
    ssize_t read;
    char user_input[1001];

    // Read pin from .card file
    getline(&pin, &len, userfile);
    int pincode = atoi(pin);
    // printf("Read pin as: %d\n", pincode);
    // Prompt user for pin and read user input
    // [*] For some reason, I needed to convert strings to ints to comp
    printf("PIN? ");
    fflush(stdout);
    fgets(user_input, 1000, stdin);
    if (user_input == NULL)
    {
        printf("Not authorized\n\n");
        return;
    }
    int incode = atoi(user_input);
    fflush(stdout);

    // Authenticate pin and user
    if (incode == pincode)
    {
        // User is authenticated, prompt for further instructions
        printf("Authorized\n\n");
        printf("ATM (%s):  ", name);
        fflush(stdout);
        while (fgets(user_input, 1000, stdin) != NULL)
        {
            char delimit[] = " \t\r\b\v\f\n";
            char *token = strtok(user_input, delimit);
            if (token == NULL)
            {
                printf("ATM (%s):  ", name);
                fflush(stdout);
                continue;
            }
            // balance command
            if (strcmp(token, "balance") == 0)
            {
                token = strtok(NULL, delimit);
                if (token != NULL)
                {
                    printf("Usage: balance\n\n");
                    printf("ATM (%s):  ", name);
                    fflush(stdout);
                    continue;
                }
                //printf("[*] Running authenticated command balance\n");
                balance(atm, name);
            }
            else if (strcmp(token, "withdraw") == 0)
            { // withdraw command
                char *amt = strtok(NULL, delimit);
                token = strtok(NULL, delimit);
                if (token != NULL || amt == NULL)
                {
                    printf("Usage: withdraw <amt>\n\n");
                    printf("ATM (%s):  ", name);
                    fflush(stdout);
                    continue;
                }
                if (atoi(amt) < 0 || (atoi(amt) == 0 && amt[0] != '0')) {
                // Check if is negative, or if cannot convert to int and is not zero
                // Wrap around is converted to negative, so no need to check for overflow 
                    printf("Incorrect amt input. Int converted was%d\n", atoi(amt));
                    printf("ATM (%s):  ", name);
                    fflush(stdout);
                    continue;
                }
                //printf("[*] Running authenticated command withdraw\n");
                withdraw(atm, name, amt);
            }
            else if (strcmp(token, "end-session") == 0)
            { // end-session command
                printf("User logged out\n\n");
                return;
            }
            else if (strcmp(token, "begin-session") == 0)
            {
                printf("A user is already logged in\n\n");
            }
            else
            {
                printf("Invalid command\n\n");
            }

            printf("ATM (%s):  ", name);
            fflush(stdout);
        }
    }
    else
    {
        printf("Not authorized\n\n");
    }

    /* while ((read = getline(&line, &len, userfile)) != -1) {
        printf("%s", line);
    } */
}

void balance(ATM *atm, char *user)
{
    char recvline[10000];
    int n;
    char command[400];
    sprintf(command, "balance %s\n", user);

    // Sending balance command
    atm_send(atm, command, strlen(command));
    n = atm_recv(atm, recvline, 10000);
    recvline[n] = 0;
    fputs(recvline, stdout);
}

void withdraw(ATM *atm, char *user, char *amt)
{
    char recvline[10000];
    int n;
    char command[400];
    sprintf(command, "withdraw %s %s\n", user, amt);

    // Sending withdraw command
    atm_send(atm, command, strlen(command));
    n = atm_recv(atm, recvline, 10000);
    recvline[n] = 0;
    fputs(recvline, stdout);
}