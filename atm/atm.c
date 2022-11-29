#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return 0;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return 0;
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return 0;
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

ATM *atm_create(unsigned char *key, unsigned char *iv)
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
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(atm->sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("Timeout amount not set");
    }
    
    // Initialize random seed for command IDs
    srand(time(NULL));

    atm->key = key;
    atm->iv = iv;
    //printf("key: %s\n", atm->key);
    //printf("iv: %s\n", atm->iv);

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
    char *card = NULL;
    size_t len = 0;
    char user_input[1001];

    // Read pin from .card file
    getline(&card, &len, userfile);
    int card_length = strlen(card);
    //printf("Card: %s", card);
    //printf("Length of card: %d\n", card_length);

    BIO *b64, *bmem;
    unsigned char *pin_ciphertext = (unsigned char *) malloc(card_length);
    memset(pin_ciphertext, 0, card_length);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(card, card_length);
    bmem = BIO_push(b64, bmem);
    int pin_ciphertext_len = BIO_read(bmem, pin_ciphertext, card_length);
    BIO_free_all(bmem);

    //printf("Length of base64 decoded PIN ciphertext: %d\n", pin_ciphertext_len);
    //printf("Decoded PIN ciphertext: %s\n", pin_ciphertext);
    
    unsigned char pin[128];
    decrypt(pin_ciphertext, pin_ciphertext_len, atm->key, atm->iv, pin);

    int pincode = atoi((char *) pin);
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
                // printf("[*] Running authenticated command balance\n");
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
                if (atoi(amt) < 0 || (atoi(amt) == 0 && amt[0] != '0'))
                {
                    // Check if is negative, or if cannot convert to int and is not zero
                    // Wrap around is converted to negative, so no need to check for overflow
                    // printf("Incorrect amt input. Int converted was%d\n", atoi(amt));
                    printf("Usage: withdraw <amt>\n\n");
                    printf("ATM (%s):  ", name);
                    fflush(stdout);
                    continue;
                }
                // printf("[*] Running authenticated command withdraw\n");
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
    int id = rand(); 
    sprintf(command, "%d balance %s\n", id, user);

    // Sending balance command
    atm_send(atm, command, strlen(command));
    n = atm_recv(atm, recvline, 10000);
    recvline[n] = 0;
    if (n == -1) {
        printf("Timeout error: No message was received\n\n");
        return;
    }
    fputs(recvline, stdout);
}

void withdraw(ATM *atm, char *user, char *amt)
{
    char recvline[10000];
    int n;
    char command[400];
    int id = rand(); 
    sprintf(command, "%d withdraw %s %s\n", id, user, amt);

    // Sending withdraw command
    atm_send(atm, command, strlen(command));
    n = atm_recv(atm, recvline, 10000);
    recvline[n] = 0;
    if (n == -1) {
        printf("Timeout error: No message was received\n\n");
        return;
    }
    fputs(recvline, stdout);
}
