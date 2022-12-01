#include "bank.h"
#include "ports.h"
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <string.h>
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

// Source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encrypt(
    unsigned char *plaintext,
    int plaintext_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *ciphertext
)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return 0;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        return 0;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        return 0;
    }

    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return 0;
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// HMAC code from https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying#Calculating_HMAC
typedef unsigned char byte;
const char hn[] = "SHA256";

int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        if(ctx == NULL) {
            //printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        if(md == NULL) {
            //printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        if(rc != 1) {
            //printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        if(rc != 1) {
            //printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        if(rc != 1) {
            //printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        if(rc != 1) {
            //printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        if(!(req > 0)) {
            //printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        if(*sig == NULL) {
            //printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        if(rc != 1) {
            //printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        if(rc != 1) {
            //printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !slen || !pkey) {
        return -1;
    }

    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        if(ctx == NULL) {
            //printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        if(md == NULL) {
            //printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        if(rc != 1) {
            //printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        if(rc != 1) {
            //printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        if(rc != 1) {
            //printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        byte buff[EVP_MAX_MD_SIZE];
        size_t size = sizeof(buff);
        
        rc = EVP_DigestSignFinal(ctx, buff, &size);
        if(rc != 1) {
            //printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        if(!(size > 0)) {
            printf("EVP_DigestSignFinal failed (2)\n");
            break; /* failed */
        }
        
        const size_t m = (slen < size ? slen : size);
        result = !!CRYPTO_memcmp(sig, buff, m);
        
        OPENSSL_cleanse(buff, sizeof(buff));
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}

void print_it(const char* label, const byte* buff, size_t len)
{
    if(!buff || !len)
        return;
    
    if(label)
        printf("%s: ", label);
    
    for(size_t i=0; i < len; ++i)
        printf("%02X", buff[i]);
    
    printf("\n");
}

Bank *bank_create(unsigned char *key, unsigned char *iv)
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
    bank->ids = hash_table_create(10);
    /*(User a;
    strcpy(a.pin, "1234");
    a.balance = 10000000;
    hash_table_add(bank->users, "jerry", &a);
    User *b = hash_table_find(bank->users, "jerry");
    printf("Jerry -> %s\n", (*b).pin);*/

    bank->key = key;
    bank->iv = iv;
    bank->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen((char*)key));
    //printf("key: %s\n", bank->key);
    //printf("iv: %s\n", bank->iv);

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

    unsigned char ciphertext[128];
    int ciphertext_len;

    ciphertext_len = encrypt(
	(unsigned char *) pin,
	strlen ((char *) pin),
	bank->key,
	bank->iv,
	ciphertext
    );

    printf("Ciphertext length: %d\n", ciphertext_len);

    //printf("Ciphertext is:\n");
    //BIO_dump_fp(fp, (const char *)ciphertext, ciphertext_len);
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(fp, BIO_NOCLOSE);
    BIO_push(b64, bio);
    BIO_write(b64, ciphertext, ciphertext_len);
    BIO_flush(b64);
    BIO_free_all(b64);

    //fprintf(fp, "%x\n", pin);
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
    // char sendline[1000];
    // command[len] = 0;
    // sprintf(sendline, "Bank got: %s\n", command);
    // bank_send(bank, sendline, strlen(sendline));

    // Code for verifying command using signature NOT WORKING
    char *string = strdup(command);
    char* id = strsep(&string, " ");
    // Changed syntax of command to be comma separated will account for this below
    char *comm = strsep(&string, "\n");
    byte* sig = strsep(&string, "\n");
    size_t slen = 0;
    // After tokenizing the input, I need to reconstruct the entire msg
    char check[400];
    bzero(check, sizeof(check));
    sprintf(check, "%s %s\n", id, comm);
    // Printing received signature
    print_it("Signature1", sig, 32);
    fflush(stdout);
    //Calculating new signature on received msg, should match above
    byte* signew = NULL;
    int rc = sign_it(check, strlen(check), &signew, &slen, bank->pkey);
    print_it("Signature2", signew, 32);

    // Verifying that received msg has not been tampered;
    // Signature will always be 32 long
    rc = verify_it(check, strlen(check), sig, 32, bank->pkey);
    if(rc == 0) {
        printf("\nVerified signature\n\n");
    } else {
        printf("\nFailed to verify signature, message recevied was: %s\n\n", check);
        char* response = "Tampering detected, please try again\n\n";
        bank_send(bank, response, strlen(response));
        return;
    } 

    //printf("Received tokens id: %s, and command: %s\n\n", id, comm);
    fflush(stdout);

    if (hash_table_find(bank->ids, id) != NULL)
    {
        return;
    } 

    hash_table_add(bank->users, id, "");

    char* token = strsep(&comm, ",");

    if (strcmp(token, "withdraw") == 0)
    {
        bank_process_withdraw(bank, comm);
    }
    else if (strcmp(token, "balance") == 0)
    {
        char *ret = bank_process_balance(bank, comm);
        char response[400];
        sprintf(response, "%s\n\n", ret);
        bank_send(bank, response, strlen(response));
    }
}
