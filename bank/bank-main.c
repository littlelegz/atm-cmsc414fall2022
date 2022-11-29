/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{
   FILE *bankfile = fopen(argv[1], "r");
   if (!bankfile) {
        printf("Error opening bank initialization file\n");
	exit(64);
   }

   char line[97];
   char key[65];
   char iv[33];
   fgets(line, 97, bankfile);
   strncpy(key, line, 64);
   key[64] = '\0';
   strncpy(iv, line + 64, 32);
   iv[32] = '\0';
   
   int n;
   char sendline[1000];
   char recvline[1000];

   Bank *bank = bank_create(
	(unsigned char *) key,
	(unsigned char *) iv
   );

   printf("%s", prompt);
   fflush(stdout);

   while(1)
   {
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, 10000,stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           n = bank_recv(bank, recvline, 10000);
           bank_process_remote_command(bank, recvline, n);
       }
   }

   return EXIT_SUCCESS;
}
