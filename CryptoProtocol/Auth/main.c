#include <stdio.h>
#include "auth.h"
#include <openssl/sha.h>
#include <string.h>
#include "../crypto/crypto.h"



/*
 * Test main to check auth functions. Don't use for production :(
 */
int main(int argc, const char * argv[]) {

    // Generate a hashed password with a bit of salt
    /*char data[] = "password";
    size_t length = strlen(data) + strlen(SALTME)+10;
    char * toHash;
    toHash= malloc(length);
    strcpy(toHash, SALTME);
    strcat(toHash, data);
    char hash[SHA512_DIGEST_LENGTH];
    char * result = SHA512(toHash, sizeof(data) - 1, hash);
    for (int i = 0; i < strlen(toHash); i++) {
        printf("%02X", hash[i]);
    }*/
    int erreur = checkUser("user:", "password");
    if (erreur > 0)
        printf("trouvé");
    else
        printf("pas trouvé  ou erreur %d", erreur);
    return 0;
}