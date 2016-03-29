//
//  main.c
//  CryptoProtocol
//
//  Created by Alexandre Cetto on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#include <stdio.h>
#include "crypto/crypto.h"

int main(int argc, const char * argv[]) {
    // Passphrase
    setPassPhrase();

    // Generation de la cle de session
    generateSessionKey();

    // Chiffrement
    char* cipher = encryptAES("KALASH");
    // Dechiffrement
    char* plaintext = decryptAES(cipher);

    /* SHA256 */
    // Hashe
    unsigned char md[SHA256_DIGEST_LENGTH];
    // Message a hacher
    char* message = "POULPE";
    if(!SHA256_hach(message, sizeof(message), md)) {
        // Traitement des erreurs.
    }

    return 0;
}
