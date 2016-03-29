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
    // insert code here...
    printf("Hello, World!\n");

    char* cipher = encryptAES("KALASH");
    char* plaintext = decryptAES(cipher);

    unsigned char md[SHA256_DIGEST_LENGTH]; // 32 bytes
    char* message = "POULPE";
    if(!SHA256_hach(message, sizeof(message), md))
    {
        // handle error
    }

    return 0;
}
