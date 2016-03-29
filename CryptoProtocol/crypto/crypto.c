//
//  crypto.c
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#include "crypto.h"

/***************************************************************************************/
/******************************* 1. AES128_CTR FUNCTIONS *******************************/
/***************************************************************************************/

/** Initialisation AES MODE.
 @param [struct ctr_state]     *state  structure pour initialisation du mode,
 @param [const unsigned char]  iv      vecteur d'initialisation des blocs.
 **/
void init_ctr(struct ctr_state *state, const unsigned char iv[AES_BLOCK_SIZE]) {
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    
    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);
    
    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

/** Chiffrement d'un fichier avec algorithme AES 128bits CTR.
 @param  [char*]  plaintext   chaine de caracteres a chiffrer,
 @return [char*]  le texte chiffre.
 **/
char* encryptAES(char* plaintext) {
    char* cipher[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Could not create random bytes.\n");
        return -1;
    }
    
    // Initialisation de la cle pour chiffrer.
    if (AES_set_encrypt_key("lol", 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        exit(1);
    }
    
    init_ctr(&state, iv); //Counter call
    
    // Chiffrement..
    AES_ctr128_encrypt((unsigned char *) plaintext, cipher, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
    printf("%s \n\n", cipher);


    return cipher;
}

/** Dechiffrement d'un fichier avec algorithme AES 128bits CTR.
 @param  [char*]  cipher   chaine de caracteres a dechiffrer,
 @return [char*]  le texte dechiffre.
 **/
unsigned char* decryptAES(unsigned char* cipher) {
    char* plaintext[AES_BLOCK_SIZE];
    init_ctr(&state, iv); //Counter call

    // Dechiffrement.
    AES_ctr128_encrypt(cipher, (unsigned char *) plaintext, AES_BLOCK_SIZE, &key, state.ivec, state.ecount, &state.num);
    printf("%s \n\n", plaintext);

    return plaintext;
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/**************************** 4. HASH WITH SHA 256 FUNCTION ****************************/
/***************************************************************************************/

/** Hachage d'un fichier avec SHA256.
 @param [void*]           input  message a hacher,
 @param [unsigned long]   length taille du message,
 @param [unsigned char*]  message hache,
 @return [int] statut 0 succes, -1 erreur.
 **/
int SHA256_hach(void* input, unsigned long length, unsigned char* md) {
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return -1;

    if(!SHA256_Update(&context, (unsigned char*)input, length))
        return -1;

    if(!SHA256_Final(md, &context))
        return -1;

    printBytes(md, SHA256_DIGEST_LENGTH);

    return 0;
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

void printBytes(unsigned char* buff, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buff[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}

void sign(char* s);

unsigned char* generateNonce() {
    unsigned char nonce[4];
    int rc = RAND_bytes(nonce, sizeof(nonce));
    unsigned long err = ERR_get_error();

    if (rc != 1)
        printf("%lu", err);

    return nonce;
}

void decryptWithPrivateKey();

void checkSign();

void generateSessionKey();

void cryptWithPublicKey();