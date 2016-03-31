//
//  crypto.c
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#include "crypto.h"

/***************************************************************************************/
/********************************** PASSPHRASE FUNCTION ********************************/
/***************************************************************************************/

/** Creation d'un passphrase.
 **/
void setPassPhrase() {
    char* newPassPhrase;

    newPassPhrase = getpass("entrer passphrase: ");
    int lenPassPhrase = (int)strlen(newPassPhrase);

    if (lenPassPhrase < AES_BLOCK_SIZE) {
        for (int i = lenPassPhrase; i < AES_BLOCK_SIZE+1; i++)
            newPassPhrase[i] = '0';
    }

    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        passPhrase[i] = newPassPhrase[i];

}

/** Recuperation d'un passphrase.
 **/
unsigned char* getPassPhrase() {
    return passPhrase;
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/**************************** SESSION KEY GENERATION FUNCTION **************************/
/***************************************************************************************/

/**
 * Generation de la cle de session.
 */
void generateSessionKey() {
    // Initialisation de la cle pour chiffrer.
    if (AES_set_encrypt_key(passPhrase, 128, &sessionKey) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        exit(1);
    }
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/


/***************************************************************************************/
/********************************* AES128_CTR FUNCTIONS ********************************/
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
    
    init_ctr(&state, iv); //Counter call
    
    // Chiffrement.
    AES_ctr128_encrypt((unsigned char *) plaintext, cipher, AES_BLOCK_SIZE, &sessionKey, state.ivec, state.ecount, &state.num);
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
    AES_ctr128_encrypt(cipher, (unsigned char *) plaintext, AES_BLOCK_SIZE, &sessionKey, state.ivec, state.ecount, &state.num);
    printf("%s \n\n", plaintext);

    return plaintext;
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/****************************** HASH WITH SHA 256 FUNCTION *****************************/
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

    printHex(md, SHA256_DIGEST_LENGTH);

    return 0;
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/** Affichage buffer en Hexadecimal.
 @param [unsigned char*]  buff  buffer,
 @param [size_t]          len   taille du buffer.
 **/
void printHex(unsigned char* buff, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buff[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}

/***************************************************************************************/
/******************************** RSA SIGNATURE FUNCTION *******************************/
/***************************************************************************************/

/** Signe le nonce avec cle privee RSA.
 @param  [unsigned char*] nonce     nonce,
 @param  [unsigned char*] signature signature.
 **/
unsigned char* sign(unsigned char* nonce) {
    FILE* privkeyFile;
    RSA* privkey = NULL;

    OpenSSL_add_all_algorithms();
    char* privatePath = getPath("private");
    privkeyFile = fopen(privatePath, "r");

    // Lecture de la cle privee RSA.
    if (!PEM_read_RSAPrivateKey(privkeyFile, &privkey, NULL, "cryptoprotocol")) {
        fprintf(stderr, "Error loading Private Key File.\n");
        exit(1);
    }
    fclose(privkeyFile);

    // Hashe
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // Signature
    unsigned char* signature = malloc(sizeof(unsigned char)*512);
    // Taille de la signature
    unsigned int signLen;
    int ret;

    SHA256(nonce, 4, hash);

    /* Signature */
    ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signLen, privkey);
    printf("RSA_sign: %s\n", (ret == 1) ? "OK" : "NONOK");

    return signature;
}

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/** Generation d'un nonce.
 * @param [unsigned char*] nonce nonce,
 * @return 0, succes.
 */
int generateNonce(char* nonce) {
    int rc = RAND_bytes(nonce, sizeof(nonce));
    unsigned long err = ERR_get_error();

    if (rc != 1)
        printf("%lu", err);

    return 0;
}

/** Verifie la signature avec la cle publique RSA.
 @param  [unsigned char*] nonce     nonce,
 @param  [unsigned char*] signature signature.
 @return [int] 1 succes.
 **/
int checkSign(unsigned char* nonce, unsigned char* signature) {
    FILE* pubkeyFile;
    RSA* pubkey = NULL;

    OpenSSL_add_all_algorithms();
    char* publicPath = getPath("public");
    pubkeyFile = fopen(publicPath, "r");

    // Lecture de la cle publique RSA.
    if (!PEM_read_RSA_PUBKEY(pubkeyFile, &pubkey, NULL, "cryptoprotocol")) {
        fprintf(stderr, "Error loading Public Key File.\n");
        exit(1);
    }
    fclose(pubkeyFile);

    // Hashe
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int ret;

    SHA256(nonce, 4, hash);

    /* Verification */
    ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, 512, pubkey);
    printf("RSA_Verify: %s\n", (ret == 1) ? "OK" : "NONOK");

    return ret;
}

/** Recuperation du chemin absolu.
 * @param  [char*] keyType type de la cle (public, private),
 * @return [char*] chemin absolu.
 */
char* getPath(char* keyType) {
    const char* name = "HOME";
    char* value;
    char* finalPath;

    value = getenv(name);

    if (value == NULL) {
        printf("$HOME inconnu");
        exit(EXIT_FAILURE);
    }

    finalPath = malloc(strlen(value)+strlen(keyType)+26);

    /* Reconstruction du chemin relatif. */
    strcat(finalPath, value);
    strcat(finalPath, "/CryptoProtocol/cert/");
    strcat(finalPath, keyType);
    strcat(finalPath, ".pem");

    return finalPath;
}

/** Chiffre un paquet avec cle publique RSA.
 * @param  [unsigned char*] packet paquet,
 * @return [unsigned char*] chaine de caracteres chiffree.
 */
unsigned char* cryptWithPublicKey(unsigned char* packet) {
    char* publicPath = getPath("public");
    FILE* pubkeyFile = fopen(publicPath, "r");
    RSA* pubkey = NULL;

    // Lecture de la cle publique RSA.
    if (!PEM_read_RSA_PUBKEY(pubkeyFile, &pubkey, NULL, "cryptoprotocol")) {
        fprintf(stderr, "Error loading Public Key File.\n");
        return -1;
    }
    fclose(pubkeyFile);

    int pktLen;
    unsigned char encrypt[1024];

    /* Chiffrement */
    pktLen = RSA_public_encrypt(pktLen, packet, encrypt, pubkey,
                                    RSA_PKCS1_OAEP_PADDING);

    printf("Encrypt length = %d\n", pktLen);

    printf("crypt: %s\n", encrypt);

    return encrypt;
}

/** Dechiffre un paquet chiffre avec cle privee RSA.
 * @param  [unsigned char*] encodedPacket paquet chiffre,
 * @return [unsigned char*] chaine de caracteres dechiffree.
 */
unsigned char* decryptWithPrivateKey(unsigned char* encodedPacket) {
    char* privatePath = getPath("private");
    FILE* privkeyFile = fopen((const char*)privatePath, "r");
    RSA* privkey = NULL;

    OpenSSL_add_all_algorithms();
    // Lecture de la cle privee RSA.
    if (!PEM_read_RSAPrivateKey(privkeyFile, &privkey, NULL, "cryptoprotocol")) {
        fprintf(stderr, "Error loading Private Key File.\n");
        return -1;
    }
    fclose(privkeyFile);

    int encPktLen;
    printf("encodedPacket: %s\n", encodedPacket);

    unsigned char decrypt[1024];

    /* Dechiffrement */
    encPktLen = RSA_private_decrypt(512, encodedPacket, decrypt, privkey,
                                    RSA_PKCS1_OAEP_PADDING);

    printf("encPktLen: %d\n", encPktLen);
    if (strlen((const char*)encodedPacket) != encPktLen) {
        return 1;
    }

    for (int i = 0; i < encPktLen; i++) {
        if (encodedPacket[i] != decrypt[i]) {
            return 1;
        }
    }

    printf("decrypt: %s\n", decrypt);

    return decrypt;
}

