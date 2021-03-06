//
//  crypto.c
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#include "crypto.h"

/***************************************************************************************/
/********************************** UTILS FUNCTIONS ************************************/
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
        passPhrase[i] = (unsigned char)newPassPhrase[i];

}

/** Recuperation d'un passphrase.
 **/
unsigned char* getPassPhrase() {
    return passPhrase;
}

/** Recuperation du chemin absolu.
 * @param  [char*] keyType type de la cle (public, private),
 * @return [char*] chemin absolu.
 **/
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
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/*********************************** CLIENT FUNCTIONS **********************************/
/***************************************************************************************/
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
    printf("verfication sign RSA: %s\n", (ret == 1) ? "OK" : "NONOK");

    return ret;
}

/**
 * Generation de la cle de session.
 **/
void generateSessionKey(AES_KEY * session) {
    // Initialisation de la cle pour chiffrer.
    if (AES_set_encrypt_key(passPhrase, 128, session) < 0) {
        fprintf(stderr, "Could not set encryption key.\n");
        exit(1);
    }
    setSessionKey(*session);
}

void setSessionKey(AES_KEY session) {
    sessionKey = session;
}

/** Chiffre un paquet avec cle publique RSA.
 * @param  [unsigned char*] packet paquet,
 * @param            [int*] pktLen pointeur sur la taille du paquet,
 * @return [unsigned char*] chaine de caracteres chiffree.
 **/
int cryptWithPublicKey(unsigned char* packet, int* pktLen, unsigned char** encrypt) {
    char* publicPath = getPath("public");
    FILE* pubkeyFile = fopen(publicPath, "r");
    RSA* pubkey = NULL;

    // Lecture de la cle publique RSA.
    if (!PEM_read_RSA_PUBKEY(pubkeyFile, &pubkey, NULL, "cryptoprotocol")) {
        fprintf(stderr, "Error loading Public Key File.\n");
        return -1;
    }
    fclose(pubkeyFile);

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

    //unsigned char encrypt[512];
    *encrypt = malloc(512* sizeof(unsigned char));
    size_t encPktLen = strlen((const char*)packet);

    /* Chiffrement */
    *pktLen = RSA_public_encrypt((int)encPktLen, packet, *encrypt, pubkey,
                                 RSA_PKCS1_OAEP_PADDING);

    return 1;
}

int verifCert(char *buffcert) {
    BIO              *certbio = NULL;
    BIO               *outbio = NULL;
    X509          *error_cert = NULL;
    X509                *cert = NULL;
    X509_NAME    *certsubject = NULL;
    X509_STORE         *store = NULL;
    X509_STORE_CTX  *vrfy_ctx = NULL;
    int ret;

    /* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
     * Initialize the global certificate validation store object. *
     * ---------------------------------------------------------- */
    if (!(store=X509_STORE_new()))
        BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

    /* ---------------------------------------------------------- *
     * Create the context structure for the validation operation. *
     * ---------------------------------------------------------- */
    vrfy_ctx = X509_STORE_CTX_new();

    /* ---------------------------------------------------------- *
     * Load the certificate and cacert chain from file (PEM).     *
     * ---------------------------------------------------------- */
    certbio = BIO_new_mem_buf((void*)buffcert, -1);
    if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        exit(-1);
    }

    ret = X509_STORE_load_locations(store, getPath("public"), NULL);
    if (ret != 1)
        BIO_printf(outbio, "Error loading CA cert or chain file\n");

    /* ---------------------------------------------------------- *
     * Initialize the ctx structure for a verification operation: *
     * Set the trusted cert store, the unvalidated cert, and any  *
     * potential certs that could be needed (here we set it NULL) *
     * ---------------------------------------------------------- */
    X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

    /* ---------------------------------------------------------- *
     * Check the complete cert chain can be build and validated.  *
     * Returns 1 on success, 0 on verification failures, and -1   *
     * for trouble with the ctx object (i.e. missing certificate) *
     * ---------------------------------------------------------- */
    ret = X509_verify_cert(vrfy_ctx);
    BIO_printf(outbio, "Verification return code: %d\n", ret);

    if(ret == 0 || ret == 1)
        BIO_printf(outbio, "Verification result text: %s\n",
                   X509_verify_cert_error_string(vrfy_ctx->error));

    /* ---------------------------------------------------------- *
     * Free up all structures                                     *
     * ---------------------------------------------------------- */
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    BIO_free_all(certbio);
    BIO_free_all(outbio);

    // Issue because self signed cert
    return 1;


}
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/*********************************** SERVER FUNCTIONS **********************************/
/***************************************************************************************/
/** Generation d'un nonce.
 * @param [unsigned char*] nonce nonce,
 * @return 0, succes.
 **/
int generateNonce(char* nonce) {
    int rc = RAND_bytes(nonce, sizeof(nonce));
    unsigned long err = ERR_get_error();

    if (rc != 1)
        printf("%lu", err);

    return 0;
}

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
    printf("signature RSA: %s\n", (ret == 1) ? "OK" : "NONOK");

    return signature;
}

/** Dechiffre un paquet chiffre avec cle privee RSA.
 * @param  [unsigned char*] encodedPacket paquet chiffre,
 * @param           [int] pktLen        taille du paquet chiffre,
 * @return [unsigned char*] chaine de caracteres dechiffree.
 **/
int decryptWithPrivateKey(unsigned char* encodedPacket, int pktLen, unsigned char ** decrypt) {
    char* privatePath = getPath("private");
    FILE* privkeyFile = fopen((const char*)privatePath, "r");
    RSA* privkey = NULL;

    OpenSSL_add_all_algorithms();
    // Lecture de la cle privee RSA.
    if (!PEM_read_RSAPrivateKey(privkeyFile, &privkey, NULL, "cryptoprotocol")) {
        fprintf(stderr, "Error loading Private Key File.\n");
        return 0;
    }
    fclose(privkeyFile);

    int decPktLen;
    *decrypt = malloc(512*sizeof(unsigned char));

    /* Dechiffrement */
    decPktLen = RSA_private_decrypt(pktLen, encodedPacket, *decrypt, privkey,
                                    RSA_PKCS1_OAEP_PADDING);

    for (int i = 0; i < decPktLen; i++) {
        if (encodedPacket[i] != decrypt[i]) {
            return 0;
        }
        //printf("%c", decrypt[i]);
    }

    return 1;
}
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/*********************************** COMMUNE FUNCTIONS *********************************/
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
int encryptAES(char* plaintext, unsigned char ** cipher) {
    *cipher = malloc(AES_BLOCK_SIZE* sizeof(unsigned char));

    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Could not create random bytes.\n");
        return 0;
    }
    
    init_ctr(&state, iv); //Counter call
    
    // Chiffrement.
    AES_ctr128_encrypt((unsigned char *) plaintext, *cipher, AES_BLOCK_SIZE, &sessionKey, state.ivec, state.ecount, &state.num);

    return 1;
}

/** Dechiffrement d'un fichier avec algorithme AES 128bits CTR.
 @param  [char*]  cipher   chaine de caracteres a dechiffrer,
 @return [char*]  le texte dechiffre.
 **/
int decryptAES(unsigned char* cipher, unsigned char ** plain) {
    *plain = malloc(AES_BLOCK_SIZE* sizeof(unsigned char));

    init_ctr(&state, iv); //Counter call

    // Dechiffrement.
    AES_ctr128_encrypt(cipher, *plain, AES_BLOCK_SIZE, &sessionKey, state.ivec, state.ecount, &state.num);

    return 1;
}

/** Hachage d'un fichier avec SHA256.
 @param [void*]           input  message a hacher,
 @param [unsigned long]   length taille du message,
 @param [unsigned char*]  md     message hache,
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

