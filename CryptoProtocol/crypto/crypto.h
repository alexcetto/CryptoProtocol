//
//  crypto.h
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#ifndef crypto_h
#define crypto_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include <openssl/engine.h>

#define BUFF_SIZE 1024

/********************************** UTILS FUNCTIONS ************************************/
/* Passphrase */
unsigned char passPhrase[AES_BLOCK_SIZE];

/** Creation d'un passphrase.
 **/
void setPassPhrase();
/** Recuperation d'un passphrase.
 **/
unsigned char* getPassPhrase();

/** Recuperation du chemin absolu.
 * @param  [char*] keyType type de la cle (public, private),
 * @return [char*] chemin absolu.
 */
char* getPath(char* keyType);

/** Affichage buffer.
 @param [unsigned char*]  buff  buffer,
 @param [size_t]          len   taille du buffer.
 **/
void printBytes(unsigned char* buff, size_t len);
/***************************************************************************************/

/******************************* GENERATION KEY SESSION ********************************/
/**
 * Generation de la cle de session.
 */
void generateSessionKey();
/***************************************************************************************/

/************************* AES_128_CTR GLOBALS AND STRUCT INIT *************************/
struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
} state;

AES_KEY sessionKey;

/* Vecteur d'initialisation */
unsigned char iv[AES_BLOCK_SIZE];
/***************************************************************************************/

/************************** AES_128_CTR PROTOTYPES FUNCTIONS ***************************/

/** Initialisation AES MODE.
 @param [struct ctr_state]     *state  structure pour initialisation du mode,
 @param [const unsigned char]  iv      vecteur d'initialisation des blocs.
 **/
void init_ctr(struct ctr_state *state, const unsigned char iv[AES_BLOCK_SIZE]);

/** Chiffrement d'un fichier avec algorithme AES 128bits CTR.
 @param [char*]  read   fichier a chiffrer,
 @param [char*]  write  fichier de sortie chiffre,
 @return [int] statut 0 succes, -1 erreur.
 **/
char* encryptAES(char* plaintext);

/** Dechiffrement d'un fichier avec algorithme AES 128bits CTR.
 @param [char*]  read   fichier a chiffrer,
 @param [char*]  write  fichier de sortie chiffre,
 @return [int] statut 0 succes, -1 erreur.
 **/
unsigned char* decryptAES(unsigned char* cipher);
/***************************************************************************************/

/********************* SHA_256_HASH GLOBALS AND PROTOTYPE FUNCTION *********************/
/** Hachage d'un fichier avec SHA256.
 @param [unsigner char*]  md             hache,
 @param [char*]           filename       nom du fichier a hacher.
 @return [int] statut 0 succes, -1 erreur.
 **/
int SHA256_hach(void* input, unsigned long length, unsigned char* md);
/***************************************************************************************/

/** Generation d'un nonce.
 * @param [unsigned char*] nonce nonce,
 * @return 0, succes.
 */
int generateNonce(unsigned char* nonce);
/** Signe le nonce avec cle privee RSA.
 @param  [unsigned char*] nonce     nonce,
 @param  [unsigned char*] signature signature.
 **/
unsigned char * sign(unsigned char* nonce);

/** Chiffre un paquet avec cle publique RSA.
 * @param  [unsigned char*] packet paquet,
 * @return [unsigned char*] chaine de caracteres chiffree.
 */
unsigned char* cryptWithPublicKey(unsigned char* packet);

/** Dechiffre un paquet chiffre avec cle privee RSA.
 * @param  [unsigned char*] encodedPacket paquet chiffre,
 * @return [unsigned char*] chaine de caracteres dechiffree.
 */
unsigned char* decryptWithPrivateKey(unsigned char* encodedPacket);

void checkSign();

void printHex(const char *title, const unsigned char *s, int len);
#endif /* crypto_h */
