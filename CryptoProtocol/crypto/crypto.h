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
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/engine.h>


/***************************************************************************************/
/********************************** UTILS FUNCTIONS ************************************/
/***************************************************************************************/
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

/** Affichage buffer en Hexadecimal.
 @param [unsigned char*]  buff  buffer,
 @param [size_t]          len   taille du buffer.
 **/
void printHex(unsigned char* buff, size_t len);
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/*********************************** CLIENT FUNCTIONS **********************************/
/***************************************************************************************/
/** Verifie la signature avec cle publique RSA.
 @param  [unsigned char*] nonce     nonce,
 @param  [unsigned char*] signature signature.
 @return [int] 1 succes.
 **/
int checkSign(unsigned char* nonce, unsigned char* signature);

/**
 * Generation de la cle de session.
 */
void generateSessionKey();

/** Chiffre un paquet avec cle publique RSA.
 * @param  [unsigned char*] packet paquet,
 * @return [unsigned char*] chaine de caracteres chiffree.
 */
unsigned char* cryptWithPublicKey(unsigned char* packet);

int verifCert(char *buffcert);
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/*********************************** SERVER FUNCTIONS **********************************/
/***************************************************************************************/
/** Generation d'un nonce.
 * @param [unsigned char*] nonce nonce,
 * @return 0, succes.
 */
int generateNonce(char* nonce);
/** Signe le nonce avec cle privee RSA.
 @param  [unsigned char*] nonce     nonce,
 @return  [unsigned char*] signature signature.
 **/
unsigned char* sign(unsigned char* nonce);

/** Dechiffre un paquet chiffre avec cle privee RSA.
 * @param  [unsigned char*] encodedPacket paquet chiffre,
 * @return [unsigned char*] chaine de caracteres dechiffree.
 */
unsigned char* decryptWithPrivateKey(unsigned char* encodedPacket);
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

/***************************************************************************************/
/*********************************** COMMUNE FUNCTIONS *********************************/
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

/** Hachage d'un fichier avec SHA256.
 @param [unsigner char*]  md             hache,
 @param [char*]           filename       nom du fichier a hacher.
 @return [int] statut 0 succes, -1 erreur.
 **/
int SHA256_hach(void* input, unsigned long length, unsigned char* md);
/***************************************************************************************/

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/

#endif /* crypto_h */
