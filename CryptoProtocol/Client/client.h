//
//  client.h
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#ifndef client_h
#define client_h

#include <stdio.h>
#include <netinet/in.h>

#define MSG_SIZE 4096
#define HELLO_MSG "Hello,1.0"
#define SIG_SIZE 512
#define CERT_SIZE 2358
#define NONCE_SIZE 4
#define PORT 8888
#define SERVER_ADDR "127.0.0.1"

struct sockaddr_in server;

char msg_received[MSG_SIZE];
char * receivedCert;
char * receivedNonce;
char * receivedSigNonce;


int openSocket(void);
int sendCommand(int sock, char* message);
int receivedResponse(int socket);

#endif /* client_h */
