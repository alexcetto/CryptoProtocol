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

#define MSG_SIZE 1024
#define HELLO_MSG "Hello,1.0"

//int sock;
struct sockaddr_in server;


int openSocket(void);
int sendCommand(int sock, char* message);
void receivedResponse(int socket);

#endif /* client_h */
