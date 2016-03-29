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

int sock;
struct sockaddr_in server;
char message[MSG_SIZE], server_reply[MSG_SIZE];

#endif /* client_h */
