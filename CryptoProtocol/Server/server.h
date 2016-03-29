//
//  server.h
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//

#ifndef server_h
#define server_h

#include <stdio.h>
#include <netinet/in.h>

#define MSG_SIZE 1024

int socket_desc, client_sock, c, read_size;
struct sockaddr_in server, client;
char client_message[MSG_SIZE];

#endif /* server_h */
