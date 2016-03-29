//
//  server.c
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//
/*
 * tcpserver.c - A simple TCP echo server
 * usage: tcpserver <port>
 */

/*
    C socket server example
*/

#include <stdio.h>
#include <string.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include "openssl/rand.h"
#include "openssl/err.h"

#include "server.h"
#include "../Auth/auth.h"

int main(int argc, char *argv[]) {

    openSocket();
    acceptNewClient();
    //Receive a message from client
    /*while (1) {
        bzero(client_message, MSG_SIZE);
        read_size = recv(client_sock, client_message, MSG_SIZE, 0);

        puts("Received :");
        puts(client_message);

        //Send the message back to client
        write(client_sock, client_message, read_size);
    }*/

    if (read_size == 0) {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if (read_size == -1) {
        perror("recv failed");
    }

    close(socket_desc);

    return 0;
}

int openSocket() {
    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Could not create socket");
    }
    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(8888);

    //Bind
    if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(socket_desc, 3);

    return 0;
}

int acceptNewClient() {
    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);

    //accept connection from an incoming client
    client_sock = accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &c);
    if (client_sock < 0) {
        perror("accept failed");
        return 1;
    }
    puts("Connection accepted");

    bzero(client_message, MSG_SIZE);
    read_size = (int) recv(client_sock, client_message, MSG_SIZE, 0);

    puts("Received :");
    puts(client_message);

    if(strncmp(client_message, MSG_HELLO, strlen(MSG_HELLO)) != 0) {
        perror("ERROR: Wrong Hello msg");
        return 1;
    }

    /**
     * @TODO: remplace by fonction
     */
    unsigned char nonce[4];
    int rc = RAND_bytes(nonce, sizeof(nonce));
    unsigned long err = ERR_get_error();

    if(rc != 1) {
        perror("ERROR: ");
        printf("%d", err);
    }

    /**
     * @TODO: Send certificate, nonce, SIG(nonce)
     */

    return 0;
}