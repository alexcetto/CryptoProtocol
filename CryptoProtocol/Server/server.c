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
#include <stdlib.h>

#include "server.h"
#include "../crypto/crypto.h"



/*
 * Start the TCP server and wait for a client to connect
 * The server listen to the 8888 port, defined in the .h
 */
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

    // Close properly the server socket, else may provoke errors
    close(socket_desc);

    return 0;
}


/*
 * Open the TCP socket
 */
int openSocket() {
    int optval; // Flag value for setsockopt

    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Could not create socket");
    }

    /* setsockopt: Handy debugging trick that lets
     * us rerun the server immediately after we kill it;
     * otherwise we have to wait about 20 secs.
     * Eliminates "ERROR on binding: Address already in use" error.
     */
    optval = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval , sizeof(int));
    puts("Socket created");

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(SERVER_PORT);

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


/*
 * Wait for a client to connect, negociate with the HELLO, version
 * if good, sends the payload containing server certificate, nonce and signed nonce to authenticate
 */
int acceptNewClient() {
    FILE *fp; /* certificate */
    size_t certSize; /* filesize */
    size_t buffSize;
    unsigned char* buffer; /*buffer will contain cert, nonce, SIG(nonce) */
    char nonce[4];
    unsigned char* signedNonce;
    char* certPath = getPath("cert");


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

    // Generate Nonce
    generateNonce(nonce);

    puts("Nonce:");
    printHex(nonce, sizeof(nonce));
    puts(nonce);

    // Sign Nonce
    signedNonce = sign(nonce);

    // store cert in buffer
    printf("Storing cert into buffer...\n");
    fp = fopen((const char*)certPath,"r");
    if (fp == NULL) {
        printf("Error: There was an Error opening the file %s \n", certPath);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);

    certSize = (size_t) ftell(fp);         /*calc the certSize needed*/
    fseek(fp, 0, SEEK_SET);
    buffSize = certSize + sizeof(nonce) + sizeof(signedNonce);
    buffer = malloc(buffSize);  /*allocalte space on heap*/

    if (fread(buffer, sizeof(char), certSize, fp) != certSize) {
        printf("Error: There was an Error reading the file %s\n", certPath);
        exit(1);
    }

    fclose(fp); // Close the certfile

    printf("%d\n", strlen(buffer));

    // Append ",nonce,signedNonce" to buffer
    sprintf(buffer + strlen(buffer), nonce);
    sprintf(buffer + strlen(buffer), signedNonce);


    // Send "cert,nonce,sig(nonce)"
    if (send(client_sock, buffer, strlen(buffer), 0) < 0) {
        puts("Send failed");
        return -1;
    }

    free(buffer);

     /*
     * @TODO: Receive(C(SessionKey, Nonce+1))
     * @TODO: Uncypher with private RSA key Session Key & check Nonce
     * @TODO: Receive(user:pwd, Nonce+1)
     * @TODO: Uncypher with Session Key & check Nonce
     * @TODO: checkUser(user, pwd)
     * @TODO: Send(Connection OK) OR Send(Connection NOT OK)
     */

    return 0;
}