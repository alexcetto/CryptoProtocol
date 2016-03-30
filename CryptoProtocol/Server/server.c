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
#include "openssl/rand.h"
#include "openssl/err.h"

#include "server.h"
#include "../Auth/auth.h"
#include "../crypto/crypto.h"




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
    FILE *fp; /* certificate */
    size_t certSize; /* filesize */
    size_t buffSize;
    unsigned char* buffer; /*buffer will contain cert, nonce, SIG(nonce) */

    const char * name = "HOME";
    char * value;
    char * finalPath;

    value = getenv(name); // look for the user's directory

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
    generateNonce(nonce);
    puts("Nonce ");
    puts(nonce);

    /**
     * @TODO: Send(certificate, nonce, SIG(nonce)) - In progress
     */
    // store cert in buffer
    printf("Storing cert into buffer...\n");

    if(value == NULL) {
        printf("Connais pas HOMEPATH LOL");
        exit(EXIT_FAILURE);
    }

    puts(value);
    //sprintf(finalPath,"%s/CryptoProtocol/cert/cert.pem",value);
    finalPath = strcat(value, "/CryptoProtocol/cert/cert.pem");

    printf("LOOL %s\n", finalPath);

    fp = fopen((const char*)finalPath,"r"); /*open file*/
    if (fp == NULL){ /*ERROR detection if file == empty*/
        printf("Error: There was an Error opening the file %s \n", finalPath);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);

    certSize = (size_t) ftell(fp);         /*calc the certSize needed*/
    fseek(fp, 0, SEEK_SET);
    buffSize = certSize + sizeof(delimiter) + sizeof(nonce);
    buffer = malloc(buffSize);  /*allocalte space on heap*/

    if (fread(buffer, sizeof(char), certSize, fp) != certSize) {
        printf("Error: There was an Error reading the file %s\n", finalPath);
        exit(1);
    }

    /*int i;
    for(i=0; i<certSize;i++){
        printf("%02x", buffer[i]);
    }
    printf("\n");*/

    fclose(fp);


    //@TODO: Debug Signature

    /*
    unsigned char* signedNonce ;
    signedNonce = sign(nonce);

    puts("Signed Nonce ");
    puts(signedNonce);
    */

    // Append nonce to buffer
    sprintf(buffer + strlen(buffer), delimiter);
    sprintf(buffer + strlen(buffer), nonce);

    printf("Buffer : ");
    puts(buffer);

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