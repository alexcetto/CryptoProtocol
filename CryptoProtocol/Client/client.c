//
//  client.c
//  CryptoProtocol
//
//  Created by José Tarsitano on 10/03/2016.
//  Copyright © 2016 Alexandre Cetto. All rights reserved.
//


/*
 * tcpclient.c - A simple TCP client
 * usage: tcpclient <host> <port>
 */
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include <unistd.h>
#include <stdlib.h>

#include "client.h"
#include "../crypto/crypto.h"

int main(int argc, char *argv[]) {
    char message[MSG_SIZE];

    int sock = openSocket();

    //keep communicating with server
    while (1) {
        printf("Enter message : ");
        scanf("%s", message);

        sendCommand(sock, message);

        receivedResponse(sock);
    }

    close(sock);
    return 0;
}

/**
 * Create and open a socket to the localhost on port 8888 and
 * authenticate the server with its cert and signature onto nonce.
 * Then, it generate session key, cipher it with server's public key
 * and send it.
 * To finish, it send the login:pwd ciphered to server and wait the OK from it.
 *
 * @return [int] sock  created socket
 */
int openSocket(void) {
    //Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
    }
    puts("Socket created");

    server.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    //Connect to remote server
    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    puts("Connected\n");

    /**************************************
     *                                    *
     * Send "Hello,N°version" message     *
     *                                    *
     **************************************/
    printf("Message : %s\n", HELLO_MSG);

    printf("socket %d\n", sock);

    if (send(sock, HELLO_MSG, strlen(HELLO_MSG), 0) < 0) {
        puts("Send failed");
        return -1;
    }

    /*******************************************
     *                                         *
     * receive(ServerCert, Nonce, Sig(Nonce))  *
     *                                         *
     *******************************************/
    receivedResponse(sock);

    puts("Received : ");
    puts(msg_received);

    // Get the cert into the received message
    receivedCert = malloc(CERT_SIZE* sizeof(char));
    for (int i = 0; i < CERT_SIZE; ++i) {
        receivedCert[i] = msg_received[i];
    }
    puts("Cert: ");
    puts(receivedCert);

    // Get the nonce into the received message
    receivedNonce = malloc(NONCE_SIZE* sizeof(char));
    int i = 0;
    for (int j = CERT_SIZE; j < CERT_SIZE+NONCE_SIZE; ++j) {
        receivedNonce[i] = msg_received[j];
        i++;
    }
    puts("Nonce: ");
    puts(receivedNonce);

    // Get the SIG(nonce) into the received message
    receivedSigNonce = malloc(SIG_SIZE*sizeof(char));
    i=0;
    for (int k = CERT_SIZE+NONCE_SIZE; k < CERT_SIZE+NONCE_SIZE+SIG_SIZE; ++k) {
        receivedSigNonce[i] = msg_received[k];
        i++;
    }
    puts("Sig: ");
    puts(receivedSigNonce);

    //@TODO: Debug verifyCert()
    //printf("Cert : %d\n", verifCert(receivedCert));



    /*
     * @TODO: Verif cert received with known one
     * @TODO: Generate Session Key
     * @TODO: send(cypher(session Key, Nonce+1))
     * @TODO: send(user:pwd, Nonce+1)
     * @TODO: receive(Connection OK)
     */




    return sock;
}

/**
 * Send a command to server.
 * @param  [int]   sock    the opened socket to the server
 * @param  [char*] message plaintext message to the server
 * @return [int]   0: send successful, 1: send fail
 */
int sendCommand(int sock, char* message) {
    // TODO: call encryptAES() to cipher message before send it
    if (send(sock, message, strlen(message), 0) < 0) {
        puts("Send failed");
        return 1;
    }
    return 0;
}

/**
 * Receive message from server.
 * @param  [int]   sock the opened socket to the server
 * @return [int]   0: send successful, 1: send fail
 */
int receivedResponse(int sock) {
    // TODO: call decryptAES() on ciphered message after received it.
    bzero(msg_received, strlen(msg_received));
    if (recv(sock, msg_received, MSG_SIZE, 0) < 0) {
        puts("recv failed");
        return 1;
    }
    return 0;
}