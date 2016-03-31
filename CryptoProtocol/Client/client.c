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

int main(int argc, char *argv[]) {
    char message[MSG_SIZE], msg_received[MSG_SIZE];
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

int openSocket(void) {
    //Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
    }
    puts("Socket created");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);

    //Connect to remote server
    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    puts("Connected\n");

    // Send Hello message
    printf("Message : %s\n", HELLO_MSG);

    printf("socket %d\n", sock);

    if (send(sock, HELLO_MSG, strlen(HELLO_MSG), 0) < 0) {
        puts("Send failed");
        return -1;
    }


    // receive(ServerCert, Nonce, Sig(Nonce))
    receivedResponse(sock);

    puts("Received : ");
    puts(msg_received);




    /*
     * @TODO: Verif cert received with known one
     * @TODO: Generate Session Key
     * @TODO: send(cypher(session Key, Nonce+1))
     * @TODO: send(user:pwd, Nonce+1)
     * @TODO: receive(Connection OK)
     */




    return sock;
}

int sendCommand(int sock, char* message) {
    //Send some data
    if (send(sock, message, strlen(message), 0) < 0) {
        puts("Send failed");
        return 1;
    }
    return 0;
}

void receivedResponse(int sock) {
    //Receive a reply from the server
    bzero(msg_received, strlen(msg_received));

    if (recv(sock, msg_received, MSG_SIZE, 0) < 0) {
        puts("recv failed");
        return;
    }
    return;
}