//
// Created by Olivier Marin on 29/03/2016.
//

#include <strings.h>
#include "auth.h"
#include "../Server/server.h"

int checkUser(char* user, char* pass) {

    bzero(client_message, MSG_SIZE);
    read_size = recv(client_sock, client_message, MSG_SIZE, 0);

    puts("Received :");
    puts(client_message);
}
