//
// Created by Olivier Marin on 29/03/2016.
//

#ifndef CRYPTOPROTOCOLCLIENT_AUTH_H
#define CRYPTOPROTOCOLCLIENT_AUTH_H


int checkUser(char* user, char* pass);
char * searchInDB(char *username);
int checkPassword(char *, char *);
char** str_split(char* a_str, const char a_delim);

#define SALTME "CAKUHDFBAOZEFHUBLAEHFBDLAUHEFBALZHFEBALUEFVKAUHFDBAZEFHBA"

#endif //CRYPTOPROTOCOLCLIENT_AUTH_H
