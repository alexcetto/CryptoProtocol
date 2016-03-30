//
// Created by Olivier Marin on 29/03/2016.
//

#include <strings.h>
#include "auth.h"
#include "../Server/server.h"


/*
 * Recieve the user and pass and check it against database
 * -> look for user in db text
 * if found
 * -> hmac the password with salt
 * -> if check if corresponding ok return ok
 * -> else return error
 * else return error
 */
int checkUser(char* user, char* pass) {
    if (searchInDB(user) == 1) {
        printf("c'est bon");
        return 1;
    }
    else {
        printf("pas dans la db");
        return 0;
    }
}

int searchInDB(char *str) {
    FILE *fp;
    int line_num = 1;
    int find_result = 0;
    char temp[512];
    char * fname = "/Users/alexandrecetto/CryptoProtocol/DB.txt";
    short found = 0;

    if((fp = fopen(fname, "r")) == NULL) {
    	return(-1);
    }

    while (fgets(temp, 512, fp) != NULL) {
        if ((strstr(temp, str)) != NULL) {
            printf("A match found on line: %d\n", line_num);
            printf("\n%s\n", temp);
            find_result++;
            found = 1;
        }
        line_num++;
    }

    if (find_result == 0) {
        printf("\nSorry, couldn't find a match.\n");
    }

    //Close the file if still open.
    if (fp) {
        fclose(fp);
    }

    if(found == 1)
        return 1;
    else
        return 0;
}