#include <strings.h>
#include <stdlib.h>
#include <assert.h>
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
    char * testUser = searchInDB(user);
    if (testUser != NULL) {
        printf("Found in DB \n");
        char ** hash = str_split(testUser, ':');
        printf("found %s", hash[1]);
        if (checkPassword(pass, hash[1]) == 1){
            printf("Password is coherent");
        }
        else return 0;
    }
    else {
        printf("Not found in DB\n");
        return 0;
    }
}


/*
 * Return the relative path of the DB, buggy for now, don't use it.
 * The DB should be stored in $HOME/CryptoProtocol/DB.txt
 */
char* getPathOfDB(void) {
    const char* name = "HOME";
    char*       homepath;
    char*       finalPath;

    homepath = getenv(name); // look for the user's directory

    if (homepath == NULL) {
        printf("Connais pas $HOME");
        exit(EXIT_FAILURE);
    }

    finalPath = malloc(200);

    /* Reconstruction du chemin relatif. */
    strcat(finalPath, homepath);
    strcat(finalPath, "/CryptoProtocol/DB.txt");

    return finalPath;
}


/*
 * Get the username and the hash of the pwd with the username parameter in the DB
 * Return the values found or NULL if nothing found
 */
char * searchInDB(char *username) {
    FILE    *fp;
    int     line_num = 1;
    char    temp[512];
    char*   fname = "/Users/alexandrecetto/CryptoProtocol/DB.txt"; // Fix for incorrect relative path
    short   found = 0;

    if((fp = fopen(fname, "r")) == NULL) {
        printf("Error opening DB file\n");
    	return NULL;
    }

    while (fgets(temp, 512, fp) != NULL && found != 1) {
        if ((strstr(temp, username)) != NULL) {
            found = 1;
            break;
        }
        line_num++;
    }


    //Close the file if still open.
    if (fp) {
        fclose(fp);
    }

    if(found == 1)
        return temp;
    else
        return NULL;
}


/*
 * Take the password hash found in db and the clear password and compare it
 * Return 0 if not coherent
 * Return 1 else
 */
int checkPassword(char * password, char * hash){


    return 1;
}


/*
 * Split str with the a_delim
 */
char **str_split(char *a_str, const char a_delim) {
    char *token;
    char *string;
    char *tofree;

    string = strdup(a_str);
    printf(a_str);

    if (string != NULL) {

        tofree = string;

        while ((token = strsep(&string, a_delim)) != NULL) {
            printf("%s\n", token);
        }

        free(tofree);
    } else {
        printf(string);
    }

    return NULL;
}