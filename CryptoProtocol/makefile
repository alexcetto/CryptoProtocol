CC = gcc
CFLAG = -Wall
LIB_DIR = -L /usr/local/opt/openssl/lib
LIBH_DIR = -I /usr/local/opt/openssl/include

LIBS = -lssl -lcrypto

all: clean server client

lib: crypto/crypto.c crypto/crypto.h
	$(CC) -c crypto/crypto.c -o crypto.o $(LIB_DIR) $(LIBH_DIR) $(LIBS)

serv: Server/server.c Server/server.h
	$(CC) $(CFLAG) -c Server/server.c -o server.o $(LIB_DIR) $(LIBH_DIR) $(LIBS)  

cli: Client/client.c Client/client.h
	$(CC) $(CFLAG) -c Client/client.c -o client.o $(LIB_DIR) $(LIBH_DIR) $(LIBS)

server: lib serv
	$(CC) $(CFLAG) -o serverExe server.o crypto.o $(LIB_DIR) $(LIBH_DIR) $(LIBS) 

client: lib cli
	$(CC) $(CFLAG) -o clientExe client.o crypto.o $(LIB_DIR) $(LIBH_DIR) $(LIBS)

clean:
	rm *.o
