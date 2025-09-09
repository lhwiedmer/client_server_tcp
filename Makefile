CC=g++
CFLAGS= -Wall -g -O3

all: cliente servidor

cliente: cliente.cpp
	$(CC) $(CFLAGS) cliente.cpp -o cliente -lssl -lcrypto

servidor: servidor.cpp
	$(CC) $(CFLAGS) servidor.cpp -o servidor -lssl -lcrypto

clean:
	rm -f cliente servidor