CC=g++
CFLAGS= -Wall -g -O3

all: cliente servidor

cliente: cliente.cpp encrypt.o decrypt.o
	$(CC) $(CFLAGS) cliente.cpp -o cliente encrypt.o decrypt.o sign.o \
	verify.o -lssl -lcrypto

servidor: servidor.cpp encrypt.o decrypt.o
	$(CC) $(CFLAGS) servidor.cpp -o servidor encrypt.o decrypt.o sign.o \
	verify.o -lssl -lcrypto

decrypt.o: decrypt/decrypt.cpp
	$(CC) $(CFLAGS) -c decrypt/decrypt.cpp -o decrypt.o -lssl -lcrypto

encrypt.o: encrypt/encrypt.cpp
	$(CC) $(CFLAGS) -c encrypt/encrypt.cpp -o encrypt.o -lssl -lcrypto

verify.o: verify/verify.cpp
	$(CC) $(CFLAGS) -c verify/verify.cpp -o verify.o -lssl -lcrypto

sign.o: sign/sign.cpp
	$(CC) $(CFLAGS) -c sign/sign.cpp -o sign.o -lssl -lcrypto

clean:
	rm -f cliente servidor *.o