CC=gcc
OPENSSL=openssl
INCLUDE=$(OPENSSL)/include/
CFLAGS=-c -I$(INCLUDE) 

all: server

p3: client.c
	$(CC) client.c -I$(INCLUDE) -L$(OPENSSL) -o client $(OPENSSL)/libcrypto.a -ldl -lpthread
	./client
	cat secret.txt

 

p1: 
		$(CC) rsa.c -I$(INCLUDE) -L$(OPENSSL) -o rsa $(OPENSSL)/libcrypto.a -ldl -lpthread
		$(CC) aes.c -I$(INCLUDE) -L$(OPENSSL) -o aes $(OPENSSL)/libcrypto.a -ldl -lpthread
		./aes
		./rsa

clean:
	rm -rf client rsa aes aes.txt rsa.txt