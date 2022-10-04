#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include<inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PORT 12000 

int padding = RSA_PKCS1_PADDING;
AES_KEY *expanded;

unsigned char key[16] = {
    0xa2, 0x21, 0x12, 0x93,
    0xf9, 0xf5, 0x56, 0xa7,
    0xfa, 0x69, 0x35, 0xab,
    0xac, 0x7d, 0x0e, 0x1e
    };


static bool SetReadTimeout(const int sock)
{
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    printf("Unable to set the read timeout\n");
    return false;
  }

  return true;
}

RSA *RSA_create(unsigned char *key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio;
  keybio = BIO_new_mem_buf(key, -1);
  if (keybio == NULL)
  {
    printf("Failed to create key BIO");
    return 0;
  }
  if (public)
  {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  }
  else
  {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  }
  if (rsa == NULL)
  {
    printf("Failed to create the RSA");
  }

  return rsa;
}

int public_encryption(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *encrypted)
{
  RSA *rsa = RSA_create(key, 1);
  int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}

int public_decryption(unsigned char *enc_data, int data_len, unsigned char *key,
                   unsigned char *decrypted)
{
  RSA *rsa = RSA_create(key, 1);
  int result =
      RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
  return result;
}

static bool read_b(const int sock, char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    if (!SetReadTimeout(sock))
    {
      return false;
    }

    int ret = recv(sock, ptr, ptr - buf + n, 0);
    if (ret <= 0)
    {
      return false;
    }

    ptr += ret;
  }

  return true;
}

static bool write_b(const int sock, const char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    int ret = send(sock, ptr, n - (ptr - buf), 0);
    if (ret <= 0)
    {
      printf("Unable to send via socket\n");
      return false;
    }

    ptr += ret;
  }

  return true;
}

static void server(const int sock){
	int data_size = 8192;
	FILE *fp;
  char buf[data_size];
	int mes_data_size;
	read_b(sock, &mes_data_size, sizeof(mes_data_size));
	printf("The RSA public key data_size will be = %i\n" , mes_data_size);
	read_b(sock, buf, mes_data_size);
  fp = fopen("secret.txt", "w");
	unsigned char* encoded_m = malloc(mes_data_size) ;
	int key_data_size = strlen(key);
  //int key_data_size = 16;


	public_encryption(key, key_data_size, buf, encoded_m);
	printf("Sending the AES key\n");


  int encoded_size = strlen(encoded_m);
	write_b(sock, &encoded_size, sizeof(encoded_size));
	write_b(sock, encoded_m, encoded_size);
	printf("AES key sent\n");
	
	unsigned char out[16];
	char buff_2[data_size];
	read_b(sock, buff_2, 16);

	expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
	AES_set_decrypt_key(key, 128, expanded);
	AES_decrypt(buff_2, out, expanded);
	int k;
	for(k = 0; k < 16; k++){
                fprintf(fp, "%c", (char)out[k]);
        }
        printf("\n");

}

int main(int argc, char const *argv[]) 
{ 
    int sock = 0; 
    struct sockaddr_in server_address;
    sock = socket(AF_INET, SOCK_STREAM, 0);  
    if ((sock) > 0) 
    { 
        printf("New Socket is created \n"); 
  
    }
	
    server_address.sin_family = AF_INET; 
    server_address.sin_port = htons(PORT); 
    
    if(inet_pton(AF_INET, "10.75.9.63", &server_address.sin_addr) > 0)  
    { 
        printf("Socket address has been recognized \n"); 
 
    } 
 
    if (connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) == 0) 
   { 
        printf("The connection is setup \n"); 
    } 
    
    else if(connect(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
	    printf("Socket Address failed \n");
	    return -1;
    }
    server(sock);
	

    return 0; 
} 

