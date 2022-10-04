#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

int padding = RSA_PKCS1_PADDING;
uint8_t secret[16] = {
    0xb2, 0x01, 0x12, 0x93,
    0xe9, 0x55, 0x26, 0xa7,
    0xea, 0x69, 0x3a, 0xcb,
    0xfc, 0x7d, 0x0e, 0x1f};
	
char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAroyB+A4W/acwRq9gthl0\n"
"jb81nPHQ/s9lZNq0AEUnkWnOK+Rae+JoupsSeUehKYJQJkFYjnBc2aV8gSqxtY+b\n"
"r/XcIRSgk9ULUdELaak1WaYfjVEhyUgiQSXBa/QVsnSLMe4Hn6Mdx9J31y3/TLNp\n"
"AaB3Q37e9nfi3xT8K05govYbgV+j9z0zqJeJhS0D7aRzCc+MYDGlVuLpA0UDtjmA\n"
"KM0xD4e0U845qeUMqq7CdXt5mIiqFr7BL28F7zD9b5tqr407UEhsTESnkP9jfFJM\n"
"+t9+EKVUGmNTJMQPimRFot0ZGaTz4J4Jcnl3y0UhwwNqSVpnrOhAkzV+MhHmNOoc\n"
"wwIDAQAB\n"
                   "-----END PUBLIC KEY-----\n";
	
static __inline__ uint64_t tmr_start(void)
{
  unsigned cycles_low, cycles_high;
  asm volatile("CPUID\n\t"
               "RDTSC\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
}

static __inline__ uint64_t tmr_stop(void)
{
  unsigned cycles_low, cycles_high;
  asm volatile("RDTSCP\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               "CPUID\n\t"
               : "=r"(cycles_high), "=r"(cycles_low)::"%rax",
                 "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
}


RSA *createRSA(unsigned char *key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio;
  keybio = BIO_new_mem_buf(key, -1);
  if (keybio == NULL)
  {
    printf("Failed to create the key BIO");
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
    printf("Failed to create RSA");
  }

  return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *encrypted)
{
  RSA *rsa = createRSA(key, 1);
  int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}
uint64_t sum;
int main()
  {  
    FILE *fp;
    int k;
    uint64_t tmr_arr[1000000];
    fp = fopen("rsa.txt", "w");
	unsigned char* encoded = (unsigned char* )malloc(sizeof(publicKey));
	for(k = 0;  k < 1000000; k++){
 		  uint64_t t1 = tmr_start();\
		  public_encrypt(secret, sizeof(secret), publicKey, encoded);
		  uint64_t t2 = tmr_stop();
		  tmr_arr[k] = t2 - t1;
      sum += tmr_arr[k]; 
      fprintf(fp," %ld\n",tmr_arr[k]);
	}
	uint64_t m = sum / 1000000;
	printf("The Mean obtained for RSA is : %ld\n ", m);
  fclose(fp);
  return 0;
  }

