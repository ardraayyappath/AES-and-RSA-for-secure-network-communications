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
#include <openssl/rand.h>

AES_KEY *expanded;

uint8_t secret[16] = {
    0xb2, 0x01, 0x12, 0x93,
    0xe9, 0x55, 0x26, 0xa7,
    0xea, 0x69, 0x3a, 0xcb,
    0xfc, 0x7d, 0x0e, 0x1f};
 
uint8_t key[16];

static __inline__ uint64_t timer_start(void)
{
  unsigned slow_cycle, fast_cycle;
  asm volatile("CPUID\n\t"
               "RDTSC\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               : "=r"(fast_cycle), "=r"(slow_cycle)::"%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)fast_cycle << 32) | slow_cycle;
}

static __inline__ uint64_t timer_stop(void)
{
  unsigned slow_cycle, fast_cycle;
  asm volatile("RDTSCP\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               "CPUID\n\t"
               : "=r"(fast_cycle), "=r"(slow_cycle)::"%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)fast_cycle << 32) | slow_cycle;
}
uint64_t sum;
int main()
  {  
    FILE *fp;
    AES_KEY *expanded;
    uint64_t A_time[1000000];
    int k = 0;
    int rc = RAND_bytes(key,sizeof(key));
    if(rc != 1)
    {
      printf("Error generating AES key");
    }
	fp = fopen("aes.txt", "w");
	unsigned char encoded_M[16]; 
	
	for(k = 0;  k < 1000000; k++){
 		  uint64_t t1 = timer_start();\
		  expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
		  AES_set_encrypt_key(key, 128, expanded);
		  AES_encrypt(secret, encoded_M, expanded);
		  uint64_t t2 = timer_stop();
		  A_time[k] = t2 - t1;
      sum += A_time[k]; 
      fprintf(fp,"%ld\n",A_time[k]);
      free(expanded);
	}
	uint64_t m = sum / 1000000;
	printf("The Mean obtained for AES is : %ld\n ", m);
  fclose(fp);
  return 0;
  }

