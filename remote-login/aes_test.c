#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <polarssl/aes.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

int main()
{
    unsigned char buff[2][64] = {"ABCDEFGHIJKLMN", ""};
    int retval;
    unsigned char IV[16];
    unsigned char IV2[16];
    unsigned char key[32];
    ctr_drbg_context ctr_drbg;
    entropy_context entropy;
    char *pers = "aes_generate_key";
    entropy_init(&entropy);
    int ret;
    if ((ret = ctr_drbg_init(&ctr_drbg,entropy_func,&entropy,(unsigned char*)pers, strlen(pers))) != 0)
    {
        printf("Failed\n");
        return 0;
    }
    if((ret = ctr_drbg_random( &ctr_drbg,IV,16)) !=0)
    {
        printf("Failed\n");
        return 0;
    }
    
    if ((ret = ctr_drbg_init(&ctr_drbg,entropy_func,&entropy,(unsigned char*)pers, strlen(pers))) != 0)
    {
        printf("Failed\n");
        return 0;
    }
    if((ret = ctr_drbg_random( &ctr_drbg,key,32)) !=0)
    {
        printf("Failed\n");
        return 0;
    }
    aes_context enc_ctx;
    aes_context dec_ctx;

    memcpy(IV2,IV,16);           //copy IV

    aes_setkey_enc(&enc_ctx, key, 256);
    aes_setkey_dec(&dec_ctx, key, 256);


    //encrypt
    aes_crypt_cbc(&enc_ctx, AES_ENCRYPT, 64, IV, buff[0], buff[1]);
    printf("Before encrypt:%s\n", buff[0]);
    int i;
    for( i=0;i<16;i++)
        printf("%02x",buff[1][i]);
    printf("\n");
    //decrypt
    aes_crypt_cbc(&dec_ctx, AES_DECRYPT, 64, IV2, buff[1],buff[0]);
    printf("After decrypt:%s\n", buff[0]);
    
	for( i=0;i<32;i++)
        	printf("%02x", key[i]);
    printf("\n");    
    return 0;
}
