#include <iostream>
#include <sstream>
#include <string>
#include "polarss
#include "polarssl/sha1.h"
#include "polarssl/aes.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include<iostream>

unsigned char key[32] = {54, 207, 140, 177, 126, 224, 252, 171, 112, 224, 200, 60, 78, 13, 191, 219, 84, 13, 121, 195, 161, 97, 151, 243, 207, 35, 194, 227, 65, 74, 70, 35};


using namespace std;
namespace custom{

void setup_rng(
string cppsha1(string text) {
	unsigned char obuf[20];
	sha1((unsigned char*)text.c_str(), text.size(), obuf);
	string s="";
	
	int i;
	
 	for (i = 0; i < 20; i++) {
 		s+=obuf[i];
        }
        
	stringstream ss;
	for(int i=0; i<20; ++i)
	    ss << std::hex << (int)obuf[i];
	string mystr = ss.str();
    return mystr;
    }
    

string encrypt(string plaintext, unsigned char key[32]) {
	unsigned char IV[16];
	ctr_drbg_context ctr_drbg;
	entropy_context entropy;
	char *pers = "aes_generate_key";
	entropy_init(&entropy);
	unsigned char buff[64], buff_out[64];
	memset(buff, 0, sizeof(buff));
	for(int i=0; i<plaintext.length(); ++i) {
		buff[i] = plaintext[i];
}
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
  
	string en;
	for(int i=0; i<16; ++i)
    	en.push_back(IV[i]);
    	  
    aes_context enc_ctx;
    
    aes_setkey_enc(&enc_ctx, key, 256);
    
    aes_crypt_cbc(&enc_ctx, AES_ENCRYPT, 64, IV, buff, buff_out);
    
    
 
    for(int i=0; i<64; ++i) {
		en.push_back(buff_out[i]);
	}
    return en;
}

string decrypt(string ciphertext, unsigned char key[32]) {
	aes_context enc_ctx;
    
    aes_setkey_dec(&enc_ctx, key, 256);
    
    unsigned char IV[16], buff[64], buff_out[64];
    memset(buff, 0, sizeof(buff));
    memset(buff_out,0,sizeof(buff));
    for(int i=0; i<16; ++i)
    	IV[i]=ciphertext[i];
    for(int i=0; i<64; ++i)
    	buff[i] = ciphertext[i+16];
    aes_crypt_cbc(&enc_ctx, AES_DECRYPT, 64, IV, buff, buff_out);
    
    string de;
    for(int i=0; i<64 && buff_out[i]!=0; ++i)
    	de.push_back(buff_out[i]);
    return de;
}


}
