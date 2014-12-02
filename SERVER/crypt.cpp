#include<iostream>
#include<sstream>
#include<string>
#include "polarssl/sha1.h"
#include "polarssl/aes.h"
#include "polarssl/aesni.h"

using namespace std;

unsigned char key[32] = {23,234,1,3,6,7,8,9,45,54,65,5,12,13,14,15,16,17,18,34,35,36,37,38,57,58,59,60,62,63,64,66};

namespace custom{
	string sha1_encryption(string paswd){
		unsigned char outputBuffer[20];
		sha1((unsigned char*)paswd.c_str(),paswd.size(),outputBuffer);
		string s="";
	
		int i;
	
 		for (i = 0; i < 20; i++) {
 			s+=outputBuffer[i];
        }
        
		stringstream ss;
		for(int i=0; i<20; ++i)
	    	ss << std::hex << (int)outputBuffer[i];
		string mystr = ss.str();
    	return mystr;
	}
	
	string aes_encryption(string msg,unsigned char key[32]){
		aes_context context;
		unsigned char output[16];
		string encryptedMSG;
		aes_init(&context);
		aes_setkey_enc(&context,key,256);
		for(int i=0;i<msg.length();i=i+16){
			string temp = msg.substr(i,16);
			aes_crypt_ecb(&context,AES_ENCRYPT,(unsigned char*)temp.c_str(),output);
			for(int j=0;j<16;j++)
				encryptedMSG.push_back(output[j]);
		}
		
		return encryptedMSG;
	}
	
	string aes_decryption(string msg,unsigned char key[32]){
		aes_context context;
		unsigned char output[16];
		string decryptedMSG;
		aes_init(&context);
		aes_setkey_dec(&context,key,256);
		for(int i=0;i<msg.length();i=i+16){
			string temp = msg.substr(i,16);
			aes_crypt_ecb(&context,AES_DECRYPT,(unsigned char*)temp.c_str(),output);
			for(int j=0;j<16;j++)
				decryptedMSG.push_back(output[j]);
		}
		
		return decryptedMSG;
	}
	
}