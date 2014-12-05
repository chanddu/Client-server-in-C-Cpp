#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stack>
#include <vector>
#include <set>
#include <algorithm>
#include <cmath>

using namespace std;

// FUNCTION PROTOTYPES

void init1();
void init2();
void init_z(int);
char encrypt(char, int);
char decrypt(char, int);

// GLOBALS

int pi[26]; int z[26];

// MAIN FUNCTION

int main() {

	int k, i, choice, len; string s;

	cout << "Stream Cipher with Enigma Mechanism: " << endl;
	cout << "1. Enter 1 for Encrypting a string"<< endl;
	cout << "2. Enter 2 for Decrypting a string"<< endl;
	cin >> choice;

	cout << "Enter the Key:"<< endl;
	cin >> k;

	// Initializations
	init2(); init_z(k);

	if(choice == 1) {

		cout << "Enter the string: " << endl;
		cin.ignore();
		getline (cin, s);
		char cipher[1000];
		len = s.length();

		for(i = 0; i < len; i++)
			cipher[i] = encrypt(s[i], z[i]);
		cipher[i] = '\0';

		cout << "Cipher string is: " << endl;
		cout << cipher << endl;
	}
	else if(choice == 2) {

		cout << "Enter the string: " << endl;
		cin.ignore();
		getline(cin, s);
		len = s.length();
		char sol[1000];

		for(i = 0; i < len; i++)
			sol[i] = decrypt(s[i], z[i]);
		sol[i] = '\0';

		cout << "Plain Text is: " << endl;
		cout << sol << endl;

	}


	return 0;
}

void init1() {

	for(int i = 0; i < 26; i++)
		pi[i] = i;

}

void init2() {

	int a[26] = {23,13,24,0,7,15,14,6,25,16,22,1,19,18,5,11,17,2,21,12,20,4,10,9,3,8};

	for(int i = 0; i < 26; i++)
		pi[i] = a[i];
}

void init_z(int k) {

	for(int i = 0; i < 26; i++)
		z[i] = (k+i-1)%26;
}

char encrypt(char c, int z) {

	if(c>='a' && c<='z')
		return (((pi[c-'a']+z)%26)+'a');

	if(c>='A' && c<='Z')
		return (((pi[c-'A']+z)%26)+'A');

	return c;

}

char decrypt(char c, int z) {

	int i;
	if(c>='A' && c<='Z'){
		for(i = 0; i < 25 && pi[i] != ((((c-'A') - z)+26)%26); i++);
			return (i + 'A');
	}

	if(c>='a' && c<='z'){
		for(i = 0; i < 25 && pi[i] != ((((c-'a') - z)+26)%26); i++);
			return (i + 'a');
	}
	return c;
}
