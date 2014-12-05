#include <iostream>
#include <fstream>
#include<string>
#include "crypt.cpp"

using namespace std;

int main()
{
    string username,password;
    cin >> username;
    cin >> password;
    
    ofstream file("db.txt", ios::app);
    file << username<<"$"; 
    file << custom::sha1_encryption(password)<<endl;
    
    return 0;

}
