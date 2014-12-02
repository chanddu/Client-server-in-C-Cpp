#include <iostream>
#include <fstream>
#include "user.cpp"
#include "crypto.cpp"

using namespace std;

#define file_name "user"

int main()
{
    string username,password;
    cin >> username;
    cin >> password;
    
    ofstream file(file_name, ios::app);
    file << username<<endl; 
    file << custom::cppsha1(password)<<endl;
    
    return 0;

}
