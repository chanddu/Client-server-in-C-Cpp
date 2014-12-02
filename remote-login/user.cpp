#include<iostream>
#include<vector>
#include<string>
#include<fstream>
#include<sstream>
#include<sys/socket.h>
#include <openssl/sha.h>

#define filename "users"
#include "utility.cpp"

using namespace std;

struct User {
	string username, password;
};

namespace custom
{
vector<User> get_users_from_file() {	//making the vector for username, password
	vector<User> e;
	
	ifstream file;
	file.open(filename);
	
	string user, pass;
	
	while(!file.eof()) {
		User u;
		file>>user>>pass;
		u.username = user;
		u.password = pass;
		e.push_back(u);
	}
	
	file.close();
	
	return e;
}

void add_user(string username, string password, vector<User> *e) {	//adding username, password to vector and file
	ofstream file;
	file.open(filename, ios::app);
	file<<username<<endl;
	file<<password<<endl;
	file.close();
	
	User u;
	u.username = username;
	u.password = password;
	(*e).push_back(u);
}

bool exists(User u, vector<User> e) {	//checking if it is valid user
	cout << u.username << " " << u.password << endl;
    for(int i=0; i<(int)e.size(); ++i)
    {   
        cout << "!"<<endl;
		if(u.username==e[i].username && custom::cppsha1(u.password)==e[i].password)
			return true;
    }
	return false;
}

User parseauthstring(string auth_string)
    {
        User u;
        size_t pos;
        string delimiter = "$";
        pos = auth_string.find(delimiter);
        if(pos != string::npos)
        {
            auth_string.erase(0,pos+delimiter.length());
            pos = auth_string.find(delimiter);
            if(pos != string::npos)
            {
                u.username = auth_string.substr(0,pos);
                auth_string.erase(0, pos+delimiter.length());
                pos = auth_string.find(delimiter);
                if(pos != string::npos)
                {
                    u.password = auth_string.substr(0,pos);
                }
                else
                {
                    u.username = "";
                    u.password = "";
                }
            }
            else
            {
                u.username = "";
                u.password = "";
            }
        }
        else
        {
            u.username = "";
            u.password = "";
        }

        return u;
    }

}

