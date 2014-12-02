#include <iostream>
#include <vector>

#include "user.cpp"

using namespace std;

int main()
{
    vector<User> user_list = custom::get_users_from_file();
    for(int i=0;i<(int)user_list.size();i++)
        cout << user_list[i].username << " "<<user_list[i].password<<endl;
    return 0;
}
