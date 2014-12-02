#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdlib>

#include "crypto.cpp"

#define BUFFER_SIZE 256

using namespace std;

namespace custom
{
    int getch()
    {
        int ch;
        struct termios t_old, t_new;

        tcgetattr(STDIN_FILENO, &t_old);
        t_new = t_old;
        t_new.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO,TCSANOW,&t_new);

        ch = getchar();

        tcsetattr(STDIN_FILENO,TCSANOW,&t_old);
        return ch;
    }

    string getpass(const char *prompt, bool show_asterisk=false)
    {
        const char BACKSPACE=127;
        const char RETURN=10;

        string password;
        unsigned char ch = 0;

        cout << prompt << endl;

        while((ch=getch())!=RETURN)
        {
            if(ch==BACKSPACE)
            {
                if(password.length()!=0)
                {
                    if(show_asterisk)
                        cout <<"\b \b";
                    password.resize(password.length()-1);
                }
            }
            else
            {
                password+=ch;
                if(show_asterisk)
                    cout << '*';
            }
        }
        cout << endl;
        return password;
    }
    
    string getauthstring(string username, string password)
    {
        string auth_string = "auth$" + username + "$" + password +"$";
        return auth_string;
    }
    
    
    int cpp_enc_write(int fd, string buffer)
    {
        string enc_buffer = custom::encrypt(buffer,key);
        unsigned char bytes = enc_buffer.length();
        int rc = write(fd, &bytes, 1);
        if(rc >= 0)
        {
            unsigned char buff[bytes];
            for(int i=0;i<bytes;i++)
                buff[i] = enc_buffer[i];
            rc = write(fd, buff, bytes);
        }
        return rc;
    }

    int cppwrite(int fd, string buffer)
    {
        unsigned char bytes = buffer.length();
        int rc = write(fd, &bytes, 1);
        if(rc >= 0)
        {
           // unsigned char buff[bytes];
          //  for(int i=0;i<bytes;i++)
          //      buff[i] = enc_buffer[i];
            rc = write(fd, buffer.c_str(), bytes);
        }
        return rc;
    }
    int cpp_dec_read(int fd, string& buffer)
    {
        string enc_buffer;
        unsigned char bytes;
        int rc = read(fd, &bytes, 1);
        if(rc > 0)
        {
            vector<char> temp_buff(bytes);
            rc = read(fd, temp_buff.data(),bytes);
            enc_buffer.assign(temp_buff.begin(),temp_buff.end());
        }
        string dec_buffer = custom::decrypt(enc_buffer,key);
        buffer.assign(dec_buffer.begin(),dec_buffer.end());
    }

    int cppread(int fd, string& buffer)
    {
        unsigned char bytes;
        int rc = read(fd, &bytes, 1);
        if(rc > 0)
        {
            vector<char> temp_buff(bytes);
            rc = read(fd, temp_buff.data(),bytes);
            buffer.assign(temp_buff.begin(),temp_buff.end());
        }
    }   
    
    bool authenticate(int fd, string username, string password)
    {
        string auth_string = custom::getauthstring(username,password);
        string buffer;
        //string enc_auth_string = custom::encrypt(auth_string,key);
        int rc = cpp_enc_write(fd, auth_string);
        rc = cpp_dec_read(fd, buffer);
        
        if(buffer[0] == '0')
            return false;
        else
            return true;        
    }


}
