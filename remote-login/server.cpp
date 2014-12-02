#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <polarssl/dhm.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "user.cpp"


char *socket_path = "\0hidden";
//unsigned char key[32] = {54, 207, 140, 177, 126, 224, 252, 171, 112, 224, 200, 60, 78, 13, 191, 219, 84, 13, 121, 195, 161, 97, 151, 243, 207, 35, 194, 227, 65, 74, 70, 35};
using namespace std;

int main(int argc, char *argv[]) {

  struct sockaddr_in serv_addr, cli_addr;

  int fd,cl,rc;
  unsigned int portno;
  
  
  vector<User> user_list = custom::get_users_from_file();
  cout << user_list[0].username<<endl;
  cout << user_list[1].username<<endl;
  
  constant char  *pers = "dh_server";
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  dhm_context dhm;
  
  if ( (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  bzero((char *)&serv_addr, sizeof(serv_addr));
  portno = 5001;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);

  if (bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
    perror("bind error");
    exit(-1);
  }

  if (listen(fd, 5) == -1) {
    perror("listen error");
    exit(-1);
  }
  unsigned int clilen = sizeof(cli_addr);
  while (1) {
    if ( ( cl = accept(fd, (struct sockaddr*)&cli_addr, &clilen)) == -1) {
      perror("accept error");
      continue;
    }
    if(fork()== 0){
    close(fd);
    string username, password,buffer;
    rc = custom::cpp_dec_read(cl, buffer);
    User u = custom::parseauthstring(buffer);
    //cout << u.username << " " << u.password<<endl;
    //cout << custom::exists(u,user_list);
    if(custom::exists(u,user_list))
    {
        buffer.assign("1");
        rc = custom::cpp_enc_write(cl,buffer);
        cout << "User "<< u.username << "logged in" <<endl;
    }
    else
    {
        buffer.assign("0");
        rc = custom::cpp_enc_write(cl,buffer);
        cout << "Failed login attempt" << endl;
        close(cl);
        return 0;
    }

    buffer.clear();
    
    while(1)
    {
        rc = custom::cpp_dec_read(cl,buffer);
        if(rc >= 0)
        {
            if(buffer == "exit")
            {
                cout << "User "<<u.username<<" logged out"<<endl;
                close(cl);
                return 0;
            }
            cout << "Read : " << buffer <<  endl;
            rc = custom::cpp_enc_write(cl,buffer);
            if(rc >= 0)
                cout << "Returned : "<< buffer << endl;
        }
        
        buffer.clear();

        if(rc == -1)
        {
            perror("socket i/o error");
            close(2);
        }
    }
    }
  }
  close(fd);
  return 0;
}
