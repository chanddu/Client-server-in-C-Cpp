#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <netinet/in.h>

//Includes wrapper functions to use c++ style strings with sockets
#include "utility.cpp"

using namespace std;

int main(int argc, char *argv[]) {

  string username;
  
  //Take username and password from STDIN
  //Password is taken using getpass to prevent password from being displayed on screen

  cout << "Enter username: "<<endl;
  cin >> username;
  cout << endl;
  int c = getchar();
  string password = custom::getpass("Enter password: ");
  cout << endl;
  
  struct sockaddr_in serv_addr;
  struct hostent *server;

  int fd,rc;

  int portno = atoi(argv[2]);

  if ( (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }
  
  server = gethostbyname(argv[1]);
  if(server == NULL) {
        perror("No such host");
        exit(1);
    }
    
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char*)server->h_addr,(char*)&serv_addr.sin_addr.s_addr,server->h_length);
  serv_addr.sin_port = htons(portno);
  
  //Connect to server
  
  if (connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
    perror("connect error");
    printf("Error");
    exit(-1);
  }

  //Create authentication string
  //Format: auth$username$password
  //username and password should not contain $
    
    int logged_in = custom::authenticate(fd, username,password); 
   
    if(logged_in)
    {
        cout << "Connected to ECHO Server. Enter exit to exit" << endl;

        string readbuffer;
        string writebuffer;
        while(1)
            {
                cout << "Enter text: " << endl;
                getline(cin,readbuffer);
                int rc;
                rc = custom::cpp_enc_write(fd, readbuffer);
                if(readbuffer == "exit")
                {
                    int ret = shutdown(fd, 0);
                    return 0;
                }
                cout << "Server Returned: " << endl;
                rc = custom::cpp_dec_read(fd, writebuffer);
                cout << writebuffer << endl;
                readbuffer.clear();
                writebuffer.clear();
            }

    }
    else
    {   
        cout << "Incorrect credentials" << endl;
        shutdown(fd, 0);
                
    }
  return 0;
}

