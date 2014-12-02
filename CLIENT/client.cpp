/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include "crypt.cpp"

#define PORT "8008" // the port client will be connecting to 

#define MAXDATASIZE 1024 // max number of bytes we can get at once 
using namespace std;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	string msg,uname,paswd;
	unsigned char key[32] = {23,234,1,3,6,7,8,9,45,54,65,5,12,13,14,15,16,17,18,34,35,36,37,38,57,58,59,60,62,63,64,66};

	if (argc != 2) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure
	cout<<"User Name: ";
	cin>>uname;
	cout<<"Password: ";
	cin>>paswd;
	string encpaswd = custom::sha1_encryption(paswd);
	string keyWord = uname + "$" + encpaswd;
	send(sockfd,keyWord.c_str(),MAXDATASIZE-1, 0);

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n",buf);
	if(strcmp(buf,"Login failed!")==0){
		close(sockfd);
		exit(1);
	}
	
	while(1){
		cin>>msg;
		string oup = custom::aes_encryption(msg,key);
		send(sockfd,oup.c_str(),MAXDATASIZE-1, 0);
		if(msg=="quit")
			break;
	}

	close(sockfd);
	exit(1);

	return 0;
}
