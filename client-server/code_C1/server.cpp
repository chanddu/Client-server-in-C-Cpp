/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include<fstream>
#include "crypt.cpp"
#include "polarssl/dhm.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/bignum.h"

#define PORT "8008"  // the port users will be connecting to

#define BACKLOG 10	 // how many pending connections queue will hold

int generate_key_serv(int fd,  unsigned char *key, size_t keylen);
unsigned char key[32];

using namespace std;

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	//unsigned char key[32] = {23,234,1,3,6,7,8,9,45,54,65,5,12,13,14,15,16,17,18,34,35,36,37,38,57,58,59,60,62,63,64,66};
	char buf[1024];
	bool exists = false;
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: got connection from %s\n", s);

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			recv(new_fd, buf, 1023, 0);
			ifstream myfile("db.txt");
			string line;
			string oup(buf);
			if(myfile.is_open()){
				while(!myfile.eof()){
					myfile>>line;
					if(line.compare(oup)==0){
						if (send(new_fd, "Successful Login!", 18, 0) == -1)
							perror("send");
						exists = true;
					}
				}
				myfile.close();
			}
			else
				cout<<"error opening db file"<<endl;
			if(exists){
				int rv = generate_key_serv(new_fd,key,32);
				while(1){
					recv(new_fd, buf, 1023, 0);
					string sen(buf);
					char op[16];
					string out = custom::aes_decryption(sen,key);
					if(strcmp(out.c_str(),"quit")==0){
						cout<<"connection from "<<s<<" terminated"<<endl;
						break;
					}
					for(int i=0;i<out.length();i++){
						if(out[i]=='\0')
							break;
						putchar((out[i]+256)%256);
					}
					printf("\n");
				}
			}
			else{
				cout<<"Unauthorised user attempted to connect but failed"<<endl;
				if (send(new_fd, "Login failed!", 14, 0) == -1)
					perror("send");
			}
			close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
	}

	return 0;
}

int generate_key_serv(int fd, unsigned char *key, size_t keylen)
{
	unsigned char buflen = 128;		/* Use 1024-bit P */
	unsigned char buf[(int)buflen];
  int rc;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	dhm_context dhm;

	/* Diffie-Hellman init */
	dhm_init(&dhm);

	/* Seeding the random number generator */
	entropy_init(&entropy);
	if (ctr_drbg_init(&ctr_drbg, entropy_func,
				&entropy, NULL, 0) != 0) {
		fprintf(stderr, "ERROR: ctr_drbg_init\n");
		return -1;
	}

	/* Set DHM modulus and generator */
	if (mpi_read_string(&dhm.P, 16,
			POLARSSL_DHM_RFC2409_MODP_1024_P) != 0
		|| mpi_read_string(&dhm.G, 16,
			POLARSSL_DHM_RFC2409_MODP_1024_G) != 0) {
		fprintf(stderr, "ERROR: mpi_read_string\n");
		return -1;
	}

	dhm.len = mpi_size(&dhm.P);

	/* Setup the DH parameters & send to the client */
	if (dhm_make_public(&dhm, (int)mpi_size(&dhm.P), buf, (int)buflen,
				ctr_drbg_random, &ctr_drbg) != 0) {
		fprintf(stderr, "ERROR: dhm_make_public\n");
		return -1;
	}
	
	if (send(fd,buf,buflen, 0)==-1) {
		perror("key exchange send");
	}

	memset(buf, 0, buflen	);
  if(recv(fd, buf, 1023, 0) == -1)
		perror("key exchange recv");
		
	if (dhm_read_public(&dhm, buf, dhm.len) != 0) {
		fprintf(stderr, "ERROR: dhm_read_public\n");
		return -1;
	}
	
	memset(buf, 0, buflen);
	if (dhm_calc_secret(&dhm, buf,(size_t*) &buflen,
			ctr_drbg_random, &ctr_drbg) != 0) {
		fprintf(stderr, "ERROR: dhm_calc_secret\n");
		return -1;
	}

	/* Copy the required keylength */
	memcpy(key, buf, keylen);

	dhm_free(&dhm);
	ctr_drbg_free(&ctr_drbg);
	entropy_free(&entropy);
	return 0;
}
