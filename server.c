//NAME: Tim Nguyen
//EMAIL: timothynguyen314@gmail.com
//ID: 604380809

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>		//getopt_long, optarg, isatty, pipe, fork, dup2
#include <getopt.h>		//getopt_long, optarg
#include <termios.h>	//tcgetattr
#include <poll.h>		//pollfd, poll
#include <signal.h>		//kill

#include <sys/types.h>	//socket, listen
#include <sys/socket.h>	//socket, listen
#include <netdb.h>		//gethostbyname

#include <string.h>		//memset, memcpy
#include <netinet/in.h>	//htons

#include <mcrypt.h>     //mcrypt


//Error messages
void err(char* err_fun, char* err_msg){
	fprintf(stderr, "%s: %s\n", err_fun, err_msg);
	exit(1);
}

//Encrypt variables
int encrypt_b = 0;
char* mykey;
char* IVE;
char* IVD;
int keylen;
MCRYPT encrypt_fd, decrypt_fd;

//Pipe variables
int pipe1[2];
int pipe2[2];

//Port variable
int portno = -9999;

//Socket variables
int sockfd, newsockfd;
struct sockaddr_in serv_addr, cli_addr;
struct hostent *server;
int clilen;

//Process variable
pid_t pid;

void sig_handler(){
    //Close crypt file descriptors
    if(encrypt_b){
        if(mcrypt_generic_deinit(encrypt_fd) < 0)
            err("mcrypt_generic_deinit", "System call failure");
        if(mcrypt_module_close(encrypt_fd) < 0)
            err("mcrypt_module_close", "System call failure");
        
        if(mcrypt_generic_deinit(decrypt_fd) < 0)
            err("mcrypt_generic_deinit", "System call failure");
        if(mcrypt_module_close(decrypt_fd) < 0)
            err("mcrypt_module_close", "System call failure");
    }
}

void init(){
    //Initialize mcrypt file descriptors
    if(encrypt_b){
        if((encrypt_fd = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED)
            err("mcrypt_module_open", "System call failure");
        IVE = malloc(sizeof(char) * mcrypt_enc_get_iv_size(encrypt_fd));
        int e;
        for(e = 0; e < mcrypt_enc_get_iv_size(encrypt_fd); e++)
            IVE[e] = 'T';
        if(mcrypt_generic_init(encrypt_fd, mykey, keylen, IVE) < 0)
            err("mcrypt_generic_init", "System call failure");

        if((decrypt_fd = mcrypt_module_open("twofish", NULL, "cfb", NULL)) == MCRYPT_FAILED)
            err("mcrypt_module_open", "System call failure");
        IVD = malloc(sizeof(char) * mcrypt_enc_get_iv_size(decrypt_fd));
        int d;
        for(d = 0; d < mcrypt_enc_get_iv_size(decrypt_fd); d++)
            IVD[d] = 'T';
        if(mcrypt_generic_init(decrypt_fd, mykey, keylen, IVD) < 0)
            err("mcrypt_generic_init", "System call failure");
    }

	//Initialize socket
   	sockfd = socket(AF_INET, SOCK_STREAM, 0);
   	if(sockfd == -1)
   		err("socket", "System call failure");
   	server = gethostbyname("localhost");
    if(server == NULL)
    	err("gethostbyname", "System call failure");

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    serv_addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sockfd,(struct sockaddr*) &serv_addr,sizeof(serv_addr)) == -1)
    	err("bind", "System call failure");
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, (socklen_t *) &clilen);
    if(newsockfd == -1)
    	err("accept", "System call failure");
    if(dup2(newsockfd,0) == -1 || dup2(newsockfd,1) == -1 || dup2(newsockfd,2) == -1)
    	err("dup2", "System call failure");
    if(close(newsockfd))
    	err("close", "System call failure");
}

void communication(int read_file, int write_file, int close_file, int serv_to_client){
	int SIZE = 1024;
    char buf[SIZE];
    int byte = read(read_file, buf, SIZE);
    if(byte == -1)
    	err("read", "System call failure");

    if(encrypt_b && !serv_to_client)
        if(mdecrypt_generic(decrypt_fd, buf, byte) != 0)
            err("mcdecrypt_generic", "System call failure");
    
	int i;
    for(i = 0; i < byte; i++){
        //Control-C
        if(buf[i] == 3)
            kill(pid, SIGINT);

        //Control-D
        if(buf[i] == 4){
            if(close(close_file) == -1)
            	err("close", "System call failure");
            break;
        }

        if(encrypt_b && serv_to_client)
            if(mcrypt_generic(encrypt_fd, buf+i, 1) != 0)
                 err("mcrypt_generic", "System call failure");

        if(write(write_file, buf+i, 1) == -1)
            err("write", "System call failure");
    }
}

void poll_for_events(){
	//Set up Pipe
	if(pipe(pipe1) == -1 || pipe(pipe2) == -1)
		err("pipe", "System call failure");

	//Set up Poll
    struct pollfd pfd[2];
    pfd[0].fd = STDIN_FILENO;	//input from socket
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;
    
    pfd[1].fd = pipe2[0];		//input from shell
    pfd[1].events = POLLIN;
    pfd[1].revents = 0;

    pid = fork();
    if(pid == -1)
    	err("fork", "System call failure");

    //Child Process
    if(pid == 0){
    	//Reads from pipe1[0]
        //Writes to pipe2[1]
        if(close(pipe1[1]) == -1 || close(pipe2[0]) == -1)
        	err("close", "System call failure");
        if(dup2(pipe1[0],0) == -1 || dup2(pipe2[1],1) == -1 || dup2(pipe2[1],2) == -1)
        	err("dup2", "System call failure");
        if(close(pipe1[0]) == -1 || close(pipe2[1]) == -1)
        	err("close", "System call failure");

        char* command[] = {"/bin/bash", NULL};
        execvp(command[0], command);
        err("execvp", "System call failure");
    }
    //Parent Process
    else{
    	//Writes to pipe1[1]
        //Reads from pipe2[0]
        if(close(pipe1[0]) == -1 || close(pipe2[1]) == -1)
        	err("close", "System call failure");

        //Poll For Events
	    while(1){
	    	if(poll(pfd, 2, 0) == -1)
	    		err("poll", "System call failure");

	    	if(pfd[0].revents & POLLIN)
	            communication(STDIN_FILENO, pipe1[1], pipe1[1], 0);
	        if(pfd[1].revents & POLLIN)
	            communication(pipe2[0], STDOUT_FILENO, pipe2[0], 1);
	        
	        if(pfd[0].revents & (POLLERR | POLLHUP))
	            break;
	        if(pfd[1].revents & (POLLERR | POLLHUP))
	            break;
	    }

	    int status;
	    if(waitpid(pid, &status, 0) == -1)
	        err("waitpid", "System call failure");
	    fprintf(stderr, "SHELL EXIT SIGNAL=%d STATUS=%d", WTERMSIG(status), WEXITSTATUS(status));
    }
}

int main(int argc, char* argv[]){
	//Parse arguments
    struct option options[] = {
        {"port", 1, NULL, 0},
        {"encrypt", 0, NULL, 1}
    };
    int test_options;
    while((test_options = getopt_long(argc, argv, "", options, NULL)) != -1){
    	if(test_options == 0)
            portno = atoi(optarg);
        else
        if(test_options == 1){
            encrypt_b = 1;
            struct stat key_stat;
            int key_fd = open("my.key", O_RDONLY);
            if(fstat(key_fd, &key_stat) == -1)
                err("fstat", "System call failure");
            keylen = key_stat.st_size;
            mykey = malloc(sizeof(char) * keylen);
            if(read(key_fd, mykey, keylen) == -1)
                err("read", "System call failure");
        }
        else
        	err("getopt_long", "Unrecognized argument");
    }
    if(portno == -9999)
    	err("getopt_long", "Missing port argument");

    signal(SIGINT, sig_handler);
	signal(SIGPIPE, sig_handler);

    init();
    poll_for_events();

    //Close crypt file descriptors
    if(encrypt_b){
        if(mcrypt_generic_deinit(encrypt_fd) < 0)
            err("mcrypt_generic_deinit", "System call failure");
        if(mcrypt_module_close(encrypt_fd) < 0)
            err("mcrypt_module_close", "System call failure");
        
        if(mcrypt_generic_deinit(decrypt_fd) < 0)
            err("mcrypt_generic_deinit", "System call failure");
        if(mcrypt_module_close(decrypt_fd) < 0)
            err("mcrypt_module_close", "System call failure");
    }

    exit(0);
}