#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>		//getopt_long, optarg, isatty, pipe, fork, dup2
#include <getopt.h>		//getopt_long, optarg
#include <termios.h>	//tcgetattr
#include <poll.h>		//pollfd, poll

#include <sys/types.h>	//creat
#include <sys/stat.h>	//creat
#include <fcntl.h>		//creat

#include <sys/types.h>	//socket
#include <sys/socket.h>	//socket
#include <netdb.h>		//gethostbyname

#include <string.h>		//memset, memcpy
#include <signal.h>		//kill
#include <netinet/in.h>	//htons

#include <mcrypt.h>      //mcrypt

//Terminal Settings
static int td = STDIN_FILENO;
static struct termios terminal_o;
static struct termios terminal_s;
int t = 0;

//Error messages
void err(char* err_fun, char* err_msg){
	fprintf(stderr, "%s: %s\n", err_fun, err_msg);
	if(t)
		tcsetattr(td, TCSANOW, &terminal_o);
	exit(1);
}

//Port variable
int portno = -9999;

//Log variables
int log_b = 0;
int log_fd;
char* log_file;

//Encrypt variables
int encrypt_b = 0;
char* mykey;
int keylen;
char* IVE;
char* IVD;
MCRYPT encrypt_fd, decrypt_fd;

//Socket variables
int sockfd;
struct sockaddr_in serv_addr;
struct hostent *server;

void init(){
	t = 1;

	//Get current terminal settings
    if(tcgetattr(td, &terminal_o) == -1)
    	err("tcgetattr", "System call failure");
    if(tcgetattr(td, &terminal_s) == -1)
    	err("tcgetattr", "System call failure");

    //Change flags
    terminal_s.c_iflag = ISTRIP;
    terminal_s.c_oflag = 0;
    terminal_s.c_lflag = 0;

    //Change terminal settings
    if(tcsetattr(td, TCSANOW, &terminal_s) == -1)
    	err("tcsetattr", "System call failure");

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

    if (connect(sockfd,(struct sockaddr*) &serv_addr,sizeof(serv_addr)) == -1)
    	err("connect", "System call failure");
}

void communication(int read_file, int write_file, int client_to_serv){
	//Reading from input
	int SIZE = 1024;
    char buf[SIZE];
    int byte = read(read_file, buf, SIZE);
    if(byte == -1)
    	err("read", "System call failure");

    //Writing to Log File
    if (log_b){
    	char* log_str[3];

    	if(client_to_serv){
    		log_str[0] = "SENT ";
	        if(write(log_fd, log_str[0], 5) == -1)
	        	err("write", "System call failure");
    	}else{
    		log_str[0] = "RECEIVED ";
	        if(write(log_fd, log_str[0], 9) == -1)
	        	err("write", "System call failure");
    	}

        log_str[1] = malloc(sizeof(char)*10);
        sprintf(log_str[1], "%d", byte);
        if(write(log_fd, log_str[1], strlen(log_str[1])) == -1)
        	err("write", "System call failure");

        log_str[2] = " bytes: ";
        if(write(log_fd, log_str[2], 8) == -1)
        	err("write", "System call failure");

        if(compress_b && client_to_serv){
        	if(write(log_fd, buf_c, strlen(buf_c)) == -1)
        		err("write", "System call failure");
        }else
        if(write(log_fd, buf, byte) == -1)
    	    err("write", "System call failure");

        if(write(log_fd, "\n", 1) == -1)
        	err("write", "System call failure");
    }

    if(encrypt_b && !client_to_serv)
        if(mdecrypt_generic(decrypt_fd, buf, byte) != 0)
            err("mcdecrypt_generic", "System call failure");

	int i;
    for(i = 0; i < byte; i++){
    	//Writing to display
    	if(client_to_serv){
    		if(buf[i] != 10 && buf[i] != 13){
    			if(write(STDOUT_FILENO, buf+i,1) == -1)
    				err("write", "System call failure");
                if(encrypt_b)
                    if(mcrypt_generic(encrypt_fd, buf+i, 1) != 0)
                        err("mcrypt_generic", "System call failure");
            }
    	}
    	//Carriage return or line feed
    	if(buf[i] == 10 || buf[i] == 13){
    		char nl[2] = {13, 10};
            if(write(STDOUT_FILENO, nl, 2) == -1)
            	err("write", "System call failure");
            if(client_to_serv){
            	buf[i] = 10;
                if(encrypt_b)
                    if(mcrypt_generic(encrypt_fd, buf+i, 1) != 0)
                        err("mcrypt_generic", "System call failure");
            	if(write(write_file, buf+i, 1) == -1)
            		err("write", "System call failure");
            }
    	}else
    	//Write to output
    	if(write(write_file, buf+i, 1) == -1)
			err("write", "System call failure");
    }
}

void poll_for_events(){
	//Set up poll
    struct pollfd pfd[2];
    pfd[0].fd = STDIN_FILENO; 	//input from keyboard
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;
    
    pfd[1].fd = sockfd; 		//input from socket
    pfd[1].events = POLLIN;
    pfd[1].revents = 0;

    //Poll for events
    while(1){
    	if(poll(pfd, 2, 0) == -1)
    		err("poll", "System call failure");

    	if(pfd[0].revents & POLLIN)
            communication(STDIN_FILENO, sockfd, 1);
        if(pfd[1].revents & POLLIN)
            communication(sockfd, STDOUT_FILENO, 0);
        
        if(pfd[0].revents & (POLLERR | POLLHUP))
            break;
        if(pfd[1].revents & (POLLERR | POLLHUP))
            break;
    }
}

int main(int argc, char* argv[]){
	//Parse arguments
    struct option options[] = {
        {"port", 1, NULL, 0},
        {"log", 1, NULL, 1},
        {"encrypt", 0, NULL, 2}
    };
    int test_options;
    while((test_options = getopt_long(argc, argv, "", options, NULL)) != -1){
    	if(test_options == 0)
            portno = atoi(optarg);
        else
        if(test_options == 1){
            log_b = 1;
            log_file = optarg;
            log_fd = creat(log_file, S_IRWXU);
            if(log_fd == -1)
            	err("creat", "System call failure");
        } else
        if(test_options == 2){
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

    init();
    poll_for_events();

    //Restore terminal settings
    if(tcsetattr(td, TCSANOW, &terminal_o) == -1)
    	err("tcsetattr", "System call failure");

    //Close mcrypt file descriptors
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



