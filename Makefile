default:
	gcc -o client -g client.c -lmcrypt
	gcc -o server -g server.c -lmcrypt
clean:
	rm -rf client server client_server.tar.gz client.dSYM server.dSYM
dist:
	tar -czf client_server.tar.gz client.c server.c Makefile README