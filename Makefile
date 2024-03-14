all: client_ssl server_ssl
CC = clang
CFLAGS = 
LIBS = -L/opt/homebrew/Cellar/openssl@3/3.2.0_1/lib -lssl -lcrypto
INCLUDES = -I/opt/homebrew/Cellar/openssl@3/3.2.0_1/include

server_ssl: server_ssl.c
	$(CC) -o $@ $< $(INCLUDES) $(LIBS)
client_ssl: client_ssl.c
	$(CC) -o $@ $< $(INCLUDES) $(LIBS)

clean:
	rm -f server_ssl
	rm -f client_ssl
