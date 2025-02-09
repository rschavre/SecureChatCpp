#include <iostream>
#include <stdio.h>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <mutex>
#include <thread>
#include <future>
#include <chrono>
#include <termios.h>


//Network related includes:
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


SSL_CTX* ssl_initialise();

void _server(std::string ssl_header_string="chat_START_SSL_NOT_SUPPORTED");

SSL* ssl_connection(int client_sock , SSL_CTX* ctx);

int tcp_establish_server_socket(int port_number=8080);

int ssl_handle_client(int client_socket, SSL_CTX* ctx);
int handle_client(int client_socket);

