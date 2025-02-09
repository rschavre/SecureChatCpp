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
#include <algorithm>

//Network related includes:
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


SSL* ssl_connection_client(int client_sock , SSL_CTX* ctx);
int tcp_establish_client_socket(struct hostent* he , int port_number);
void _client(const std::string& hostname ,int port ,std::string use_ssl = "chat_START_SSL_NOT_SUPPORTED");
int ssl_handle_server_fromclient(int client_sock , SSL_CTX* ctx);
int handle_server_fromclient(int client_socket);
