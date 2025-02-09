#include "main_code_server.h"

static void clear_input() {
    // Get the file descriptor for the terminal input
    int fd = fileno(stdin);

    // Create a termios structure to modify the terminal settings
    struct termios t;
    tcgetattr(fd, &t);

    // Flush the input buffer
    tcflush(fd, TCIFLUSH);

    // Set the modified terminal settings
    tcsetattr(fd, TCSANOW, &t);
}

static char* getAnswer(char* buffer)
{    
    fgets(buffer, 1024, stdin);
    return buffer;
}

static void remove_Null_char(std::string* mystr){
    size_t pos = (*mystr).find('\0');
    // Keep erasing null characters until none are found
    while (pos != std::string::npos) {
        (*mystr).erase(pos, 1);
        pos = (*mystr).find('\0');
    }
}

SSL_CTX* ssl_initialise(){
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings(); 
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    // SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
        // exit(EXIT_FAILURE);
    }


    if (SSL_CTX_set_default_verify_paths(ctx) != 1){
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Load server certificate and private key */
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
    // if (SSL_CTX_use_certificate_file(ctx, "bob.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
        // exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
    // if (SSL_CTX_use_PrivateKey_file(ctx, "bob_private_key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return NULL;
        // exit(EXIT_FAILURE);
    }


    // Require client authentication
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    // Load trusted CA certificates
    if(SSL_CTX_load_verify_locations(ctx, "client.crt", NULL) != 1){
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    return ctx;
}

// server functions
void _server(std::string ssl_header_string){
    bool use_ssl=false;
    /*SSL INITIALISE*/
    SSL_CTX* ctx = ssl_initialise();
    /*END of SSL INITIALISE*/

    int _server_socket = tcp_establish_server_socket(); //tcp socket
    if(_server_socket <0){
        std::cerr << "Error socket failure. "<< std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout<<"The Server is Listening..."<<std::endl;
    // accepting tcp connections 
    /*while (true) */{
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(_server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            std::cerr << "Failed to accept connection" << std::endl;
            // continue;
        }

        printf("NEW Connection............\n");
        
        std::string init_buffer(1024,0);
        init_buffer.reserve(1024); 
        recv(client_sock, (void*)init_buffer.c_str(), init_buffer.capacity(), 0); // Received : CLIENT_HELLO
        // remove_Null_char(&init_buffer);

        init_buffer="chat_ok_reply";      
        send(client_sock, init_buffer.c_str(), strlen(init_buffer.c_str()), 0);

        init_buffer="";
        recv(client_sock, (void*)init_buffer.c_str(), init_buffer.capacity(), 0); //receive the chat_START_SSL msg
        if(strcmp(init_buffer.c_str(),"chat_START_SSL")==0 && ssl_header_string=="chat_START_SSL"){
            use_ssl=true;
        }
        else{ // receive the chat_START_SSL_NOT_SUPPORTED
            use_ssl=false;
        }

        sleep(1);
        if(use_ssl){
            /*SSL Chat*/
            // Handle the ssl client
            init_buffer="chat_START_SSL_ACK";
            send(client_sock, init_buffer.c_str(), strlen(init_buffer.c_str()), 0);
            std::cout<<"STARTING SSL CHAT................\n";
            
            ssl_handle_client(client_sock , ctx );
        }
        else{
            /*No SSL Chat*/ // handle normal without ssl
            init_buffer="chat_START_SSL_NOT_SUPPORTED";
            send(client_sock, init_buffer.c_str(), strlen(init_buffer.c_str()), 0);
            std::cout<<"Normal CHAT................\n";
            handle_client(client_sock);
        }

        close(client_sock);
        sleep(1);
    }

    close(_server_socket);
    SSL_CTX_free(ctx);

}

SSL* ssl_connection(int client_sock , SSL_CTX* ctx){ // ssl handshake
    // Create SSL connection
    SSL* ssl = SSL_new(ctx);

    // BIO* client_bio = BIO_new_socket(client_sock, BIO_NOCLOSE);
    // SSL_set_bio(ssl, client_bio, client_bio);
    SSL_set_fd(ssl, client_sock);

    // Perform SSL handshake
    if (SSL_accept(ssl) != 1) {
        fprintf(stderr, "SSL handshake error\n");
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }
    
    // Verify client certificate
    X509* client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert == NULL) {
        fprintf(stderr, "No client certificate\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Client certificate verification error\n");
        X509_free(client_cert);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }

    // Print client certificate information
    char* subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(client_cert), NULL, 0);
    printf("Client certificate subject: %s\n", subject);
    printf("Client certificate issuer: %s\n", issuer);
    OPENSSL_free(subject);
    OPENSSL_free(issuer);

    X509_free(client_cert);
    
    return ssl;
}


int tcp_establish_server_socket(int port_number){
//socket
    int _server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (_server_socket < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return -1;
    }
            // // Set socket options to allow reuse of address and port
            // int optval = 1;
            // setsockopt(_server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
            // setsockopt(_server_socket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    // Set up server address structure
    struct sockaddr_in servaddr;
    std::memset(&servaddr, 0, sizeof(servaddr)); // clear values
    servaddr.sin_family = AF_INET; //TCP Socket
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port_number);

//bind
    if (bind(_server_socket, reinterpret_cast<struct sockaddr*>(&servaddr), sizeof(servaddr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        close(_server_socket);
        return -1;
    }

//listen
    if (listen(_server_socket, 10) < 0) { // 10 connections can be queued
        std::cerr << "Failed to listen on socket" << std::endl;
        close(_server_socket);
        return -1;
    }
    return _server_socket;
}


int ssl_handle_client(int client_socket, SSL_CTX* ctx){ //using ssl to handle client connection
    // Create SSL connection and Perform SSL Handshake
    SSL* ssl = ssl_connection(client_socket,ctx);
    if(ssl == NULL ){
        std::cerr << "Error ssl failure. "<< std::endl;
        return -1;
    }
    int ret = SSL_do_handshake(ssl);
    if(ret==1){

        SSL_write(ssl,  "OK_FROM_SERVER", strlen("OK_FROM_SERVER"));
        
        while (1) {
            fd_set readfds, writefds;
            FD_ZERO(&readfds);
            FD_ZERO(&writefds);
            FD_SET(client_socket, &readfds);
            FD_SET(client_socket, &writefds);
            FD_SET(fileno(stdin), &readfds);
            FD_SET(fileno(stdout), &writefds);

            select(client_socket+1, &readfds, &writefds, NULL, NULL);

            if (FD_ISSET(client_socket, &readfds)) { //Client Socket is available for read //recv
                std::string buffer(1024,0);
                buffer.reserve(1024); 
                int n = SSL_read(ssl, (void*)buffer.c_str(), buffer.capacity());
                if (n < 0) {
                    printf("Connection closed\n");
                    break;
                }
                //Once i recv on socket clear my recent input and print the message from the socket
                clear_input();
                
                if(n!=0){
                    remove_Null_char(&buffer);
                    if(strcmp(buffer.c_str(),"quit\n")==0){
                        printf("QUIT MSG FROM CLIENT\n");
                        break;
                    }
                    char cmsg[] = "\rClient says:";
                    fwrite(cmsg, 1, strlen(cmsg), stdout);
                    fwrite(buffer.c_str(), 1, strlen(buffer.c_str()), stdout);
                }
            }

            if (FD_ISSET(fileno(stdin), &readfds)) {
                char buffer[1024];
    
                std::chrono::seconds timeout(5);

                std::future<char*> future = std::async(std::launch::async,getAnswer,buffer);
                if (future.wait_for(timeout) == std::future_status::ready){
                    char* result = future.get();
                    SSL_write(ssl,  buffer, strlen(buffer));
                    // remove_Null_char(&buffer);
                    if(strcmp(buffer,"quit\n")==0){
                        clear_input();
                        break;
                    }
                }
                clear_input();

            }

            if (FD_ISSET(fileno(stdout), &writefds)) {
                // Standard output is ready for writing
            }

            if (FD_ISSET(client_socket, &writefds)) {
                // Socket is ready for writing
            }
        }

    }
    
    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);

    return 1;
}

int handle_client(int client_socket){ //using send and recv to handle client connection
    int status = fcntl(client_socket, F_SETFL, fcntl(client_socket, F_GETFL, 0) | O_NONBLOCK);
    if (status == -1){
        perror("calling fcntl");
        return -1;
    }
    // handle

    while (1) {
        fd_set readfds, writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(client_socket, &readfds);
        FD_SET(client_socket, &writefds);
        FD_SET(fileno(stdin), &readfds);
        FD_SET(fileno(stdout), &writefds);

        select(client_socket+1, &readfds, &writefds, NULL, NULL);

        if (FD_ISSET(client_socket, &readfds)) { //Client Socket is available for read //recv
            std::string buffer(1024,0);
            buffer.reserve(1024); 
            int n =recv(client_socket, (void*)buffer.c_str(), buffer.capacity(), 0); // Received : CLIENT_HELLO
            if (n < 0) {
                printf("Connection closed\n");
                break;
            }
            //Once i recv on socket clear my recent input and print the message from the socket
            clear_input();
            
            if(n!=0){
                remove_Null_char(&buffer);
                if(strcmp(buffer.c_str(),"quit\n")==0){
                    printf("QUIT MSG FROM CLIENT\n");
                    break;
                }
                char cmsg[] = "\rClient says:";
                fwrite(cmsg, 1, strlen(cmsg), stdout);
                fwrite(buffer.c_str(), 1, strlen(buffer.c_str()), stdout);

            }
        }

        if (FD_ISSET(fileno(stdin), &readfds)) {
            char buffer[1024];

            std::chrono::seconds timeout(5);

            std::future<char*> future = std::async(std::launch::async,getAnswer,buffer);
            if (future.wait_for(timeout) == std::future_status::ready){
                char* result = future.get();
                send(client_socket, buffer, strlen(buffer), 0);
                if(strcmp(buffer,"quit\n")==0){
                    clear_input();
                    break;
                }
            }
            clear_input();
            // fgets(buffer, sizeof(buffer), stdin);
        }

        if (FD_ISSET(fileno(stdout), &writefds)) {
            // Standard output is ready for writing
        }

        if (FD_ISSET(client_socket, &writefds)) {
            // Socket is ready for writing
        }
    }
    return 1;
}