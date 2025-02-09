#include "main_code_client.h"

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

static std::string getAnswer(std::string& buffer)
{    
    fgets( (char*)(buffer).c_str(), 1024, stdin);
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

SSL_CTX* ssl_initialise_client(){
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings(); 
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    // SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
        // exit(EXIT_FAILURE);
    }

    /* Load client certificate and private key */
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0) {
    // if (SSL_CTX_use_certificate_file(ctx, "alice.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
        // exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0 ) {
    // if (SSL_CTX_use_PrivateKey_file(ctx, "alice_private_key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return NULL;
        // exit(EXIT_FAILURE);
    }


    // // Require client authentication
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // // Load trusted CA certificates
    SSL_CTX_load_verify_locations(ctx, "server.crt", NULL); // remove comment
    // SSL_CTX_load_verify_locations(ctx, "int.crt", NULL); // remove comment

    return ctx;
}

SSL* ssl_connection_client(int client_sock , SSL_CTX* ctx){ // ssl handshake
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings(); 
    // Create SSL connection
    SSL* ssl = SSL_new(ctx);
    // BIO* server_bio = BIO_new_socket(client_sock, BIO_NOCLOSE);
    // SSL_set_bio(ssl, server_bio, server_bio);
    SSL_set_fd(ssl, client_sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL handshake error\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }

    // Verify server certificate
    X509* server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert == NULL) {
        fprintf(stderr, "No server certificate\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Server certificate verification error\n");
        X509_free(server_cert);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }

    // Print server certificate information
    char* subject = X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), NULL, 0);
    printf("Server certificate subject: %s\n", subject);
    printf("Server certificate issuer: %s\n", issuer);
    OPENSSL_free(subject);
    OPENSSL_free(issuer);

    X509_free(server_cert);
    return ssl;
}


int tcp_establish_client_socket(struct hostent* he , int port_number){
    
    int _client_socket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port_number);
    // server_address.sin_port = htons(std::stoi(port)); //if port is string
    server_address.sin_addr = *((struct in_addr*)he->h_addr);

    if (connect(_client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        return -1;
    }

    return _client_socket; 
}
// client functions
void _client(const std::string& hostname ,int port , std::string ssl_header_string){
    bool use_ssl=true;
    struct hostent* he;

    if ((he = gethostbyname(hostname.c_str())) == NULL) {  // get the host info
        std::cerr << "gethostbyname error" << std::endl;
        return;
    }
    

    // TCP Handshake
    int _client_socket = tcp_establish_client_socket(he,port);
    if(_client_socket<0){
        return;
    }

    std::string init_buffer(1024,0);
    init_buffer.reserve(1024); 

    init_buffer = "chat_hello";
    send(_client_socket, init_buffer.c_str(), strlen(init_buffer.c_str()), 0); //sent CLIENT_HELLO 

    init_buffer="";
    recv(_client_socket, (void*)init_buffer.c_str(), init_buffer.capacity(), 0); // SERVER_HELLO

    // init_buffer = "chat_START_SSL";
    init_buffer = ssl_header_string;
    send(_client_socket, init_buffer.c_str(), strlen(init_buffer.c_str()), 0);

    init_buffer="";
    recv(_client_socket, (void*)init_buffer.c_str(), init_buffer.capacity(), 0);
    if(strcmp(init_buffer.c_str(),"chat_START_SSL_ACK")==0){
        std::cout<<"STARTING SSL CHAT................\n";
        use_ssl=true;
    }
    else{
        std::cout<<"Normal CHAT................\n";
        use_ssl=false;
    }
    sleep(1);

    if(use_ssl){
        /*SSL INITIALISE*/
        SSL_CTX* ctx = ssl_initialise_client();
        /*END of SSL INITIALISE*/
        ssl_handle_server_fromclient(_client_socket , ctx); // Handle chat using SSL
        SSL_CTX_free(ctx);
    }
    else{
        handle_server_fromclient(_client_socket); //Normal Handle without SSL
    }

    close(_client_socket);
}

int ssl_handle_server_fromclient(int client_sock , SSL_CTX* ctx){
    // Create SSL connection and Perform SSL Handshake
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings(); 
    SSL* ssl = ssl_connection_client(client_sock,ctx);
    if(ssl == NULL ){
        std::cerr << "Error ssl failure. "<< std::endl;
        return -1;
    }
    int ret = SSL_do_handshake(ssl);
    if(ret==1){

        char tempbuffer[1024];
        int n = SSL_read(ssl, tempbuffer, sizeof(tempbuffer));
        
        while (1) {
            fd_set readfds, writefds;
            FD_ZERO(&readfds);
            FD_ZERO(&writefds);
            FD_SET(client_sock, &readfds);
            FD_SET(client_sock, &writefds);
            FD_SET(fileno(stdin), &readfds);
            FD_SET(fileno(stdout), &writefds);

            select(client_sock+1, &readfds, &writefds, NULL, NULL);

            if (FD_ISSET(client_sock, &readfds)) { //Client Socket is available for read //recv
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
                        printf("QUIT MSG FROM SERVER\n");
                        break;
                    }
                    char cmsg[] = "\rServer says:";
                    fwrite(cmsg, 1, strlen(cmsg), stdout);
                    fwrite(buffer.c_str(), 1, strlen(buffer.c_str()), stdout);
                }
            }

            if (FD_ISSET(fileno(stdin), &readfds)) {
                std::string buffer(1024,0);
                buffer.reserve(1024); 
                
                std::chrono::seconds timeout(5);
                std::future<std::string> future = std::async(std::launch::async,getAnswer,std::ref(buffer));
                if (future.wait_for(timeout) == std::future_status::ready){
                    std::string result = future.get();
                    SSL_write(ssl,  buffer.c_str(), strlen(buffer.c_str()));
                    remove_Null_char(&buffer);
                    if(strcmp(buffer.c_str(),"quit\n")==0){
                        clear_input();
                        break;
                    }

                }
                clear_input();

            }

            if (FD_ISSET(fileno(stdout), &writefds)) {
                // Standard output is ready for writing
            }

            if (FD_ISSET(client_sock, &writefds)) {
                // Socket is ready for writing
            }
        }
        
    }

    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return 0;
}

int handle_server_fromclient(int client_socket){
    int status = fcntl(client_socket, F_SETFL, fcntl(client_socket, F_GETFL, 0) | O_NONBLOCK);
    if (status == -1){
        perror("calling fcntl");
    // handle the error.  By the way, I've never seen fcntl fail in this way
        return -1;
    }
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
                    printf("QUIT MSG FROM SERVER\n");
                    break;
                }
                char cmsg[] = "\rServer says:";
                fwrite(cmsg, 1, strlen(cmsg), stdout);
                fwrite(buffer.c_str(), 1, strlen(buffer.c_str()), stdout);
            }
        }

        if (FD_ISSET(fileno(stdin), &readfds)) {
            std::string buffer(1024,0);
            buffer.reserve(1024); 
            std::chrono::seconds timeout(5);

            std::future<std::string> future = std::async(std::launch::async,getAnswer,std::ref(buffer));
            if (future.wait_for(timeout) == std::future_status::ready){
                std::string result = future.get();
                send(client_socket, buffer.c_str(), strlen(buffer.c_str()), 0);
                if(strcmp(buffer.c_str(),"quit\n")==0){
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
    return 1;
}
