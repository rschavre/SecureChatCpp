// g++ -std=c++14 my_main_code.cpp main_code_server.cpp main_code_client.cpp $(pkg-config --cflags --libs openssl) -o my_main_code

// g++ -std=c++14 my_main_code.cpp $(pkg-config --cflags --libs openssl) -o my_main_code

//  g++ -std=c++14 my_main_code.cpp -o my_main_code
// ./my_main_code -s
// ./my_main_code -c localhost

// https://wiki.openssl.org/index.php/Main_Page

//General includes:
#include <iostream>
#include <stdio.h>
#include <string>

#include "main_code_server.h"
#include "main_code_client.h"

int main(int argc, char *argv[])
{
    //Bob starts the app using “secure_chat_app -s”, 
    //and Alice starts the app using “secure_chat_app -c bob1”
    if(argc==2 && std::string(argv[1])=="-s"){
        //Server Mode
        //Without SSL
        _server();
    }
    else if(argc==3 && std::string(argv[1])=="-s" && std::string(argv[2])=="-ssl"){
        //Server Mode
        // with SSL
        _server("chat_START_SSL");
    }

    else if(argc==3 && std::string(argv[1])=="-c"){
        // Client Mode
        std::string hostname = argv[2]; 
        _client(hostname,8080);  // use std::stoi(port) //if port is string convert to int
    }
    else if(argc==4 && std::string(argv[1])=="-c" && std::string(argv[3])=="-ssl"){
        // Client Mode
        std::string hostname = argv[2]; 
        _client(hostname,8080,"chat_START_SSL");  // ssl=true use std::stoi(port) //if port is string convert to int
    }
    else{
        printf("usage: program -s\n\
        program -s -ssl\n\
        program -c hostname\n\
        program -c hostname -ssl\n");
        exit(1);
    }
    return 0;
}