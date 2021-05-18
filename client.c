#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

    //todo1: Înregistrarea unui cont
    /*
    Ruta de acces: POST /api/v1/tema/auth/register
    • Tip payload: application/json
    • Payload:
    {
    ”username”: String,
    ”password”: String
    }
    • Întoarce eroare dacă username-ul este deja folosit de către cineva
    */
int register_user( char *username, char *password) {
    //read data from terminal
    printf("username=");
    memset(username, 0,USER_LEN);
    fgets(username, USER_LEN-1,stdin);
    username[strlen(username) - 1] = '\0';
    printf("password=");
    memset(password, 0, PASSWORD_LEN);
    fgets(password, PASSWORD_LEN- 1,stdin);
    password[strlen(password) - 1] = '\0';
    //finished reading username & password
    //ma folosesc de parson ca sa creez body_data?
    char json[1000];
    strcpy(json,"{\"username\":\"1233\",\"password\":\"bla\"}");
    //printf("%s", json);
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000,1);
    message = compute_post_request(IP_SERVER, REGISTER_URL, "application/json",json,NULL, 0);
    send_to_server(sockfd, message);
    puts(message);
    message = receive_from_server(sockfd);
    puts(message);
    close_connection(sockfd);
    
    return 0;
}
/*
• Ruta de acces: POST /api/v1/tema/auth/login
• Tip payload: application/json
• Payload:
    {
    ”username”: String,
    ”password”: String
    }
• Întoarce cookie de sesiune
• Întoarce un mesaj de eroare dacă credenţialele nu se potrivesc
*/
int login_user(char *username, char *password){
    printf("username=");
    memset(username, 0,USER_LEN);
    fgets(username, USER_LEN-1,stdin);
    username[strlen(username) - 1] = '\0';
    printf("password=");
    memset(password, 0, PASSWORD_LEN);
    fgets(password, PASSWORD_LEN- 1,stdin);
    password[strlen(password) - 1] = '\0';
    //finished reading user & pass
    char json[1000];
    strcpy(json,"{\"username\":\"1233\",\"password\":\"bla\"}");
    //printf("%s", json);
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000,1);
    message = compute_post_request(IP_SERVER, LOGIN_URL, "application/json",json,NULL, 0);
    send_to_server(sockfd, message);
    puts(message);
    message = receive_from_server(sockfd);
    puts(message);
    close_connection(sockfd);

    return 0;
}
int main(int argc, char *argv[])
{
    char *message;
    char *response;
    int sockfd;
    char cmd[COMMAND_LEN];//stocheaza input terminal
    char username[USER_LEN];
    char password[PASSWORD_LEN];
    
    while(1){
        memset(cmd, 0,COMMAND_LEN);
        fgets(cmd, COMMAND_LEN -1, stdin);
        //daca nu puneam strstr trebuia sa pun '\0' la sf
        if (strstr(cmd, "register")){
            register_user(username, password);
        } else if (strstr(cmd, "login")){
            login_user(username, password);
        } else
            break;
            
    }
    // free the allocated data at the end!

    return 0;
}
