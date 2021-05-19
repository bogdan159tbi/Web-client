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
#include "parson.h"
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
char *json_parse_to_string(char *username, char *password) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *serialized_string;
    serialized_string = json_serialize_to_string_pretty(root_value);
    puts(serialized_string);
    //tre sa le dau free neaparat
    /*
    json_free_serialized_string(serialized_string);
    json_value_free(root_value);
    */
   return serialized_string;
}
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

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000,1);
    char *string_from_json = json_parse_to_string(username, password);
    message = compute_post_request(IP_SERVER, REGISTER_URL, "application/json", string_from_json , NULL, 0);
    send_to_server(sockfd, message);
    
    puts("###start request###");
    puts(message);
    puts("###end of request###");
    
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

char *get_cookie_from_server_message(char *server_message){
    char *cookie;
    cookie = strstr(server_message, "Set-Cookie: ");
    cookie = cookie + strlen("Set-Cookie: ");
    cookie = strtok(cookie, ";");
    
    return cookie;
}
int login_user(char *username, char *password, char **cookie){
    printf("username=");
    memset(username, 0,USER_LEN);
    fgets(username, USER_LEN-1,stdin);
    username[strlen(username) - 1] = '\0';
    printf("password=");
    memset(password, 0, PASSWORD_LEN);
    fgets(password, PASSWORD_LEN- 1,stdin);
    password[strlen(password) - 1] = '\0';
    //finished reading user & pass
    
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000,1);
    char *string_from_json = json_parse_to_string(username, password);

    message = compute_post_request(IP_SERVER, LOGIN_URL, "application/json", string_from_json,NULL, 0);
    send_to_server(sockfd, message);

    puts("###start request###");
    puts(message);
    puts("###end of request###");
    //tre sa fac rost de cookie-ul de sesiune returnat de server

    message = receive_from_server(sockfd);
    *cookie = get_cookie_from_server_message(message);
    if(*cookie)
        printf("cookie este %s\n", *cookie);
    close_connection(sockfd);

    //free la message alocat cu calloc la linia 101 ??
    return 0;
}

/*
Cerere de acces in bibliotecă
• Ruta de acces: GET /api/v1/tema/library/access
• Trebuie sa demonstraţi că sunteţi autentificaţi => folosesc cookie de sesiune returnat la login
• Întoarce un token JWT, care demonstrează accesul la bibliotecă = pastrez jwt pentru mai tarziu,l trimit ca parametru
• Întoarce un mesaj de eroare dacă nu demonstraţi că sunteţi autentificaţi => daca return 0 -> totul e OK
*/
void get_token_from_response(char *server_message, char **token){
    *token = strstr(server_message, "{");
    *token = strtok(*token,":");
    *token = strtok(NULL,":");
    //iau din "token"} => token ,adica fara ghilimele si } de la sf
    //TODO inca nu am luat tokenul cum trebuie
    *token = *token ++;
    *token = strtok(NULL,"\"");
}
int enter_library(char *session_cookie, char **jwt_token){

    DIE(session_cookie == NULL, "session cookie = null");
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup
    message = compute_get_request(IP_SERVER, ACCESS_URL, NULL, cookies , 1);
    send_to_server(sockfd, message);

    puts("###start request###");
    puts(message);
    puts("###end of request###");
    //tre sa fac rost de cookie-ul de sesiune returnat de server

    message = receive_from_server(sockfd);
    printf("tokenul jwt este\n");
    char *token;
    get_token_from_response(message, &token); 
    DIE(!token ,"token e null\n");
    puts(token);

    return 0;
}
int main(int argc, char *argv[])
{
    char *message;
    char *response;
    int sockfd, result;
    char cmd[COMMAND_LEN];//stocheaza input terminal
    char username[USER_LEN];
    char password[PASSWORD_LEN];
    char *login_cookie = NULL, *jwt_token = NULL;
    
    while(1){
        memset(cmd, 0,COMMAND_LEN);
        fgets(cmd, COMMAND_LEN -1, stdin);
        //daca nu puneam strstr trebuia sa pun '\0' la sf
        if (strstr(cmd, "register")){
            result = register_user(username, password);
            DIE(result < 0, "register failed\n");
        } else if (strstr(cmd, "login")){
            result = login_user(username, password, &login_cookie);
            DIE(result < 0, "login failed\n");
        } else if (strstr(cmd,"enter_library")){
            result = enter_library(login_cookie, &jwt_token);
            DIE(result < 0, "entering the library failed\n");
        } else 
            break;
    }
    // free the allocated data at the end!
    
    return 0;
}
