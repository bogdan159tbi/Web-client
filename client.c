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
    message = compute_post_request(IP_SERVER, REGISTER_URL, "application/json", string_from_json , NULL, 0, NULL);
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

    message = compute_post_request(IP_SERVER, LOGIN_URL, "application/json", string_from_json,NULL, 0 ,NULL);
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
    *token = strtok(*token,"}");
    //daca trebuie sa scoatem token-ul si dintre ghilimele
    *token = (*token) + 1;
    (*token)[strlen(*token) - 1] = '\0';
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
    message = compute_get_request(IP_SERVER, ACCESS_URL, NULL, cookies , 1, NULL);
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
    *jwt_token = token;
    return 0;
}

void read_info_book(char **info_book){
    memset(*info_book, 0, BOOK_INFO_LEN);
    fgets(*info_book, BOOK_INFO_LEN - 1, stdin);
    (*info_book)[strlen(*info_book) - 1] = '\0';
}

char *book_to_json(char *title, char *author, char *genre,
                    char *page_count, char *publisher){

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "title", title);
    json_object_set_string(root_object, "author", author);
    json_object_set_string(root_object, "genre", genre);
    json_object_set_string(root_object, "page_count", page_count);
    json_object_set_string(root_object, "publisher", publisher);
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
/*
    Adaugarea unei cărţi
    • Ruta de acces: POST /api/v1/tema/library/books
    • Tip payload: application/json
    • Trebuie să demonstraţi că aveţi acces la bibliotecă
    • Payload:
        {
        ”title”: String,
        ”author”: String,
        ”genre”: String,
        ”page_count”: Number
        ”publisher”: String
        }
    • Întoarce un mesaj de eroare dacă nu demonstraţi că aveţi acces la bibliotecă
    • Întoarce un mesaj de eroare dacă informaţiile introduse sunt incomplete sau nu respectă formatarea
*/
int add_book(char *session_cookie, char *auth_token, char **title, char **author,
            char **genre, char **page_count, char **publisher){
    
    printf("title=");
    read_info_book(title);

    printf("author=");
    read_info_book(author);

    printf("genre=");
    read_info_book(genre);

    printf("page_count=");
    read_info_book(page_count);

    printf("publisher=");
    read_info_book(publisher);

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000, 1);
    DIE(!message,"message null");

    char *string_from_json = book_to_json(*title, *author, *genre,
                                         *page_count, *publisher);

    DIE(!string_from_json, "json string e null\n");

    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup

    //add authorization header

    message = compute_post_request(IP_SERVER, BOOKS_URL, "application/json", string_from_json, cookies, 1, auth_token);
    send_to_server(sockfd, message);

    puts("###start request###");
    puts(message);
    puts("###end of request###");
    //tre sa fac rost de cookie-ul de sesiune returnat de server

    message = receive_from_server(sockfd);
    puts(message);

    return 0;
}
/*
    Vizualizarea informaţiilor sumare despre toate cărţile
    • Ruta de acces: GET /api/v1/tema/library/books
    • Trebuie sa demonstraţi că aveţi acces la bibliotecă
    • Întoarce o listă de obiecte json:
    [{
    id: Number,
    title: String
    }]
    • Întoarce un mesaj de eroare dacă nu demonstraţi că aveţi acces la bibliotecă
*/
int get_books(char *session_cookie, char *auth_token){
    DIE(session_cookie == NULL, "session cookie = null");
    DIE(auth_token == NULL, "auth token = null");

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup
    message = compute_get_request(IP_SERVER, BOOKS_URL, NULL, cookies , 1, auth_token);
    send_to_server(sockfd, message);

    puts("###start request###");
    puts(message);
    puts("###end of request###");
    //tre sa fac rost de cookie-ul de sesiune returnat de server

    message = receive_from_server(sockfd);
    if(message){
        message = strstr(message, "{");
        message[strlen(message) -1] = '\0'; // ca sa stergem ] de la sfarsit
        puts(message);
    } else
        printf("nu exista nicio carte\n");
    return 0;
}
/*
    Vizualizarea detaliilor despre o carte
    • Ruta de acces: GET /api/v1/tema/library/books/:bookId. În loc de :bookId este un id de carte efectiv
    (ex: /api/v1/tema/library/books/1)
    • Trebuie sa demonstraţi că aveţi acces la bibliotecă
    • Întoarce un obiect json:
    {
    ”id”: Number,
    ”title”: String,
    ”author”: String,
    ”publisher”: String,
    ”genre”: String,
    ”page_count”: Number
    }
    • Întoarce un mesaj de eroare dacă nu demonstraţi că aveţi acces la bibliotecă
    • Întoarce un mesaj de eroare dacă id-ul pentru care efectuaţi cererea este invalid
*/

int get_book(char *session_cookie , char *auth_token){
    printf("id=");
    char *id_book = calloc(BOOK_INFO_LEN, 1);
    DIE(!id_book,"id book null");
    read_info_book(&id_book);

    DIE(session_cookie == NULL, "session cookie = null");
    DIE(auth_token == NULL, "auth token = null");

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup
    char url_book[MAX_URL_LEN];
    strcpy(url_book, BOOKS_URL);
    strcat(url_book, "/");
    strcat(url_book, id_book);
    message = compute_get_request(IP_SERVER, url_book, NULL, cookies , 1, auth_token);
    send_to_server(sockfd, message);

    puts("###start request###");
    puts(message);
    puts("###end of request###");

    message = receive_from_server(sockfd);
    message = strstr(message, "[");
    message++;
    message[strlen(message)-1] = '\0';
    puts(message);//mesajul e sub forma {"title":titlu etc}

    return 0;
}
/*
    Ştergerea unei cărţi
    • Ruta de acces: DELETE /api/v1/tema/library/books/:bookId. În loc de :bookId este un id de carte
    efectiv (ex: /api/v1/tema/library/books/1)
    • Trebuie să demonstraţi că aveţi acces la bibliotecă
    • Întoarce un mesaj de eroare dacă nu demonstraţi că aveţi acces la bibliotecă
    • Întoarce un mesaj de eroare dacă id-ul pentru care efectuaţi cererea este invalid
*/
int delete_book(char *session_cookie , char *auth_token){
    printf("id=");
    char *id_book = calloc(BOOK_INFO_LEN, 1);
    DIE(!id_book,"id book null");
    read_info_book(&id_book);

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup?
    char url_book[MAX_URL_LEN];
    strcpy(url_book, BOOKS_URL);
    strcat(url_book, "/");
    strcat(url_book, id_book);
    message = compute_delete_request(IP_SERVER, url_book, "application/json", cookies, 1, auth_token);;
    send_to_server(sockfd, message);

    puts("###start request###");
    puts(message);
    puts("###end of request###");

    message = receive_from_server(sockfd);
    puts(message);

    return 0;
}
void alloc_info_book(char **title, char **author,
                    char **page_count, char **publisher, char **genre)
{
    *title =calloc(BOOK_INFO_LEN, 1);
    DIE(!(*title),"title e null");

    *author =calloc(BOOK_INFO_LEN, 1);
    DIE(!(*author),"title e null");
    
    *genre =calloc(BOOK_INFO_LEN, 1);
    DIE(!(*genre),"title e null");
    
    *page_count =calloc(BOOK_INFO_LEN, 1);
    DIE(!(*page_count),"title e null");

    *publisher =calloc(BOOK_INFO_LEN, 1);
    DIE(!(*publisher),"title e null");

}
void free_info_book(char **title, char **author,
                    char **page_count, char **publisher, char **genre){              
    free(*title);
    free(*author);
    free(*publisher);
    free(*genre);
    free(*page_count);
}
int logout(char *session_cookie, char *auth_token){
    //cookie devine invalid la delogare
    //daca decomentez, nu mai merge cookie -ul vechi
    //copiez dupa alt cookie(poate expira)
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    cookies[0] = session_cookie;//sa folosesc strdup?
    message = compute_get_request(IP_SERVER, LOGOUT_URL, NULL, cookies , 1, auth_token);
    send_to_server(sockfd, message);
    puts(message);

    message = receive_from_server(sockfd);
    puts(message);

    return 0;
}
int main(int argc, char *argv[])
{
    int result;
    char cmd[COMMAND_LEN];//stocheaza input terminal
    char username[USER_LEN];
    char password[PASSWORD_LEN];
    char *title, *author,
         *genre, *publisher;
    char *page_count;     
    char *login_cookie = NULL, *jwt_token = NULL;
    
    alloc_info_book(&title, &author, &page_count, 
                    &publisher, &genre);

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
        } else  if(strstr(cmd, "add_book")){
            result = add_book(login_cookie, jwt_token, &title, &author,
                             &genre, &page_count, &publisher);
            DIE( result < 0,"adding a book failed\n");
        } else if (strstr(cmd, "get_books")) {
            result = get_books(login_cookie, jwt_token);
            DIE(result < 0, "getting books failed");
        } else if (strstr(cmd, "get_book")){
            result = get_book(login_cookie ,jwt_token);
            DIE(result < 0, "getting a book failed");
        } else if (strstr(cmd, "delete_book")){
            result = delete_book(login_cookie ,jwt_token);
            DIE(result < 0, "deleting a book failed");
        } else if (strstr(cmd,"logout")){
            result = logout(login_cookie ,jwt_token);
            DIE(result < 0, "logging out failed");
        } else 
            break;
    }
    // free the allocated data at the end!
    free_info_book(&title, &author, &page_count, &
                    publisher, &genre);

    return 0;
}
