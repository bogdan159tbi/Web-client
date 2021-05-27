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

struct book_t{
    char *title;
    char *author;
    char *publisher;
    char *genre;
    int page_count;
};
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
    //puts(serialized_string);
    //tre sa le dau free neaparat
    /*
    json_free_serialized_string(serialized_string);
    json_value_free(root_value);
    */
   return serialized_string;
}
int read_input_stdin(char **input){
    memset(*input, 0,INPUT_LEN);
    fgets(*input, INPUT_LEN-1,stdin);
    (*input)[strlen(*input) - 1] = '\0';

    return 0;
}
/**
 * 1 daca s a inregistrat un nou user
 * 0 daca username e deja luat si afisez mesajul de eroare primit de la server
 **/
int check_username_taken(char *message){
    JSON_Value *root_value = json_value_init_object();
    root_value = json_parse_string(strchr(message,'{'));

    JSON_Object *root_object = json_value_get_object(root_value);
    if(json_object_get_string(root_object, "error")){
        printf("error: %s\n",json_object_get_string(root_object, "error"));
        puts("Try using another username");
        return 0;
    }
    return 1;
}
int register_user( char *username, char *password) {
    //read data from terminal
    printf("username=");
    read_input_stdin(&username);
    
    printf("password=");
    read_input_stdin(&password);
    //finished reading username & password
    //ma folosesc de parson ca sa creez body_data?

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000,1);
    char *string_from_json = json_parse_to_string(username, password);
    struct Request *post_request = init_post_request(IP_SERVER, REGISTER_URL, "application/json", string_from_json , NULL, 0, NULL);
    
    message = compute_post_request(post_request);
    send_to_server(sockfd, message);
    
    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Trying to register user: %s\n", username);
    
    message = receive_from_server(sockfd);
    int res = check_username_taken(message);
    if(res){
        printf("User %s created successfully\n", username);
    } 
    close_connection(sockfd);
    
    //TODO :free allocated data
    free(message);
    // free(string_from_json); ?? tre dat free?
    free_request(&post_request);
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
int check_username(char *message){
    JSON_Value *root_value = json_value_init_object();
    root_value = json_parse_string(strchr(message,'{'));

    JSON_Object *root_object = json_value_get_object(root_value);
    if(json_object_get_string(root_object, "error"))
        return 1;
    return 0;
}
char *get_cookie_from_server_message(char *server_message){
    char *cookie;
    //trebuie parsat cu json sau doar pt DATA? 
    cookie = strstr(server_message, "Set-Cookie: ");
    cookie = cookie + strlen("Set-Cookie: ");
    cookie = strtok(cookie, ";");
    
    return cookie;
}

int login_user(char *username, char *password, char **cookie){
    printf("username=");
    read_input_stdin(&username);
    printf("password=");
    read_input_stdin(&password);
    //finished reading user & pass
    
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(1000,1);
    char *string_from_json = json_parse_to_string(username, password);

    struct Request *post_request = init_post_request(IP_SERVER, LOGIN_URL, "application/json", string_from_json,NULL, 0 ,NULL);
    
    message = compute_post_request(post_request);
    
    send_to_server(sockfd, message);

    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Trying to log in user : %s\nThis should not take too long!\n", username);
    message = receive_from_server(sockfd);
    
    int check_account = check_username(message);
    if(check_account == 1)
        printf("No account with this username\n");
    else {
        *cookie = get_cookie_from_server_message(message);
        printf("User %s logged in successfully!\n",username);
        /*
        if(*cookie)
            printf("cookie este %s\n", *cookie);
        */
    }
    close_connection(sockfd);

    //free la message alocat cu calloc la linia 101 ??
    free(message);
    free_request(&post_request);
    return 0;
}

void get_token_from_response(char *server_message, char **token){
    JSON_Value *root_value = json_value_init_object();
    root_value = json_parse_string(strchr(server_message,'{'));

    JSON_Object *root_object = json_value_get_object(root_value);
    *token = (char*)json_object_get_string(root_object, "token");
}
/**
 * 1 daca s a realizatat intrarea in librarie
 * 0 altfel
 **/
int check_entry_library(char *message){
    char *tok = strtok(message,"\n");
    if(strstr(tok,"OK"))
        return 1;
    return 0;
}
/*
Cerere de acces in bibliotecă
• Ruta de acces: GET /api/v1/tema/library/access
• Trebuie sa demonstraţi că sunteţi autentificaţi => folosesc cookie de sesiune returnat la login
• Întoarce un token JWT, care demonstrează accesul la bibliotecă = pastrez jwt pentru mai tarziu,l trimit ca parametru
• Întoarce un mesaj de eroare dacă nu demonstraţi că sunteţi autentificaţi => daca return 0 -> totul e OK
*/

int enter_library(char *session_cookie, char **jwt_token){

    DIE(session_cookie == NULL, "Try logging in before!");
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup
    struct Request *get_request = init_get_request(IP_SERVER, ACCESS_URL, NULL, cookies , 1, NULL);

    message = compute_get_request(get_request);
    send_to_server(sockfd, message);
//
    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Entering the library...\n");    
    message = receive_from_server(sockfd);
    get_token_from_response(message, jwt_token);
    DIE(!(*jwt_token) ,"token e null\n");
    if(check_entry_library(message)){
        printf("Welcome to the library!\n");
    } else
        printf("Access not allowed in the library!\n");
    /*
    printf("Auth token este");
    puts(*jwt_token);
    */
    //TODO: free allocated data
    free_request(&get_request);
    free(message);
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
/*
    1 daca cartea a fost adaugata cu succes
    0 altfel
*/
int check_successful_response(char *message){
    if (strstr(message, "OK"))
        return 1;
    
    return 0;
}
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

    struct Request *post_request = init_post_request(IP_SERVER, BOOKS_URL, "application/json", string_from_json, cookies, 1, auth_token);

    message = compute_post_request(post_request);
    send_to_server(sockfd, message);

    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Adding book: \" %s \" in the library..\n", *title);

    message = receive_from_server(sockfd);
    //puts(message);
    int result = check_successful_response(message);
    if(result){
        printf("Book \" %s \" was added to your library!\n", *title);     
    } else {
        printf("Book \" %s \" was NOT added to your library\n", *title);
    }
    
    //TODO: free id_book and struct book etc
    free_request(&post_request);
    free(message);
    
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
void get_books_from_response(char **message){
    JSON_Value *root_value = json_value_init_object();
    root_value = json_parse_string(strchr(*message,'{'));

    JSON_Object *root_object = json_value_get_object(root_value);
    *message = (char*)json_object_get_string(root_object, "id");
}
int get_books(char *session_cookie, char *auth_token){
    DIE(session_cookie == NULL, "session cookie = null");
    DIE(auth_token == NULL, "No authentication was made.Please enter library!\n");

    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");

    cookies[0] = session_cookie;//sa folosesc strdup
    struct Request *get_request = init_get_request(IP_SERVER, BOOKS_URL, NULL, cookies , 1, auth_token);

    message = compute_get_request(get_request);
    send_to_server(sockfd, message);

    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Getting books from the library...This should not take too long!\n");

    message = receive_from_server(sockfd);
    //get_books_from_response(&message); //nu stiu daca merge pentru ca am un array de jsonuri
    char *book_list = strstr(message, "{");
    if(book_list){
        book_list[strlen(book_list) -1] = '\0'; // ca sa stergem ] de la sfarsit
        puts(book_list);
        free(message);
    } else
        printf("There is no book for this user in his library.\n");
    //TODO: free id_book and struct book etc
    free_request(&get_request);
    
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

void show_book(struct book_t *book){
    printf("Title: %s\n", book->title);
    printf("Author: %s\n", book->author);
    printf("Publisher: %s\n", book->publisher);
    printf("Genre: %s\n", book->genre);
    printf("Page_count: %d\n", book->page_count);
}
int get_book_info(struct book_t *new_book, char *response_server){
    JSON_Value *root_value = json_value_init_object();
    root_value = json_parse_string(strchr(response_server,'{'));

    JSON_Object *root_object = json_value_get_object(root_value);
    new_book->title = (char*)json_object_get_string(root_object, "title");
    new_book->author = (char*)json_object_get_string(root_object, "author");
    new_book->publisher = (char*)json_object_get_string(root_object, "publisher");
    new_book->genre = (char*)json_object_get_string(root_object, "genre");
    new_book->page_count = (int)json_object_get_number(root_object, "page_count");

    return 0;
}
/*
    1, daca server afiseaza un mesaj de eroare pt o carte inexistenta
    0, daca server afiseaza altceva != error 
*/
int check_error_book(char *message){
    JSON_Value *root_value = json_value_init_object();
    root_value = json_parse_string(strchr(message,'{'));

    JSON_Object *root_object = json_value_get_object(root_value);
    if(json_object_get_string(root_object, "error"))
        return 1;
    return 0;
}
void free_book(struct book_t *book){
    free(book->title);
    free(book->author);
    free(book->publisher);
    free(book->genre);
    free(book);
}
int get_book(char *session_cookie , char *auth_token){
    printf("id=");
    char *id_book = calloc(BOOK_INFO_LEN, 1);
    DIE(!id_book,"id book null");
    read_info_book(&id_book);
    if(!strcmp(id_book,"")){
        free(id_book);
        printf("Id nu e bun\n");
        return -1;
    }
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
    struct Request *get_request = init_get_request(IP_SERVER, url_book, NULL, cookies , 1, auth_token);

    message = compute_get_request(get_request);
    send_to_server(sockfd, message);
//
    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Getting book with id: %s from the library!\n", id_book);
    message = receive_from_server(sockfd);
    int exists =  check_error_book(message);
    struct book_t *book_id = calloc(sizeof(struct book_t), 1);
    DIE(!book_id, "book e null");

    get_book_info(book_id, message);
    if (exists == 1)
        printf("Book with id = %s doesn't exist in your library\n", id_book);
    else 
        show_book(book_id);

    //TODO: free id_book and struct book etc
    free(id_book);
    free_book(book_id);
    free_request(&get_request);

    return 0;
}
/*
    1, daca s a sters cu success cartea
    0, altfel
*/
int check_delete_success(char *message){
    char *tok = strtok(message,"\n");
    if(strstr(tok, "OK"))
        return 1;
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

    struct Request * delete_request = init_delete_request(IP_SERVER, url_book, "application/json", cookies, 1, auth_token);;

    message = compute_delete_request(delete_request);
    send_to_server(sockfd, message);
//
    //puts("###start request###");
    //puts(message);
    //puts("###end of request###");
    printf("Deleting book with ID = %s from the library\n", id_book);
    message = receive_from_server(sockfd);
    int book_exists = check_error_book(message);

    //TODO: sa stilizez mesajul primit de la server
    if(book_exists == 1){
        printf("Book with ID = %s doesn't exist in your library!\n", id_book);
    } else{ 
        //puts(message);
        if(check_delete_success(message))
            printf("Book with ID = %s was successfully deleted\n", id_book);
        else
            printf("Book with id = %s could NOT have been deleted.\n",id_book);
    }
    free(message);
    free(id_book);
    free_request(&delete_request);

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
/**
 * 1,daca s a delogat cu succes
 * 0 altfel
 * */
int check_logout(char *message){
    char *tok = strtok(message, "\n");
    if(strstr(tok,"OK"))
        return 1;
    return 0;
}
int logout(char **session_cookie, char **auth_token){
    //cookie devine invalid la delogare
    //daca decomentez, nu mai merge cookie -ul vechi
    //copiez dupa alt cookie(poate expira)
    int sockfd = open_connection(IP_SERVER, PORT_SERVER, 
                                AF_INET, SOCK_STREAM, 0);
    char **cookies = calloc(MAX_COOKIES, sizeof(char*));
    DIE(!cookies, "calloc failed");
    char *message = calloc(10000, 1);
    DIE( message == NULL, "calloc failed\n");
    cookies[0] = *session_cookie;//sa folosesc strdup?

    struct Request *get_request = init_get_request(IP_SERVER, LOGOUT_URL, NULL, cookies , 1, *auth_token);

    message = compute_get_request(get_request);
    
    send_to_server(sockfd, message);
    //puts(message);
    printf("Trying to log out user from the library\n");
    message = receive_from_server(sockfd);
    //puts(message);
    int result = check_logout(message);
    if(result){
        printf("User logged out successfully.See you next time!\n");
    } else{
        printf("User could NOT log out from the library\n.Try again!\n");
        puts(message);
    }
    *session_cookie = NULL;
    *auth_token = NULL;

    free(message);
    free_request(&get_request);

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
            result = logout(&login_cookie , &jwt_token);
            DIE(result < 0, "logging out failed");
        } else if (strstr(cmd, "exit"))
            break;
        else 
            printf("Incorrect cmd.Try again!\n");
    }
    // free the allocated data at the end!
    free_info_book(&title, &author, &page_count, &
                    publisher, &genre);

    return 0;
}
