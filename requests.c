#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

struct Cookies{
    char **cookies;
    int cookies_nr;
};

struct Request{
    char *host;
    char *url;
    char *content_type;
    char *body_data;
    char *query_params;
    char *auth_token;
    struct Cookies *cookies_array;
};

void free_cookie(struct Cookies **cookie){
    for(int i = 0 ; i < (*cookie)->cookies_nr;i++){
        free((*cookie)->cookies[i]);
    }
    free((*cookie)->cookies);
    free((*cookie));
}
void free_request(struct Request **request){
    if((*request)->host)
        free((*request)->host);
    if((*request)->url)
        free((*request)->url);
    if((*request)->body_data)
        free((*request)->body_data);
    if((*request)->query_params)
        free((*request)->query_params);
    free((*request));
}
/*
  Adauga bearer de token si cookie-ul obtinut in urma apelului de functie register_user  
*/
void add_session_auth(struct Cookies *cookies_array, char *auth_token,
                     char **line, char **message)
{
    if (cookies_array->cookies != NULL) {
       strcpy(*line,"Cookie: ");
       for(int i = 0 ; i < cookies_array->cookies_nr; i++){
           strcat(*line, cookies_array->cookies[i]);
       }
       compute_message(*message, *line);   
    }
    if (auth_token != NULL){
        sprintf(*line, "Authorization: Bearer %s", auth_token);
        compute_message(*message, *line);
    }
}

struct Request *init_get_request(char *host, char *url,char *query_params,
                                char **cookies, int cookies_count,  char* authorization_token)
{
    struct Request *req = NULL;
    req = calloc(sizeof(struct Request), 1);
    DIE(!req, "request failed\n");

    req->host = strdup(host);
    req->url = strdup(url);

    if(query_params)
        req->query_params = strdup(query_params);
    else
        req->query_params = NULL;

    if(cookies_count > 0){
        req->cookies_array = calloc(sizeof(struct Cookie*),1);
        DIE(!req->cookies_array, "cookies array failed to alloc\n");
        req->cookies_array->cookies = cookies;
        req->cookies_array->cookies_nr = cookies_count;
    } else{
        req->cookies_array = calloc(sizeof(struct Cookie*),1);
        DIE(!req->cookies_array,"array cookies null\n");
    }
    if(authorization_token)
        req->auth_token = strdup(authorization_token);
    else{
        req->auth_token = calloc(MAX_COOKIES, 1);
        DIE(!req->auth_token,"auth token failed to allocate\n");
    }
    //pot sa dau free la vreun parametru daca a fost alocat inainte de apel
    return req;    
}
char *compute_get_request(struct Request *request)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL, request params (if any) and protocol type
    if (request->query_params != NULL) {
        sprintf(line, "GET %s?%s HTTP/1.1", request->url, request->query_params);
    } else {
        sprintf(line, "GET %s HTTP/1.1", request->url);
    }

    compute_message(message, line);
    // Step 2: add the host
    sprintf(line, "Host: %s", request->host);
    compute_message(message, line);

    // Step 3 (optional): add headers and/or cookies, according to the protocol format
    add_session_auth(request->cookies_array, request->auth_token,
                    &line, &message);    
    // Step 4: add final new line
    compute_message(message, "");
    return message;
}
//char **body data a=7 b=7 initial
struct Request *init_post_request(char *host, char *url, char* content_type, char *body_data,
                                char **cookies, int cookies_count, char* authorization_token)
{
    struct Request *req = NULL;
    req = calloc(sizeof(struct Request), 1);
    DIE(!req, "request failed\n");

    req->host = strdup(host);
    req->url = strdup(url);

    if(content_type)
        req->content_type = strdup(content_type);
    else
        req->content_type = NULL;
    if(body_data)
        req->body_data = strdup(body_data);
    else
        req->body_data = NULL;
    
    if(cookies_count){
        req->cookies_array = calloc(sizeof(struct Cookies*), 1);
        DIE(!req->cookies_array, "cookies array failed to allcoate\n");
        req->cookies_array->cookies = calloc(sizeof(char*), MAX_COOKIES);
        DIE(!req->cookies_array->cookies, "cookies ** failed to alloc\n");
        req->cookies_array->cookies = cookies;
        req->cookies_array->cookies_nr = cookies_count;
    }
    if(authorization_token)
        req->auth_token = strdup(authorization_token);

    //pot sa dau free la vreun parametru daca a fost alocat inainte de apel
    return req;    
}
char *compute_post_request(struct Request *request)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    //char *body_data_buffer = calloc(LINELEN, sizeof(char));
    DIE(!request,"request e null");
    // Step 1: write the method name, URL and protocol type

    DIE(!request->url,"url e null");
    sprintf(line, "POST %s HTTP/1.1", request->url);
    compute_message(message, line);
    
    // Step 2: add the host
    DIE(!request->host,"host e null");
    sprintf(line, "Host: %s", request->host);
    compute_message(message, line);
    /* Step 3: add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
    DIE(!request->content_type,"content_type e null");
    sprintf(line, "Content-Type: %s", request->content_type);
    compute_message(message, line);

    DIE(!request->body_data,"body data null");
    sprintf(line, "Content-Length: %lu", strlen(request->body_data));
    compute_message(message, line);

    // Step 4 (optional): add cookies
    //DIE(!request->cookies_array,"cookies null");
    //DIE(!request->auth_token,"auth null");
    if(request->cookies_array)
        add_session_auth(request->cookies_array, request->auth_token,
                    &line, &message);
    // Step 5: add new line at end of header

    compute_message(message, "");
    // Step 6: add the actual payload data
    strcat(message, request->body_data); // nu tre \r\n dupa body data

    free(line);
    return message;
}
struct Request *init_delete_request(char *host, char *url, char* content_type,
                                    char **cookies, int cookies_count,  char* authorization_token)
{
    struct Request *req = NULL;
    req = calloc(sizeof(struct Request), 1);
    DIE(!req, "request failed\n");

    req->host = strdup(host);
    req->url = strdup(url);

    if(content_type)
        req->content_type = strdup(content_type);
    else
        req->content_type = NULL;
    
    if(cookies_count){
        req->cookies_array = calloc(sizeof(struct Cookie*), 1);
        DIE(!req->cookies_array, "cookies array failed to alloc\n");
        req->cookies_array->cookies = cookies;
        req->cookies_array->cookies_nr = cookies_count;
    }
    if(authorization_token)
        req->auth_token = strdup(authorization_token);

    //pot sa dau free la vreun parametru daca a fost alocat inainte de apel
    return req;
}
char *compute_delete_request(struct Request *request)
{   
    char *message = calloc(BUFLEN, sizeof(char));
    DIE(!message, "msg null");
    char *line = calloc(LINELEN, sizeof(char));
    DIE(!line, "msg null");
    char *body_data_buffer = calloc(LINELEN, sizeof(char));
    DIE(!body_data_buffer, "msg null");
    // Step 1: write the method name, URL and protocol type
    sprintf(line, "DELETE %s HTTP/1.1", request->url);
    compute_message(message, line);
    
    // Step 2: add the host
    sprintf(line, "Host: %s", request->host);
    compute_message(message, line);
    /* Step 3: add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
    sprintf(line, "Content-Type: %s", request->content_type);
    compute_message(message, line);

    // Step 4 (optional): add cookies
    add_session_auth(request->cookies_array, request->auth_token,
                    &line, &message);
    // Step 5: add new line at end of header

    compute_message(message, "");

    free(line);
    return message;

}