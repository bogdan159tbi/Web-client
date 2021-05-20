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

void add_session_auth(char **cookies, int cookies_count, char *auth_token,
                     char **line, char **message)
{
    if (cookies != NULL) {
       strcpy(*line,"Cookie: ");
       for(int i = 0 ; i < cookies_count; i++){
           strcat(*line, cookies[i]);
       }
       compute_message(*message, *line);   
    }
    if (auth_token != NULL){
        sprintf(*line, "Authorization: Bearer %s", auth_token);
        compute_message(*message, *line);
    }
}

char *compute_get_request(char *host, char *url, char *query_params,
                            char **cookies, int cookies_count, char* authorization_token)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL, request params (if any) and protocol type
    if (query_params != NULL) {
        sprintf(line, "GET %s?%s HTTP/1.1", url, query_params);
    } else {
        sprintf(line, "GET %s HTTP/1.1", url);
    }

    compute_message(message, line);

    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    // Step 3 (optional): add headers and/or cookies, according to the protocol format
    add_session_auth(cookies, cookies_count, authorization_token,
                    &line, &message);    
    // Step 4: add final new line
    compute_message(message, "");
    return message;
}
//char **body data a=7 b=7 initial
char *compute_post_request(char *host, char *url, char* content_type, char *body_data,
                             char **cookies, int cookies_count,  char* authorization_token)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    //char *body_data_buffer = calloc(LINELEN, sizeof(char));

    // Step 1: write the method name, URL and protocol type
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);
    /* Step 3: add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
   sprintf(line, "Content-Type: %s", content_type);
   compute_message(message, line);

   sprintf(line, "Content-Length: %lu", strlen(body_data));
   compute_message(message, line);

    // Step 4 (optional): add cookies
    add_session_auth(cookies, cookies_count, authorization_token,
                    &line, &message);
    // Step 5: add new line at end of header

    compute_message(message, "");
    // Step 6: add the actual payload data
    strcat(message, body_data); // nu tre \r\n dupa body data

    free(line);
    return message;
}

char *compute_delete_request(char *host, char *url, char* content_type, 
                             char **cookies, int cookies_count,  char* authorization_token)
{   
    char *message = calloc(BUFLEN, sizeof(char));
    DIE(!message, "msg null");
    char *line = calloc(LINELEN, sizeof(char));
    DIE(!line, "msg null");
    char *body_data_buffer = calloc(LINELEN, sizeof(char));
    DIE(!body_data_buffer, "msg null");
    // Step 1: write the method name, URL and protocol type
    sprintf(line, "DELETE %s HTTP/1.1", url);
    compute_message(message, line);
    
    // Step 2: add the host
    sprintf(line, "Host: %s", host);
    compute_message(message, line);
    /* Step 3: add necessary headers (Content-Type and Content-Length are mandatory)
            in order to write Content-Length you must first compute the message size
    */
   sprintf(line, "Content-Type: %s", content_type);
   compute_message(message, line);

    // Step 4 (optional): add cookies
    add_session_auth(cookies, cookies_count, authorization_token,
                    &line, &message);
    // Step 5: add new line at end of header

    compute_message(message, "");

    free(line);
    return message;

}