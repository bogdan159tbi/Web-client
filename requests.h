#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
struct Request;
struct Cookies;
void free_request(struct Request **request);
void free_cookie(struct Cookies **cookie);

struct Request *init_get_request(char *host, char *url, char *query_params, char **cookies, int cookies_count,  char* authorization_token);
char *compute_get_request(struct Request *request);
/*

*/
// computes and returns a POST request string (cookies can be NULL if not needed)
struct Request *init_post_request(char *host, char *url, char* content_type, char *body_data,
                                char **cookies, int cookies_count, char* authorization_token);
char *compute_post_request(struct Request *request);
/*
char *host, char *url, char *query_params,
                            char **cookies, int cookies_count, char* authorization_token
*/
struct Request *init_delete_request(char *host, char *url, char* content_type,
                                    char **cookies, int cookies_count,  char* authorization_token);
char *compute_delete_request(struct Request *request);
			

#endif
