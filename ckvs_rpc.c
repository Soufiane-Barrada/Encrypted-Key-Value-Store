/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>

#include "ckvs_rpc.h"
#include "error.h"
#include "util.h"
#include "ckvs_utils.h"

/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}


int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

int ckvs_rpc(struct ckvs_connection *conn, const char *GET)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);

    // concatenation de conn->url et GET
    char* url = calloc(strlen(GET)+strlen(conn->url)+2, sizeof(char));
    if(url == NULL){
        return ERR_IO;
    }
    strncpy(url,conn->url, strlen(conn->url));
    strncpy((url+strlen(conn->url)),"/",1);
    strncat(url, GET,  strlen(GET));

    //specification de l'url 
    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    if(ret == CURLE_OUT_OF_MEMORY){
        free(url);
        return ERR_OUT_OF_MEMORY;
    }

    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK){
        free(url);
        return ERR_TIMEOUT;
    }
    free(url);
    return ERR_NONE;
}

/**
 * @brief Sends an HTTP POST request to the connected server,
 * using its url, and the GET and POST payloads.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param GET (const char*) the GET payload. Should already contain the fields "name" and "offset".
 * @param POST (const char*) the POST payload
 * @return int, error code
 */
int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST){
      M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);

    // concatenation de conn->url et GET
    char* url = calloc(strlen(GET)+strlen(conn->url)+2, sizeof(char));
    if(url == NULL){
        return ERR_IO;
    }
    strncpy(url,conn->url, strlen(conn->url));
    strncpy((url+strlen(conn->url)),"/",1);
    strncat(url, GET,  strlen(GET));

    //specification de l'url 
    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    if(ret == CURLE_OUT_OF_MEMORY){
        free(url);
        return ERR_OUT_OF_MEMORY;
    }
    CURLOPT_HTTPHEADER;
    struct curl_slist* slist= NULL;
    slist = curl_slist_append(slist,"Content-Type: application/json");
    if(slist == NULL){
        free(url);
        return ERR_OUT_OF_MEMORY;
    }
    
    ret =curl_easy_setopt(conn->curl,CURLOPT_HTTPHEADER, slist);
    if(ret == CURLE_OUT_OF_MEMORY){
        curl_slist_free_all(slist);
        free(url);
        return ERR_OUT_OF_MEMORY;
    }
    // envoyer message
    ret = curl_easy_setopt(conn->curl,CURLOPT_POSTFIELDS, POST);
    if(ret == CURLE_OUT_OF_MEMORY){
        curl_slist_free_all(slist);
        free(url);
        return ERR_OUT_OF_MEMORY;
    }

    ret = curl_easy_perform(conn->curl);
    
    if(ret != CURLE_OK){
        curl_slist_free_all(slist);
        free(url);
        return ERR_TIMEOUT;
    }
    // envoyer chaine vide
    ret = curl_easy_setopt(conn->curl,CURLOPT_POSTFIELDS, "");
    if(ret == CURLE_OUT_OF_MEMORY){
        curl_slist_free_all(slist);
        free(url);
        return ERR_OUT_OF_MEMORY;
    }

    ret = curl_easy_perform(conn->curl);
    if(ret != CURLE_OK){
        curl_slist_free_all(slist);
        free(url);
        return ERR_TIMEOUT;
    }
    free(url);

    // check response if empty

    if(strcmp(conn->resp_buf,"") != 0){
        pps_printf("%s", conn->resp_buf);
        curl_slist_free_all(slist);
        return ERR_IO;
    }

    curl_slist_free_all(slist);
    return ERR_NONE;
}

