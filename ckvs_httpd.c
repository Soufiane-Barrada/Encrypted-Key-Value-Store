/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404

#define BUFFER_EXTRACTION_LENGTH 1024


//-----------------------------Utilitary functions and prototypes-------------------------


/**
 * @brief handler for stats call, sends back a message containing the stats
 * 
 * @param nc the connection used to communicate
 * @param ckvs the struct from which we extract the information
 * @param hm the http message that was received
 */
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm);

/**
 * @brief handler for get call, sends back a message eventually containing the wanted entry 
 * 
 * @param nc the connection used to communicate
 * @param ckvs the struct from which we extract the information
 * @param hm the http message that was received
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm);

/**
 * @brief handler for set call,  
 * 
 * @param nc the connection used to communicate
 * @param ckvs the struct representing the data base
 * @param hm the http message that was received
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm);

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm);

/**
 * @brief Get the url-decoded argument
 * 
 * @param hm http message from where to get the argument 
 * @param arg the argument in question 
 * @return char* the url-decoded argument or NULL in case of an error 
 */
static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg)
{   
    char buffer[BUFFER_EXTRACTION_LENGTH] = {0}; 
    int length = mg_http_get_var(&hm->query, arg, buffer ,BUFFER_EXTRACTION_LENGTH);
    if(length <= 0){
        return NULL;
    }
    CURL *curl = curl_easy_init();
    if(curl == NULL){
        return NULL;
    }

    char * decoded_argument = curl_easy_unescape(curl, buffer, strlen(buffer), NULL);
    return decoded_argument;
}
//--------------------------------------------------------------------

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

// ======================================================================

/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(
struct mg_connection *nc, int ev, void *ev_data, void *fn_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        if(mg_http_match_uri(hm, "/stats")){

            handle_stats_call(nc , ckvs, hm );
        }else if (mg_http_match_uri(hm, "/get")){
            
            handle_get_call(nc , ckvs, hm );
        
        }else if (mg_http_match_uri(hm, "/set")){
        
            handle_set_call(nc , ckvs, hm );
        
        }else{
        
            mg_error_msg(nc, NOT_IMPLEMENTED); 
        
        }
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}


/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}


//handler methods for different calls
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm)
{
    //creating the json objects 
    json_object* response_json = json_object_new_object();
    json_object * header_string_json = json_object_new_string(ckvs->header.header_string) ;
    json_object * version_json = json_object_new_int(ckvs->header.version);
    json_object * table_size_json  = json_object_new_int(ckvs->header.table_size);
    json_object * threashold_entries_json = json_object_new_int(ckvs->header.threshold_entries);
    json_object * num_entries_json = json_object_new_int(ckvs->header.num_entries);
    json_object * keys_json = json_object_new_array() ;
    //error management
    if(response_json == NULL || header_string_json == NULL || version_json == NULL||
        table_size_json == NULL || threashold_entries_json == NULL ||  
        num_entries_json == NULL ||keys_json == NULL ){
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }
    
    for(size_t i = 0 ; i< ckvs->header.num_entries; i++){
        json_object* current_key = json_object_new_string(ckvs->entries[i].key);
        json_object_array_add(keys_json, current_key);
    }
    // adding all the children json 
    int err = json_object_object_add(response_json, "header_string" , header_string_json);
    json_object_object_add(response_json, "version" , version_json);
    json_object_object_add(response_json, "table_size" , table_size_json);
    json_object_object_add(response_json, "threshold_entries" , threashold_entries_json);
    json_object_object_add(response_json, "num_entries" , num_entries_json);
    json_object_object_add(response_json, "keys" , keys_json);
    
    //creating the response json 
    size_t message_length;
    const char * response_string = json_object_to_json_string(response_json);
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", response_string);
    json_object_put(response_json);

}


static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm)
{
    char* key = get_urldecoded_argument(hm, "key");
    if(key != NULL){
        //extracting auth_key
        char buffer[BUFFER_EXTRACTION_LENGTH] = {0}; 
        int length = mg_http_get_var(&hm->query, "auth_key", buffer ,BUFFER_EXTRACTION_LENGTH);
        if(length <= 0){
            curl_free(key);
            mg_error_msg(nc, ERR_IO);
            return ;
        }
        ckvs_sha_t auth_key;
        memset(&auth_key, 0, sizeof(auth_key));
        if(SHA256_from_string( buffer , &auth_key ) == -1){
            curl_free(key);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        //finding the entry 
        ckvs_entry_t * entry_ptr = NULL;
        int err = ckvs_find_entry(ckvs, key, &auth_key, &entry_ptr);
        if(err != ERR_NONE){
            curl_free(key);
            mg_error_msg(nc, ERR_NO_VALUE);
            return;
        }

        // computing the hexcode of c2      
        char c2_hexcoded[(SHA256_DIGEST_LENGTH*2)+1]  = {0} ;
        SHA256_to_string(&entry_ptr->c2, c2_hexcoded);

        
        //creating the data json 
        size_t initial_data_len = entry_ptr->value_len;
        char * data = NULL;
        char * data_hexcoded = NULL;
        data = calloc(initial_data_len , 1);
        data_hexcoded = calloc(initial_data_len*2 + 1 , 1);

        if(data_hexcoded == NULL  || data == NULL){
            free(data);
            free(data_hexcoded);
            curl_free(key);
            mg_error_msg(nc, ERR_OUT_OF_MEMORY);
            return;
        }

        //extracting the data         
        if ( fseek(ckvs->file,(long)entry_ptr->value_off, SEEK_SET) != 0){
            free(data);
            free(data_hexcoded);
            curl_free(key);
            mg_error_msg(nc, ERR_IO);
            return ;
        }

        if(fread(data, sizeof(char), initial_data_len, ckvs->file) != initial_data_len ){
            free(data);
            free(data_hexcoded);
            curl_free(key);
            mg_error_msg(nc, ERR_IO);
            return ;
        }

        //hex encoding the data 
        hex_encode(data , initial_data_len, data_hexcoded);

        //creating the json and putting them all together
        json_object* response_json = json_object_new_object();
        json_object * c2_json = json_object_new_string(c2_hexcoded); 
        json_object * data_json = json_object_new_string(data_hexcoded);


        err = json_object_object_add(response_json, "c2" , c2_json);
        if(err < 0){
            json_object_put(response_json);
            json_object_put(c2_json);
            json_object_put(data_json);
            free(data);
            free(data_hexcoded);
            curl_free(key);
            mg_error_msg(nc, ERR_IO);
            return ;
        }
        err = json_object_object_add(response_json, "data" , data_json);
        if(err < 0){
            json_object_put(response_json);
            json_object_put(c2_json);
            json_object_put(data_json);
            free(data);
            free(data_hexcoded);
            curl_free(key);
            mg_error_msg(nc, ERR_IO);
            return ;
        }
    
        const char * response_string = json_object_to_json_string(response_json);
        mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", response_string);
        json_object_put(response_json);
        free(data);
        free(data_hexcoded);
        curl_free(key);



    }else{
        curl_free(key);
        mg_error_msg(nc, ERR_IO);
    }


}



static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, 
                              _unused struct mg_http_message *hm)
{

    mg_http_upload(nc, hm, "/tmp");





}