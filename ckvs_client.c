#include <stdio.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "ckvs_rpc.h"
#include <json-c/json.h>

#define NUMBER_ARG_STATS_CLIENT 0 
#define NUMBER_ARG_GET 2
#define NUMBER_ARG_SET 3
#define STR(X) #X
#define INPUT_FMT(X) STR(X)


int ckvs_client_stats(const char *url, int optargc, char **optargv){
    M_REQUIRE_NON_NULL(url);
    
    if( optargc < NUMBER_ARG_STATS_CLIENT){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }
    if( optargc > NUMBER_ARG_STATS_CLIENT){
        return ERR_TOO_MANY_ARGUMENTS;
    }
    ckvs_connection_t conn; 
    memset(&conn, 0, sizeof(conn));
    int err = ckvs_rpc_init(&conn, url);
    if(err != ERR_NONE){
        return err; 
    }

    err = ckvs_rpc(&conn, "stats");
    if(err != ERR_NONE){
        ckvs_rpc_close(&conn);
        return err;
    }
    json_object * resp_json = json_tokener_parse(conn.resp_buf);
    if(resp_json == NULL){
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    json_object * header_string_json;
    json_object * version_json;
    json_object * table_size_json;
    json_object * threashhold_entries_json;
    json_object * num_entries_json;
    json_object * keys_json;
    int key_exists = json_object_object_get_ex(resp_json, "header_string", &header_string_json);
    if(!key_exists){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    key_exists = json_object_object_get_ex(resp_json, "version", &version_json);
    if(!key_exists){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    key_exists = json_object_object_get_ex(resp_json, "table_size", &table_size_json);
    if(!key_exists){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    key_exists = json_object_object_get_ex(resp_json, "threshold_entries", &threashhold_entries_json);
    if(!key_exists){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    key_exists = json_object_object_get_ex(resp_json, "num_entries", &num_entries_json);
    if(!key_exists){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    key_exists = json_object_object_get_ex(resp_json, "keys", &keys_json);
    if(!key_exists){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    
    ckvs_header_t header;
    const char * header_string = json_object_get_string(header_string_json);
    if(header_string == NULL){
        json_object_put(resp_json);
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }
    strncpy(header.header_string, header_string, CKVS_HEADERSTRINGLEN);
    //filling the header fields 
    header.num_entries = json_object_get_int(num_entries_json);
    header.table_size = json_object_get_int(table_size_json);
    header.threshold_entries = json_object_get_int(threashhold_entries_json);
    header.version = json_object_get_int(version_json);
    // printing the header
    print_header(&header);

    //printing the keys

    size_t nb_keys = json_object_array_length(keys_json);
    for(size_t i = 0; i < nb_keys ; i++){
        json_object * current_key_json = json_object_array_get_idx(keys_json, i);
        if(current_key_json == NULL){
            json_object_put(resp_json);
            ckvs_rpc_close(&conn);
            return ERR_IO;
        }
        //const char * current_key_name =  json_object_get_string(current_key_json);
        pps_printf("%-10s: %s\n", "Key", json_object_get_string(current_key_json));

    }
    json_object_put(resp_json);
    

    ckvs_rpc_close(&conn);
    return ERR_NONE;

}



int ckvs_client_get(const char *url, int optargc, char **optargv){
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    if( optargc < NUMBER_ARG_GET){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }
    if( optargc > NUMBER_ARG_GET){
        return ERR_TOO_MANY_ARGUMENTS;
    }
    
    const char* key =  optargv[0];
    const char* pwd =  optargv[1];

    return ckvs_client_getset(url, key, pwd, NULL);
}
/**
 * @brief Performs the 'set' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 3)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_set(const char *url, int optargc, char **optargv){
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(optargv);

    if(optargc < NUMBER_ARG_SET) 
        return ERR_NOT_ENOUGH_ARGUMENTS;
    if(optargc > NUMBER_ARG_SET) 
        return ERR_TOO_MANY_ARGUMENTS;
    //read the new value from the file
    const char* key =  optargv[0];
    const char* pwd =  optargv[1];
    const char* valuefilename = optargv[2];

    char* buffer = NULL ; 
    size_t buffer_size = 0 ;
    error_code err = read_value_file_content(valuefilename, &buffer, &buffer_size);

    if(err != ERR_NONE){
        return err;
    }

    return ckvs_client_getset(url, key, pwd, buffer);
}


int ckvs_client_getset(const char *url, const char *key, const char *pwd,const char* set_value){
    // start of shared code of get and set 
    M_REQUIRE_NON_NULL(url);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    ckvs_memrecord_t mr;
    memset(&mr,0 ,sizeof(ckvs_memrecord_t));
    
    // generate stretched, auth_key and c1
    int err = ckvs_client_encrypt_pwd(&mr,key,pwd);  
    if(err != ERR_NONE){
        return err;
    }
    
    // creating the connection
    ckvs_connection_t conn; 
    memset(&conn, 0, sizeof(conn));
     err = ckvs_rpc_init(&conn, url);
    if(err != ERR_NONE){
        return err; 
    }

    //transforming the key
    char * url_escaped_key = curl_easy_escape(conn.curl, key, 0);
    if(url_escaped_key == NULL){
        ckvs_rpc_close(&conn);
        curl_free(url_escaped_key);
        return ERR_OUT_OF_MEMORY;
    }
    
    //encoding the authkey
    char * enc_auth_key[SHA256_PRINTED_STRLEN] = {0};
    SHA256_to_string(&mr.auth_key.sha, enc_auth_key);
    
    //analyzing the response 
    

    // end of shared code of get and set

    if(set_value == NULL) { 
        char * Get =calloc(strlen(url_escaped_key)+strlen(enc_auth_key)+19 + 1, sizeof(char));
        sprintf(Get, "get?key=%s&auth_key=%s",url_escaped_key,enc_auth_key);
        err = ckvs_rpc(&conn, Get);
        if(err != NULL){
            free(Get);
            ckvs_rpc_close(&conn);
            curl_free(url_escaped_key);
            return err;
        }
        json_object * resp_json = json_tokener_parse(conn.resp_buf);
        if(resp_json == NULL){
            pps_printf("%s", "Incorrect key/password\n");
            pps_printf("%s", "Key not found\n");
            free(Get);
            ckvs_rpc_close(&conn);
            curl_free(url_escaped_key);
            return ERR_IO;
        }
    
        json_object * c2_json ;
        int key_exists = json_object_object_get_ex(resp_json, "c2", &c2_json);
        if(!key_exists){
            free(Get);
            ckvs_rpc_close(&conn);
            json_object_put(resp_json);
            curl_free(url_escaped_key);
            return ERR_IO;
        }
        json_object * data_json ;
        key_exists = json_object_object_get_ex(resp_json, "data", &data_json);
        if(!key_exists){
            free(Get);
            ckvs_rpc_close(&conn);
            json_object_put(resp_json);
            curl_free(url_escaped_key);
            return ERR_IO;
        }

        const char * c2_encoded = json_object_get_string(c2_json);
        if(c2_encoded == NULL){
            free(Get);
            ckvs_rpc_close(&conn);
                        json_object_put(resp_json);
            curl_free(url_escaped_key);    
            return ERR_IO;
        }
        //extracting c2
        ckvs_sha_t c2;
        memset(&c2, 0, sizeof(c2));
        SHA256_from_string(c2_encoded , &c2);
        
        //computing the master key 
        err = ckvs_client_compute_masterkey(&mr, &c2);
        if(err != ERR_NONE){
            free(Get);
            ckvs_rpc_close(&conn);
            json_object_put(resp_json);
            curl_free(url_escaped_key);    
            return err;
        }

        const char * data = json_object_get_string(data_json);
        if(data == NULL){
            free(Get);
            ckvs_rpc_close(&conn);
            json_object_put(resp_json);
            curl_free(url_escaped_key);    
            return ERR_IO;
        }
        char * data2 = calloc(strlen(data)+1, sizeof(char));
        if(data2 ==NULL){
            return ERR_OUT_OF_MEMORY;
        }
        size_t inbufLen = hex_decode(data, data2);

        if( inbufLen== -1) {
            free(Get);
            free(data2);
            ckvs_rpc_close(&conn);
            json_object_put(resp_json);
            curl_free(url_escaped_key);    
            return ERR_IO;
        }
        

        

        //creating the output 
        char * output = NULL;
        output = malloc(inbufLen + EVP_MAX_BLOCK_LENGTH);
        if(output == NULL){
            free(Get);
            free(data2);
            ckvs_rpc_close(&conn);
            json_object_put(resp_json);
            curl_free(url_escaped_key);    
            return ERR_OUT_OF_MEMORY;
        }
        size_t nb_written = 0 ; 
        err = ckvs_client_crypt_value(&mr, 0, data2, inbufLen, output, &nb_written);
        if(err != ERR_NONE){
            free(Get);
            free(output);
            free(data2);
            json_object_put(resp_json);
            ckvs_rpc_close(&conn);
            curl_free(url_escaped_key);    
            return err;
        }
            pps_printf("%s",output);
            free(Get);
            free(output);
            free(data2);
            //releasing the json 
            json_object_put(resp_json);
            ckvs_rpc_close(&conn);
            curl_free(url_escaped_key);  
    }else{
        char * Get = calloc(strlen(url_escaped_key)+strlen(enc_auth_key)+50 + 1, sizeof(char));
        sprintf(Get, "set?name=data.json&offset=0&key=%s&auth_key=%s",url_escaped_key,enc_auth_key);

        json_object* POST = json_object_new_object();
        //generate c2
        ckvs_sha_t c2 ;
        memset(&c2,0,sizeof(ckvs_sha_t));
        if(RAND_bytes(c2.sha, SHA256_DIGEST_LENGTH) != 1){
            json_object_put(POST);
            free(set_value); 
            ckvs_rpc_close(&conn);
            curl_free(url_escaped_key);
            return ERR_IO;
        }
        char* c2Hexcoded = calloc(sizeof(c2.sha)*2+1, sizeof(char));
        hex_encode(c2.sha, sizeof(c2.sha), c2Hexcoded);
        json_object * c2_js = json_object_new_string(c2Hexcoded) ;
        // data to be encrypted ?
        char* dataHexcoded = calloc(sizeof(set_value)*2+1, sizeof(char));
        hex_encode(set_value, sizeof(set_value), dataHexcoded);

        json_object * data_js = json_object_new_string(dataHexcoded) ;


        json_object_object_add(POST,"c2",c2_js);
        json_object_object_add(POST,"data",data_js);
        
        char* Post_string= json_object_to_json_string(POST);

        err = ckvs_post(&conn,Get,Post_string);
        if(err != ERR_NONE){
            json_object_put(POST);
            free(dataHexcoded);
            free(c2Hexcoded);
            free(set_value);
            ckvs_rpc_close(&conn);
            curl_free(url_escaped_key);
            return err;
        }   

        json_object_put(POST);
        free(dataHexcoded);
        free(c2Hexcoded);
        free(set_value);
        ckvs_rpc_close(&conn);
        curl_free(url_escaped_key);
    }
    
    return ERR_NONE;
    //end of shared get and set
}