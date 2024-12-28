/**
 * @file ckvs_local.c
 * @brief ckvs_local -- operations on local databases
 *
 *
 */
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

#define NUMBER_ARG_STATS 0
#define NUMBER_ARG_GET_NEW 2
#define NUMBER_ARG_SET 3
#define MAX_VALUE_LENGTH 1200
// PROTOTYPE:
int ckvs_local_getset(const char *filename, const char *key, const char *pwd,const char* set_value);

// END OF PROTOTYPE


/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_stats(const char* filename, int optargc, char* optargv[])
{
    M_REQUIRE_NON_NULL(filename);
    //M_REQUIRE_NON_NULL(optargv);
    
    if( optargc < NUMBER_ARG_STATS){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }
    if( optargc > NUMBER_ARG_STATS){
        return ERR_TOO_MANY_ARGUMENTS;
    }
    
    CKVS_t ckvs ;
    error_code err = ckvs_open(filename, &ckvs); //open file and initialize ckvs
    if(err != ERR_NONE){
        return err;
    }

    //print the header
    print_header(&(ckvs.header)); 

    //print all non empty entries
    for (size_t i = 0; i < ckvs.header.table_size ; i++)
    {
        if (strlen((ckvs.entries)[i].key) > 0)
        {
            print_entry(&(ckvs.entries)[i]);
        }
    }

    ckvs_close(&ckvs); 
    return ERR_NONE;

}


/**
 * @brief Opens the CKVS database at the given filename and executes the 'get' command,
 * ie. fetches, decrypts and prints the entry corresponding to the key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_get(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    if( optargc < NUMBER_ARG_GET_NEW){
        return ERR_NOT_ENOUGH_ARGUMENTS;
    }
    if( optargc > NUMBER_ARG_GET_NEW){
        return ERR_TOO_MANY_ARGUMENTS;
    }
    
    const char* key =  optargv[0];
    const char* pwd =  optargv[1];

    return ckvs_local_getset(filename, key, pwd, NULL);
}


int ckvs_local_set(const char* filename, int optargc, char* optargv[]){
  
    M_REQUIRE_NON_NULL(filename);
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

    return ckvs_local_getset(filename, key, pwd, buffer);

}


int ckvs_local_getset(const char *filename, const char *key, const char *pwd,const char* set_value){
    // start of shared code of get and set 
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    memset(&mr,0 ,sizeof(ckvs_memrecord_t)); // initialise mr. (ckvs_open initialises ckvs, so no need)

    error_code err = ckvs_open(filename,&ckvs); // open file

    // checking if there was a problem reading
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        if(set_value != NULL){
            free(set_value);
        }
        return err;
    }

     // generate stretched, auth_key and c1
    err=ckvs_client_encrypt_pwd(&mr,key,pwd);  
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        if(set_value != NULL){
            free(set_value);
        }
        return err;
    }
    
    // we find the corresponding entry
    ckvs_entry_t* entry_out = NULL;
    err = ckvs_find_entry(&ckvs,key,&mr.auth_key,&entry_out); 
    if(err != ERR_NONE){
        ckvs_close(&ckvs);
        if(set_value != NULL){
            free(set_value);
        }
        return err;
    }

    // end of shared code of get and set

    if(set_value == NULL) { 
        // case it's a get

        // check if there is no associated value *****
        if(entry_out->value_len == 0 && entry_out->value_off == 0){
            ckvs_close(&ckvs);
            return ERR_NO_VALUE;
        }
        // we compute the masterkey
        err= ckvs_client_compute_masterkey(&mr, &(entry_out->c2) ); 
        if(err != ERR_NONE){
            ckvs_close(&ckvs);
            return err;
        }

        // we decrypt
        size_t inbufLen = entry_out->value_len; 
        size_t outpufBufLen = 0;
       // unsigned char output[MAX_VALUE_LENGTH+EVP_MAX_BLOCK_LENGTH];
        unsigned char* output = NULL;
        output = malloc(inbufLen+EVP_MAX_BLOCK_LENGTH);
        unsigned char* input=NULL;
        input = malloc(inbufLen);
        if(output == NULL || input == NULL){
            ckvs_close(&ckvs);
            return ERR_OUT_OF_MEMORY;
        }

        if ( fseek(ckvs.file,(long)entry_out->value_off, SEEK_SET) != 0){
            ckvs_close(&ckvs);
            free(output);
            free(input);
            return ERR_IO;
        }

        if(fread(input, sizeof(char), inbufLen, ckvs.file) != inbufLen ){
            ckvs_close(&ckvs);
            free(output);
            free(input);
            return ERR_IO;
        }

        err= ckvs_client_crypt_value(&mr,0,input ,inbufLen,output,&outpufBufLen); 
        if(err != ERR_NONE){
            ckvs_close(&ckvs);
            free(output);
            free(input);
            return err;
        }
        pps_printf("%s", output);
        // end of decryption
        free(output);
        free(input);
        //end of case it's a get
    }else{
    // case it's a set 

        //compute c2
        if(RAND_bytes(entry_out->c2.sha, SHA256_DIGEST_LENGTH) != 1){
            ckvs_close(&ckvs);
            free(set_value); 
            return ERR_IO;
        }
        // we compute the masterkey
        err= ckvs_client_compute_masterkey(&mr, &(entry_out->c2) ); 
            if(err != ERR_NONE){
                free(set_value);                 
                ckvs_close(&ckvs);
                return err;
            }

        // we encrypt
        size_t inbufLen= strlen(set_value);
        size_t outpufBufLen=0;
        //unsigned char output[MAX_VALUE_LENGTH+EVP_MAX_BLOCK_LENGTH]={0};
        unsigned char* output = NULL;
        output = malloc(inbufLen+EVP_MAX_BLOCK_LENGTH);
        if(output ==  NULL){
            free(set_value);                 
            ckvs_close(&ckvs);
            return ERR_OUT_OF_MEMORY;
        }
        err= ckvs_client_crypt_value(&mr,1,set_value ,inbufLen+1,output,&outpufBufLen); 
        if(err != ERR_NONE){
            free(set_value);
            ckvs_close(&ckvs);
            free(output);
            return err;
        }
        // end of encryption

        //write the encrypted value in the file
        err= ckvs_write_encrypted_value(&ckvs,entry_out,output,outpufBufLen);
        if(err != ERR_NONE){
            ckvs_close(&ckvs);
            free(set_value);
            free(output);
            return err;
        }
        
        free(output);
        
        free(set_value);
        
        set_value=NULL;
        //end of the case it's a set
    }

    //shared code get and set
    ckvs_close(&ckvs); // close file
    
    return ERR_NONE;
    //end of shared get and set
}

/**
 * @brief Opens the CKVS database at the given filename and executes the 'new' command,
 * ie. creates a new entry with the given key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments to take 
 * @param optagrv (char* []) arguments to the command
 * @return int, an error code
 */
int ckvs_local_new(const char* filename, int optargc, char* optargv[])
{
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(optargv);

    if( optargc < NUMBER_ARG_GET_NEW) 
        return ERR_NOT_ENOUGH_ARGUMENTS;
    if( optargc > NUMBER_ARG_GET_NEW) 
        return ERR_TOO_MANY_ARGUMENTS;

    const char * key = optargv[0];
    const char * pwd = optargv[1];

    CKVS_t ckvs;
    ckvs_memrecord_t mr;
    memset(&mr,0 ,sizeof(ckvs_memrecord_t)); // initialise mr. (ckvs_open initialises ckvs, so no need)

    error_code err = ckvs_open(filename,&ckvs); // open file
     // checking if there was a problem reading
    if(err != ERR_NONE){
        ckvs_close(&ckvs); 
        return err;
    }

     // generate stretched, auth_key and c1
    err=ckvs_client_encrypt_pwd(&mr,key,pwd);  
    if(err != ERR_NONE){
        ckvs_close(&ckvs); 
        return err;
    }

    //create new entry
    ckvs_entry_t* entry_out=NULL;
    err = ckvs_new_entry(&ckvs,key,&mr.auth_key,&entry_out);
    ckvs_close(&ckvs); 

    return err;
}

