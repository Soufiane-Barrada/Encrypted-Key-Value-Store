/**
 * @file ckvs_io.c
 * @brief ckvs_io - IO operations for a local database
 */

#include <stdint.h> // for uint64_t
#include <stdbool.h>
#include "ckvs.h"
#include "ckvs_io.h"
#include <stdlib.h>

// PROTOTYPES of auxiliary methods:

/**
 * @brief checks if a number is a power of two
 *
 * @param n the number
 * @return true iff the number is a power of 2
 */
bool check_power_2(uint32_t n);

/**
 * @brief a utilatry function that rewrites the entry of ckvs at index idx
 * 
 * @param ckvs (struct CKVS *ckvs) the ckvs database
 * @param idx  (uint32_t) the index of the entry 
 * @return int, errot code
 */
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);

/**
 * @brief 
 * 
 * @param ckvs 
 * @param key 
 * @return uint32_t 
 */
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);


// END OF PROTOTYPES



/**
 * @brief Opens the CKVS database at filename.
 * Also checks that the database is valid
 *
 * @param filename (const char*) the path to the database to open
 * @param ckvs (struct CKVS*) the struct that will be initialized
 * @return int, error code
 */
int ckvs_open(const char *filename, struct CKVS *ckvs){
    
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);

    memset(ckvs,0, sizeof(struct CKVS)); //initialize the struct
    ckvs->file = NULL;
    ckvs->file = fopen(filename, "rb+");
    if (ckvs->file == NULL) 
    {
        return ERR_IO;
    
    }
    
    //Reading the header
    ckvs_header_t* header = &(ckvs->header);
    uint32_t tabHeader[4];// an array to put the 4 u_int32 values of the header 

    size_t nb_read_1 = fread(header, sizeof(char), CKVS_HEADERSTRINGLEN , ckvs->file);
    size_t nb_read_2 = fread( tabHeader, sizeof(uint32_t), 4, ckvs->file);
    if (nb_read_1 != CKVS_HEADERSTRINGLEN || nb_read_2 != 4)
    {
        ckvs_close(ckvs);  
        return ERR_IO;
    }

    //put the read values into the struct
    header->version = tabHeader[0];
    header->table_size = tabHeader[1];
    header->threshold_entries = tabHeader[2];
    header->num_entries = tabHeader[3];

    // checking if the header has correct format
    bool correct_head = (!strncmp(header->header_string, CKVS_HEADERSTRING_PREFIX,strlen(CKVS_HEADERSTRING_PREFIX))) && (header->version == CKVS_VERSION);
    bool correct_table_size = check_power_2(header->table_size);// 0 false, 1 true
    
    if (!(correct_head && correct_table_size))
    {
        ckvs_close(ckvs);
        return ERR_CORRUPT_STORE;
    }
    
    //creating the entries
    ckvs->entries = calloc(header->table_size, sizeof(ckvs_entry_t));
    if(ckvs->entries == NULL){
        ckvs_close(ckvs);
        return ERR_OUT_OF_MEMORY; 
    }
    
    // reading the entries
    size_t nb_entries = ckvs->header.table_size;
    if ( fread(ckvs->entries, sizeof(ckvs_entry_t), nb_entries, ckvs->file) != nb_entries )
    {
        ckvs_close(ckvs);
        return ERR_IO;
    }
    return ERR_NONE;
}
/**
 * @brief Closes the CKVS database and releases its resources.
 *
 * @param ckvs (struct CKVS*) the ckvs database to close
 */
void ckvs_close(struct CKVS *ckvs){
    if(ckvs == NULL ||ckvs->file == NULL) 
        return;
    
    fclose(ckvs->file);
    free(ckvs->entries);
    ckvs->entries = NULL;
    ckvs->file = NULL;
}

/**
 * @brief Finds the entry with the given (key, auth_key) pair in the ckvs database.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the entry
 * @param auth_key (const struct ckvs_sha*) the auth_key of the entry
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the entry if found.
 * @return int, error code
 */
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key
, struct ckvs_entry **e_out){


    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);
    
    bool found = false; // if key is in the table
    bool duplicate = false; // if auth_key doesn't correspond
    
    if(strlen(key) == 0){
        return ERR_KEY_NOT_FOUND;
    }

    uint32_t entry = ckvs_hashkey(ckvs,key);
    uint32_t loop_idx = 0;
    ckvs_entry_t * candidate_entry = NULL;
    while(loop_idx < ckvs->header.table_size && !found){

        uint32_t table_index = (loop_idx + entry) & (ckvs->header.table_size-1); 
        candidate_entry = &ckvs->entries[table_index];
            
        if(strncmp(candidate_entry->key, key, CKVS_MAXKEYLEN) == 0){ // if it's the corresponding key
            if(ckvs_cmp_sha(auth_key, &candidate_entry->auth_key) == 0){ 
                *e_out= candidate_entry;
            }else{
                duplicate=true; 
            }
            found =true;
        }
        loop_idx++;
    }
    
    if(duplicate){
        return ERR_DUPLICATE_ID;
    }
    if(!found){
        return ERR_KEY_NOT_FOUND;
    }

    return ERR_NONE;
}
/**
 * @brief Reads the file at filename, then allocates a buffer to dumps the file content into.
 * Not asked to students but helpful to have
 */
int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);

    FILE* file_to_read = fopen(filename, "rb"); //open file

    if(file_to_read == NULL){
        return ERR_IO; 
    }

    if(fseek(file_to_read, 0L,SEEK_END) != 0){
        fclose(file_to_read);        
        return ERR_IO;
    }
    

    long file_size = ftell(file_to_read); 
    if(file_size == -1){
        fclose(file_to_read);        
        return ERR_IO;
    }

    //allocating buffer memory 
    *buffer_ptr = calloc(file_size + 1, sizeof(char));
    if(*buffer_ptr == NULL){
        fclose(file_to_read);        
        return ERR_IO;
    } 
    *buffer_size = file_size + 1 ; 
    
    if(fseek(file_to_read, 0L,SEEK_SET) != 0){
        free(buffer_ptr);
        fclose(file_to_read);        
        return ERR_IO;
    } 
    size_t read_chars = fread(*buffer_ptr,sizeof(char), file_size,file_to_read);

    if(read_chars != file_size ){
        free(buffer_ptr);
        fclose(file_to_read);
        return ERR_IO;
    }

    fclose(file_to_read);
    return ERR_NONE;
}

/**
 * @brief Writes the already encrypted value at the end of the CKVS database,
 * then updates and overwrites the entry accordingly.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param e (struct ckvs_entry *e) the entry to which the secret belongs
 * @param buf (const unsigned char*) the encrypted value to write
 * @param buflen (uint64_t) the length of buf
 * @return int, error code
 */
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);

    // place the head of lecture at the end
    if(fseek(ckvs->file,0L,SEEK_END) != 0){
        return ERR_IO;
    }
    
    //store the beginning of where we will write (new valueoff)
    uint64_t new_valueOff = ftell(ckvs->file); 
    if(new_valueOff == -1){
        return ERR_IO;
    }
    // put the length of what was wrote in new value_len
    uint64_t new_valueLen = buflen; 
    
    uint64_t lenght_ok = fwrite(buf,sizeof(char),buflen,ckvs->file); //write
    if(lenght_ok != buflen){
        return ERR_IO;
    }
    
    //update the entry
    e->value_off = new_valueOff;
    e->value_len = new_valueLen;

    uint32_t idx = (e - (ckvs->entries)); // we compute the index of the element to be modified

    return ckvs_write_entry_to_disk(ckvs,idx);

}
/**
 * @brief Creates a new entry in ckvs with the given (key, auth_key) pair, if possible.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the new entry
 * @param auth_key (const struct ckvs_sha*) the auth_key of the new entry
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the created entry, if any.
 * @return int, error code
 */
int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);
    
    //testing the number of entries is according to the limit
    if(ckvs->header.num_entries == ckvs->header.threshold_entries){
        return ERR_MAX_FILES;
    }  
    //testing the key length
    if(strlen(key) > CKVS_MAXKEYLEN){
        return ERR_INVALID_ARGUMENT;
    }
    //testing if the key was already present in the table

    /**ckvs_entry_t dummy_out;
    memset(&dummy_out,0, sizeof(ckvs_entry_t));
    ckvs_entry_t * dummy_out_ptr = &dummy_out;*/
    ckvs_entry_t * dummy_out_ptr = NULL;

    error_code err = ckvs_find_entry(ckvs, key, auth_key, &dummy_out_ptr);
    if(err == ERR_NONE ||
     err == ERR_DUPLICATE_ID){
        return ERR_DUPLICATE_ID;
    }
    
    //creating the entry
    ckvs_entry_t new_entry;
    memset(&new_entry, 0, sizeof(ckvs_entry_t));
    strncpy(new_entry.key, key, CKVS_MAXKEYLEN);
    new_entry.auth_key = *auth_key ;

    uint32_t new_entry_idx = ckvs_hashkey(ckvs, key);
    //looking for the first empty index
    while(strcmp(ckvs->entries[new_entry_idx].key, "") != 0){
        new_entry_idx = (new_entry_idx+1)%ckvs->header.table_size;
    }
    // add the entry in ckvs *****
    ckvs->entries[new_entry_idx] = new_entry;
    *e_out = &ckvs->entries[new_entry_idx];

    error_code write_err = ckvs_write_entry_to_disk(ckvs, new_entry_idx);
    //******
    if( write_err != ERR_NONE){
        return write_err;
    }
    ckvs->header.num_entries++;
    
    //write the header in the file
    if(fseek(ckvs->file,0L,SEEK_SET) != 0){
        return ERR_IO;
    }
    size_t lenght_ok = fwrite(&(ckvs->header),sizeof(struct ckvs_header),1,ckvs->file);
    if(lenght_ok !=1){
        return ERR_IO;
    }


    return ERR_NONE; 
    
}
//-------------------------utilitary function definitions---------------------------
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key)
{
    char convert[SHA256_DIGEST_LENGTH];
    SHA256(key,strlen(key),convert);
    int32_t* res = convert;

    return *res & (ckvs->header.table_size-1);
}
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx){

    M_REQUIRE_NON_NULL(ckvs);

    // computing the offset
    long offset = sizeof(struct ckvs_entry)*idx + sizeof(struct ckvs_header);

    if(fseek(ckvs->file, offset, SEEK_SET) != 0){
        return ERR_IO;
    } 

    //write
    size_t lenght_ok = fwrite(&(ckvs->entries[idx]),sizeof(struct ckvs_entry),1,ckvs->file);
    if(lenght_ok !=1){
        return ERR_IO;
    }
    
    return ERR_NONE;
}

bool check_power_2(uint32_t n)
{
    for (uint32_t i = 0; i < 32; i++)
    {
        uint32_t mask = 1 << i;
        if ( mask == n){
            return true;
        }
    }
    return false;
}
