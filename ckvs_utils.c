
/**
 * @file ckvs_utils.c
 * @brief binary-to-hexadedimal conversion routines
 *
 * Utilities to convert binary data into printable hexadecimal format and back.
 *
 */
#include "ckvs.h"
#include <limits.h>
#include <openssl/sha.h>
#include "util.h" 
#include "ckvs_utils.h"
#include <stdlib.h>


/**
 * @brief Prints the given entry to the standard output!
 *
 * @param entry (const struct ckvs_entry*) the entry to print
 */
void print_entry(const struct ckvs_entry* entry){
    if (entry == NULL ) { // Safety protection
        return ;
    }  

    pps_printf("    Key   : "  STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", entry->key );
    pps_printf("    Value : off %lu len %lu\n", entry->value_off, entry->value_len);
    pps_printf("   ");
    print_SHA(" Auth  ",&(entry->auth_key) );
    
    pps_printf("   ");
    print_SHA(" C2    ",&(entry->c2) );
    

}

/**
 * @brief Prints the given header to the standard output,
 *
 * @param header (const struct ckvs_header*) the header to print
 */
void print_header(const struct ckvs_header* header){
    if (header == NULL ) { // Safety protection
        return ;
    }   

    
    char const * head_intro = "CKVS Header";
    pps_printf("%s %-11s: %s\n", head_intro, "type", header->header_string);
    pps_printf("%s %-11s: %d\n", head_intro, "version", header->version);
    pps_printf("%s %-11s: %d\n", head_intro, "table_size", header->table_size);
    pps_printf("%s %-11s: %d\n", head_intro, "threshold", header->threshold_entries);
    pps_printf("%s %-11s: %d\n", head_intro, "num_entries", header->num_entries);
}


/**
 * @brief Prints the given prefix and SHA (hex-encoded) to the standard output.
 *
 * @param prefix (const char*) the prefix to prepend to the SHA
 * @param sha (const struct ckvs_sha*) the SHA to print
 */
void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    if (sha == NULL || prefix == NULL) { // Safety protection
        return ;
    }
    char buffer[SHA256_PRINTED_STRLEN] = {0}; 
    SHA256_to_string(sha,buffer);
    pps_printf("%-5s: %s\n", prefix, buffer); 

    
}

/**
 * @brief Encodes a ckvs_sha into its printable hex-encoded representation.
 *
 * @param sha (const struct ckvs_sha*) pointer to the input hash
 * @param buf (char*) pointer to the char buffer,
 * assumed to be large enough to store the full representation (+ a null byte)
 *
 * @see SHA256_from_string for the inverse operation
 */
void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    if (sha == NULL || buf == NULL) { // Safety protection
        return ;
    }       
    hex_encode(sha->sha,SHA256_DIGEST_LENGTH,buf);
}


/**
 * @brief Encodes a byte array into a printable hex-encoded string.
 *
 * @param in (const uint8_t*) pointer to the input byte buffer
 * @param len (size_t) length of the input byte buffer
 * @param buf (char*) pointer to the output char buffer,
 * assumed to be large enough to store the full representation (+ a null byte)
 *
 * @see hex_decode for the inverse operation
 */
void hex_encode(const uint8_t *in, size_t len, char *buf){
    if (in == NULL || buf == NULL) { // Safety protection
        return ;
    }  
    
    for (size_t i = 0; i < len ; ++i) {
        sprintf(&buf[i*2],"%02x",in[i]);
    }
}

/**
 * @brief Compares two SHA.
 *
 * @param a (const struct ckvs_sha*) the first SHA to compare
 * @param b (const struct ckvs_sha*) the second SHA to compare
 * @return int, a negative value if a < b ;
 * 0 if a == b ;
 * and a positive value if a > b.
 */
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    return memcmp(a,b, sizeof(ckvs_sha_t));
}

/**
 * @brief Decodes a printable hex-encoded string into the corresponding value in a byte array.
 *
 * @param in (const char*) pointer to the input char array
 * @param buf (uint8_t*) pointer to the output byte buffer,
 * assumed to be large enough to store the decoded value.
 * @return int, the number of written bytes, or -1 in case of error
 *
 * @see hex_encode for the inverse operation
 */
int hex_decode(const char *in, uint8_t *buf){
    if(in == NULL || buf == NULL){
        return -1;
    }

    int len_in = strlen(in);
    int ret = len_in/2;
    int j =0; 
    uint8_t buff =0;


    char* nptr = calloc(3 ,sizeof(char));
    nptr[2]= "Z";

    if(len_in %2 != 0){
        strncpy(nptr,in,2);
        nptr[1] = nptr[0];
        strncpy(nptr,"0",1);
        ret = ret+1;
        buf[j] = strtoul(nptr,NULL,16);
        j = 1;
    }

    for (size_t i = j; i < ret ; ++i) {
        if(j==0){
            strncpy(nptr,(in +i*2),2);
        }else{
            strncpy(nptr,(in+j +(i-1)*2),2);
        }
        buff = strtoul(nptr,NULL,16);
        if(buff == ULONG_MAX){
            free(nptr);
            return -1;
        }
        buf[i] = buff;
    }

    free(nptr);
    return ret;
}

/**
 * @brief Decodes a ckvs_sha from its printable hex-encoded representation.
 *
 * @param in (const char*) pointer to the char buffer
 * @param sha (struct ckvs_sha*) pointer to the output hash
 * @return int, the number of written bytes, or -1 in case of error
 *
 * @see SHA256_to_string for the inverse operation
 */
int SHA256_from_string(const char *in, struct ckvs_sha *sha){
    M_REQUIRE_NON_NULL(sha);
    M_REQUIRE_NON_NULL(in);

    return hex_decode(in,sha->sha);

}