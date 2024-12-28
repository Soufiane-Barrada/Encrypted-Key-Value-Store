// ckvs_crypto

#include "ckvs.h"
#include "ckvs_crypto.h"
#include "ckvs_utils.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"

// -------- Prototypes for utilitary functions ----------
int generate_auth_c1(char* user_passphrase,ckvs_memrecord_t *mr);
int create_passPhrase( const char *key, const char *pwd, char** user_passphrase);
// End of Prototypes


int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd)
{
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    //initializing the struct
    memset(mr, 0, sizeof(ckvs_memrecord_t));

    char* user_passphrase = NULL;
    error_code err = create_passPhrase(key,pwd, &user_passphrase);
    if(err != ERR_NONE){
        free(user_passphrase);
        return err;
    }

    // Generate Auth_key and c1
    return generate_auth_c1(user_passphrase, mr);
}




int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}

int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2){
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);

    // generating masterkey
    unsigned int len;
    HMAC(EVP_sha256(), mr->c1.sha, SHA256_DIGEST_LENGTH, c2->sha, SHA256_DIGEST_LENGTH,  (mr->master_key).sha,&len); 

    if(len != SHA256_DIGEST_LENGTH) {
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;

}

// -------------------------------- Utilitary functions ---------------------------------------

int create_passPhrase( const char *key, const char *pwd, char** user_passphrase){
    *user_passphrase = calloc(strlen(key)+strlen(pwd)+2,sizeof(char));
    if(*user_passphrase == NULL){
        return ERR_OUT_OF_MEMORY;
    }
    strcat(*user_passphrase, key);
    strcat(*user_passphrase, "|");
    strcat(*user_passphrase, pwd);
    if(strlen(*user_passphrase) != strlen(key)+strlen(pwd) + 1){
        return ERR_INVALID_ARGUMENT;
    }
    return ERR_NONE;
}

int generate_auth_c1(char* user_passphrase,ckvs_memrecord_t *mr){

    unsigned int len1 = 0;    // where to put length of auth_key
    unsigned int len2 = 0;    // where to put length of c1
    SHA256(user_passphrase,strlen(user_passphrase),(mr->stretched_key).sha );
    free(user_passphrase);
    HMAC(EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH, AUTH_MESSAGE,strlen(AUTH_MESSAGE) ,(mr->auth_key).sha, &len1); 
    if(len1 != SHA256_DIGEST_LENGTH){
        return ERR_INVALID_COMMAND;
    }

    HMAC(EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH, C1_MESSAGE, strlen(C1_MESSAGE),(mr->c1).sha, &len2); 
    if( len2 != SHA256_DIGEST_LENGTH){
        return ERR_INVALID_COMMAND;
    }
    return ERR_NONE;
}
