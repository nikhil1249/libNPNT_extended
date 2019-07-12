#ifdef __cplusplus
extern "C" {
#endif

#include <npnt.h>
#include <inc/npnt_internal.h>

#ifdef RFM_USE_WOLFSSL
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/pem.h>
#else
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#endif

static SHA_CTX sha;
static SHA256_CTX sha256;

void reset_sha1()
{
    SHA1_Init(&sha);
}

void update_sha1(const char* data, uint16_t data_len)
{
    SHA1_Update(&sha, data, data_len);
}

void final_sha1(char* hash)
{
    SHA1_Final((unsigned char*)hash, &sha);
}

void reset_sha256()
{
    SHA256_Init(&sha256);
}

void update_sha256(const char* data, uint16_t data_len)
{
    SHA256_Update(&sha256,data,data_len);
}

void final_sha256(char* hash)
{
    SHA256_Final((unsigned char*)hash, &sha256);
}


#ifdef RFM_USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
static RsaKey         rsaKey;
static RsaKey*        pRsaKey = NULL;
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, uint8_t* signature, uint16_t signature_len)
{
    int ret = 0;

    if (pRsaKey == NULL) {
        /* Initialize the RSA key and decode the DER encoded public key. */
        FILE *fp = fopen("dgca_pubkey.pem", "r");
        if (fp == NULL) {
            return -1;
        }
        fseek(fp, 0L, SEEK_END);
        uint32_t sz = ftell(fp);
        rewind(fp);
        if (sz == 0) {
            return -1;
        }
        uint8_t *filebuf = (uint8_t*)malloc(sz);
        if (filebuf == NULL) {
            return -1;
        }
        uint32_t idx = 0;
        DerBuffer* converted = NULL;

        fread(filebuf, 1, sz, fp);
        ret = wc_PemToDer(filebuf, sz, PUBLICKEY_TYPE, &converted, 0, NULL, NULL);

        if (ret == 0) {
            ret = wc_InitRsaKey(&rsaKey, 0);
        }
        if (ret == 0) {
            ret = wc_RsaPublicKeyDecode(converted->buffer, &idx, &rsaKey, converted->length);
        }
        if (ret == 0) {
            pRsaKey = &rsaKey;
        }
        free(filebuf);
        close(fp);
    }

    if (ret < 0) {
        return -1;
    }
    uint8_t* decSig = NULL;
    uint32_t decSigLen = 0;
    /* Verify the signature by decrypting the value. */
    if (ret == 0) {
        decSigLen = wc_RsaSSL_VerifyInline(signature, signature_len,
                                           &decSig, pRsaKey);
        if ((int)decSigLen < 0) {
            ret = (int)decSigLen;
        }
    }

    /* Check the decrypted result matches the encoded digest. */
    if (ret == 0 && decSigLen != raw_data_len)
        ret = -1;
    if (ret == 0 && XMEMCMP(raw_data, decSig, decSigLen) != 0)
        ret = -1;

    return ret;
}
#else
static EVP_PKEY *dgca_pkey = NULL;
static EVP_PKEY_CTX *dgca_pkey_ctx;
int8_t npnt_check_authenticity(npnt_s *handle, uint8_t* raw_data, uint16_t raw_data_len, const uint8_t* signature, uint16_t signature_len)
{
    if (!handle || !raw_data || !signature) {
        return -1;
    }
    if (dgca_pkey == NULL) {
        FILE *fp = fopen("dgca_pubkey.pem", "r");
        if (fp == NULL) {
            return -1;
        }
        dgca_pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }
    dgca_pkey_ctx = EVP_PKEY_CTX_new(dgca_pkey, ENGINE_get_default_RSA());
    if (!dgca_pkey_ctx) {
        return -1;
    }
    int ret = 0;
    if (EVP_PKEY_verify_init(dgca_pkey_ctx) <= 0) {
        ret = -1;
        goto fail;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(dgca_pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
        ret = -1;
        goto fail;
    }
    if (EVP_PKEY_CTX_set_signature_md(dgca_pkey_ctx, EVP_sha256()) <= 0) {
        ret = -1;
        goto fail;
    }

    /* Perform operation */
    ret = EVP_PKEY_verify(dgca_pkey_ctx, signature, signature_len, raw_data, raw_data_len);

fail:
    EVP_PKEY_CTX_free(dgca_pkey_ctx);
    return ret;
}
bool npnt_checkpilotpin(char *saltedpin, char *digest_output)
{
    uint16_t outlen = 0;
    RSA *rsa_key = RSA_new();
    unsigned char *decrypted_salted_pin = NULL;

//    printf("Encrypted salted pin hash is :%s and it's length is: %d\n",saltedpin,strlen(saltedpin));
    FILE *fp = fopen("/root/PKI/Asteria/private.pem", "r");

    if(fp == NULL)
    {
        printf("Private key deosn't exist");
        return false;
    }

    PEM_read_RSAPrivateKey(fp,&rsa_key,NULL,NULL);

//    printf("Key size is:\n%d\n",RSA_size(rsa_key));
    fclose(fp);

    if(rsa_key == NULL)
    {
        return false;
    }

    uint8_t *sha_Data = base64_decode((uint8_t*)saltedpin,strlen((char*)saltedpin),&outlen);

    if(sha_Data == NULL)
    {
        RSA_free(rsa_key);
        return false;
    }
//    printf("sha_1 length is %d\n",outlen);

    decrypted_salted_pin = (unsigned char*)malloc(RSA_size(rsa_key));

//    printf("allocated size for rsa key %d",strlen((char*)decrypted_salted_pin));
    if(decrypted_salted_pin == NULL)
    {
        RSA_free(rsa_key);
        free(sha_Data);
        return false;
    }
    RSA_private_decrypt(RSA_size(rsa_key),(unsigned char*)sha_Data,decrypted_salted_pin,rsa_key,RSA_PKCS1_PADDING);

//    printf("Decrypted salted hash length is: %d\n",strlen((char*)decrypted_salted_pin));

    memcpy(digest_output,decrypted_salted_pin,32);

    free(sha_Data);
    free(decrypted_salted_pin);
    RSA_free(rsa_key);
    return true;
}

bool npnt_calculate_digest(char *output_digest,char *input_data,uint16_t length)
{
    reset_sha256();
    update_sha256(input_data,length);
    final_sha256(output_digest);
//    int i = 0;
//    for(i = 0;i < 32; i++)
//    {
//        printf("%x",output_digest[i]);
//    }
//    printf("\n");

    if(output_digest != NULL)
    {
        return true;
    }
    else
    {
        return false;
    }
}

#endif

#ifdef __cplusplus
}
#endif
