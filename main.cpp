#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <jsmn/jsmn.h>
#include <mxml/mxml.h>
#include <inc/npnt_internal.h>
#include <stdbool.h>
#include <control_iface.h>
#include <QDir>

#include <QDebug>

static EC_KEY            *ecckey  = NULL;
static EVP_PKEY          *pkey   = NULL;
static EVP_PKEY          *permart_pkey = NULL;
static BIO               *outbio = NULL;
static npnt_s            npnt_handle;

void free_common()
{
    //Free up all structures
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(permart_pkey);
    EC_KEY_free(ecckey);
    BIO_free_all(outbio);
}

int16_t extract_public_key_from_xml_artefact()
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    QFile xmlFile("permissionArtifact.xml");

    if(!xmlFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        // qDebug() << "Unable to open the file";
        return -1;
    }

    QByteArray fileData = xmlFile.readAll();

    xmlFile.close();

    uint8_t *buffer;
    mxml_node_t *permart, *certificate;
    X509 *cert = NULL;
    BIO *cert_bio;

    buffer = (uint8_t*)fileData.data();

    permart = mxmlLoadString(NULL, (char*)buffer, MXML_OPAQUE_CALLBACK);

    if (permart == NULL)
    {
        // qDebug() << "Unable to load the xml file into buffer";
        return -1;
    }

    certificate = mxmlFindElement(permart, permart, "X509Certificate", NULL, NULL, MXML_DESCEND);
    if (certificate == NULL)
    {
        // qDebug() << "Failed to extract certificate node";
        return -1;
    }

    const char* cert_der = mxmlGetOpaque(certificate);
    if (cert_der == NULL)
    {
        mxmlDelete(certificate);
        // qDebug() << "Failed to extract certificate data";
        return -1;
    }

    cert_bio = BIO_new(BIO_s_mem());

    if(cert_bio == NULL)
    {
        mxmlDelete(certificate);
        return -1;
    }

    BIO_printf(cert_bio, "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n", cert_der);

    cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    if (cert == NULL)
    {
        BIO_free_all(cert_bio);
        mxmlDelete(certificate);
        // qDebug() << "Failed to load the certificate into memory";
        return -1;
    }

    permart_pkey = X509_get_pubkey(cert);
    if (permart_pkey == NULL)
    {
        BIO_free_all(cert_bio);
        mxmlDelete(certificate);
        X509_free(cert);
        // qDebug() << "Failed to load the public key from certificate";
        return -1;
    }

    FILE* pkey_fp = fopen("dgca_pubkey.pem", "w");

    if(pkey_fp == NULL)
    {
        // qDebug() << "DGC Public key is invalid";
    }

    PEM_write_PUBKEY(pkey_fp, permart_pkey);
    fclose(pkey_fp);

    BIO_free_all(cert_bio);
    mxmlDelete(certificate);
    X509_free(cert);

    return 0;
}

int16_t load_artifact()
{
    int16_t outlen;
    uint8_t *buffer = NULL;
    uint8_t *base64_permart = NULL;
    int16_t ret;

    FILE* artefact_xml = fopen("permissionArtifact.xml", "rb");
    //Get file length
    fseek(artefact_xml, 0, SEEK_END);
    int16_t file_len = ftell(artefact_xml);
    fseek(artefact_xml, 0, SEEK_SET);

    //allocate buffer
    buffer = (uint8_t *)malloc(file_len+1);
    if (buffer == NULL)
    {
        return -1;
    }
    //Read file contents into buffer
   fread(buffer, file_len, 1, artefact_xml);

   base64_permart = base64_encode(buffer, file_len, (uint16_t*)&outlen);

   if (base64_permart == NULL)
   {
        qDebug() << "Unable to convert the PA raw data to base64";
       return -1;
   }

    //set artifact
    npnt_init_handle(&npnt_handle);

    ret = npnt_set_permart(&npnt_handle, base64_permart, outlen);

    switch (ret)
    {
        case NPNT_INV_ART:
             qDebug() << "Invalid Artefact (Not as per guideline)";
            break;
        case 0:
             qDebug() << "Permission artefact is untouched and authenticated";
            break;
        default:
            break;
    }

    free(base64_permart);

    return ret;
}

int main()
{
    outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (extract_public_key_from_xml_artefact() < 0)
    {
        qDebug() << "Failed to extract Public Key from XML file...!!!";
    }

    load_artifact();

    free_common();

    return 0;
}
