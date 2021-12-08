#include <iostream>

#include "openssl/evp.h"
#include "openssl/ts.h"

TS_REQ* get_timestamp_request(char* hash, int hash_size, ASN1_INTEGER *nonce_asn1)
{
    int ret = 0;
    TS_REQ *ts_req = NULL;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    unsigned char *data = NULL;
    ASN1_OBJECT *policy_obj = NULL;
    const EVP_MD* md = NULL;

    /* Setting default message digest. */
    if ((md = EVP_get_digestbyname("sha256")) == NULL)
    {
        goto err;
    }

    /* Creating request object. */
    if ((ts_req = TS_REQ_new()) == NULL)
    {
        goto err;
    }

    /* Setting version. */
    if (!TS_REQ_set_version(ts_req, 1)) goto err;

    /* Creating and adding MSG_IMPRINT object. */
    if ((msg_imprint = TS_MSG_IMPRINT_new()) == NULL)
    {
        goto err;
    }

    /* Adding algorithm. */
    if ((algo = X509_ALGOR_new()) == NULL)
    {
        goto err;
    }

    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
    {
        goto err;
    }
    algo->parameter->type = V_ASN1_NULL;
    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, algo)) goto err;

    /* Adding message digest. */
    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)hash, hash_size)) goto err;

    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint)) goto err;

    /* Setting policy if requested. */
    if ((policy_obj = OBJ_txt2obj("1.1.3", 0)) == NULL)
    {
        goto err;
    }
    if (policy_obj && !TS_REQ_set_policy_id(ts_req, policy_obj)) goto err;

    /* Setting nonce if requested. */
    if (nonce_asn1 && !TS_REQ_set_nonce(ts_req, nonce_asn1)) goto err;

    /* Setting certificate request flag if requested. */
    if (!TS_REQ_set_cert_req(ts_req, 1)) goto err;

    ret = 1;
    err:
    if (!ret)
    {
        TS_REQ_free(ts_req);
        ts_req = NULL;
    }
    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    OPENSSL_free(data);
    ASN1_OBJECT_free(policy_obj);
    return ts_req;
}

int main() {

    TS_MSG_IMPRINT *msg_imprint = NULL;
    char a[16];
    TS_REQ *ad = NULL;
    ad = get_timestamp_request(a, 16, reinterpret_cast<ASN1_INTEGER *>(1));

    return 0;
}
