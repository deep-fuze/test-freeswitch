//
//  TlsCore.cpp
//  FuzeTransport
//
//  Created by Tim Na on 2/26/14.
//  Copyright (c) 2014 FuzeBox. All rights reserved.
//

#include <TlsCore.h>
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, log_ << log2_ << __FUZE_FUNC__ << ": " << B)

#include <openssl/bio.h>
#include <openssl/rand.h>
#include <sstream>

#ifndef DTLSv1_get_timeout    
#define NO_DTLS_SUPPORT
#endif

namespace {
    const uint8_t cert_data_1[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGWzCCBUOgAwIBAgIQCId7hO2oON7xQDobHtTtrzANBgkqhkiG9w0BAQsFADBw\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNz\n"
    "dXJhbmNlIFNlcnZlciBDQTAeFw0xNDEyMjIwMDAwMDBaFw0xODAzMjgxMjAwMDBa\n"
    "MG4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T\n"
    "YW4gRnJhbmNpc2NvMRYwFAYDVQQKEw1GdXplIEJveCBJbmMuMRowGAYDVQQDDBEq\n"
    "LmZ1emVtZWV0aW5nLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\n"
    "AJ+BX1qXF5dhJpX8YVqULc3+bEHC+KDa8/ssNdGwtpJBXy4ERhKXma5zUhCkodt6\n"
    "ZFW7Ii0oz4ZZq+L9DgdgyKOiCkzpQRLfcWZR3KE9z/YgQGWM+XQiT6IF2dblYbjk\n"
    "2awmxlsB4yohuKWrsOGU/q36xeDqdeSCQtXJVta5JiOEd0celReBzDmN8rT42oFz\n"
    "wmHdvGD32Jnvtu5z6C9ZsHDyuLPmjCtzSNdKoEr15YQ1B/N6kqSZhV4kimKwREZo\n"
    "pq/2V09Q21q5vfHQggO5Oza79+v3edFSj/iMiQWc/rjno8REWhbVsTaf+yVhFIEP\n"
    "LV9g9FoGatB72GTEj2mjoFyUUfwQYMG4DOXgIMJLmPDBgpHNkTTfXaXy52pE3jAz\n"
    "qd3abMJs0adznR84wvMcCNPYzbCBD1VjDEZ1QyoU9zAIPDL/J6L3SOV93jsjhING\n"
    "KRjHSqs3kuAZv+ij85pqMWcSY6NDFHsBoHPqmQ6e/ulFDzB4/B2WIS3JAZ6VaRZR\n"
    "ID7UOjNMSfTDIOPDjoMbI/eO2Yy30+RocxpMhAy6wGuSqlyBC1Gu1TvCuBoNow9N\n"
    "IFOF4ioWEqSmknUKhIgQSPCEyiq7r3ZoT+AuSxmtl5B0gD0yoQsGRnAYBPqHCCNP\n"
    "XRMdBoqg1AetiJL3hmw1ViYBQaI+sSD5yJ/27HTFpcaRAgMBAAGjggHxMIIB7TAf\n"
    "BgNVHSMEGDAWgBRRaP+QrwIHdTzM2WVkYqISuFlyOzAdBgNVHQ4EFgQUDNDkPkKq\n"
    "iRM2Ga7zemr7a1/CzqowLQYDVR0RBCYwJIIRKi5mdXplbWVldGluZy5jb22CD2Z1\n"
    "emVtZWV0aW5nLmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUH\n"
    "AwEGCCsGAQUFBwMCMHUGA1UdHwRuMGwwNKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2lj\n"
    "ZXJ0LmNvbS9zaGEyLWhhLXNlcnZlci1nMy5jcmwwNKAyoDCGLmh0dHA6Ly9jcmw0\n"
    "LmRpZ2ljZXJ0LmNvbS9zaGEyLWhhLXNlcnZlci1nMy5jcmwwQgYDVR0gBDswOTA3\n"
    "BglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu\n"
    "Y29tL0NQUzCBgwYIKwYBBQUHAQEEdzB1MCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz\n"
    "cC5kaWdpY2VydC5jb20wTQYIKwYBBQUHMAKGQWh0dHA6Ly9jYWNlcnRzLmRpZ2lj\n"
    "ZXJ0LmNvbS9EaWdpQ2VydFNIQTJIaWdoQXNzdXJhbmNlU2VydmVyQ0EuY3J0MAwG\n"
    "A1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGS4zxmzzTnPObrT0rHrsr+N\n"
    "+s2FjcETRUYCmH6/kHIcgeZdlag4MoyGoG7gpZxp1/ipFHMYxgdWn9O4bP/jUU9V\n"
    "N/9rOa6YKXf8JicmabXvxByZcEEH3HR1f+f47jyqK6p4lHrzttErVhxXUxkKykQW\n"
    "FR8f72yCxql/oMh+Tct5rYQ6Tq33Key30gFPlwAag9v8rYJs3OUMYlvD2Cw8DPYo\n"
    "C3azsk3N+UjLpn35K456+ISLL2UPBfOvBPZFLhU8oUfNcYE3BmGGqJ9619CCFT3d\n"
    "Cn+qqKVO7623jUfbD57Tk5I+15Fxr51cUffz0NSclk4oBCFqVyEk3vw03q/5qt8=\n"
    "-----END CERTIFICATE-----\n";
    
    const uint8_t cert_data_2[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
    "ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL\n"
    "MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\n"
    "LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy\n"
    "YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2\n"
    "4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC\n"
    "Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1\n"
    "itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn\n"
    "4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X\n"
    "sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft\n"
    "bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA\n"
    "MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\n"
    "NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy\n"
    "dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t\n"
    "L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG\n"
    "BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ\n"
    "UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D\n"
    "aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd\n"
    "aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH\n"
    "E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly\n"
    "/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu\n"
    "xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF\n"
    "0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae\n"
    "cPUeybQ=\n"
    "-----END CERTIFICATE-----\n";
    
    const uint8_t key_data[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "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\n"
    "-----END RSA PRIVATE KEY-----\n";
}

namespace fuze {

// TlsCore specific
SSL_CTX*  TlsCore::pTlsCtx_;
MutexLock TlsCore::ctxLock_;
    
char      TlsCore::fingerPrint_[EVP_MAX_MD_SIZE*3];
    
// DtlsCore specific
SSL_CTX*  DtlsCore::pDtlsCCtx_;
SSL_CTX*  DtlsCore::pDtlsSCtx_;
    
#ifdef COOKIE_ENABLED
int       DtlsCore::IDs_;
const int COOKIE_LEN = 16;
uint8_t   g_cookie_[COOKIE_LEN];
#endif
    
namespace
{
const int KEY_LENGTH           = 1024; // Strength of generated keys. Those are RSA.
const int SERIAL_RAND_BITS     = 64;   // Random bits for certificate serial number
const int CERTIFICATE_LIFETIME = 60*60*24*30*12*3; // 3 years, arbitrarily
const int CERTIFICATE_WINDOW   = -60*60*24;        // validity window.
}

EVP_PKEY* MakeKey()
{
    _MLOG_("Making key pair");
    EVP_PKEY* pkey = EVP_PKEY_new();
    // RSA_generate_key is deprecated. Use _ex version.
    BIGNUM* exponent = BN_new();
    RSA* rsa = RSA_new();
    if (!pkey || !exponent || !rsa ||
        !BN_set_word(exponent, 0x10001) ||  // 65537 RSA exponent
        !RSA_generate_key_ex(rsa, KEY_LENGTH, exponent, NULL) ||
        !EVP_PKEY_assign_RSA(pkey, rsa)) {
        EVP_PKEY_free(pkey);
        BN_free(exponent);
        RSA_free(rsa);
        return NULL;
    }
    // ownership of rsa struct was assigned, don't free it.
    BN_free(exponent);
    _MLOG_("Key pair created");
    return pkey;
}

// Generate a self-signed certificate, with the public key from the
// given key pair. Caller is responsible for freeing the returned object.
X509* MakeCertificate(EVP_PKEY* pkey)
{
    _MLOG_("Making Fuze certificate");
    X509* x509 = NULL;
    BIGNUM* serial_number = NULL;
    X509_NAME* name = NULL;
    
    if ((x509=X509_new()) == NULL)
        goto error;
    
    if (!X509_set_pubkey(x509, pkey))
        goto error;
    
    // serial number
    // temporary reference to serial number inside x509 struct
    ASN1_INTEGER* asn1_serial_number;
    if ((serial_number = BN_new()) == NULL ||
        !BN_pseudo_rand(serial_number, SERIAL_RAND_BITS, 0, 0) ||
        (asn1_serial_number = X509_get_serialNumber(x509)) == NULL ||
        !BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
        goto error;
    
    if (!X509_set_version(x509, 0L))  // version 1
        goto error;
    
    // There are a lot of possible components for the name entries. In
    // our P2P SSL mode however, the certificates are pre-exchanged
    // (through the secure XMPP channel), and so the certificate
    // identification is arbitrary. It can't be empty, so we set some
    // arbitrary common_name. Note that this certificate goes out in
    // clear during SSL negotiation, so there may be a privacy issue in
    // putting anything recognizable here.
    if ((name = X509_NAME_new()) == NULL ||
        !X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
                                    (unsigned char*)"Fuze", -1, -1, 0) ||
        !X509_set_subject_name(x509, name) ||
        !X509_set_issuer_name(x509, name))
        goto error;
    
    if (!X509_gmtime_adj(X509_get_notBefore(x509), CERTIFICATE_WINDOW) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), CERTIFICATE_LIFETIME))
        goto error;
    
    if (!X509_sign(x509, pkey, EVP_sha1()))
        goto error;
    
    BN_free(serial_number);
    X509_NAME_free(name);
    _MLOG_("Fuze certificate created");
    return x509;
    
error:
    BN_free(serial_number);
    X509_NAME_free(name);
    X509_free(x509);
    return NULL;
}
    
int ssl_verify_peer(int preverify_ok, X509_STORE_CTX* pCtx)
{
    // currently fuze transport uses self-signed certificate
    // which causes preverify_ok to be 0 at start
    if (preverify_ok == 0) {
        int err = X509_STORE_CTX_get_error(pCtx);
        int depth = X509_STORE_CTX_get_error_depth(pCtx);
        
        _MLOG_(X509_verify_cert_error_string(err) <<
               " (depth: " << depth << ")");
    }
    
    if (X509* p_cert = (pCtx ? X509_STORE_CTX_get_current_cert(pCtx) : 0)) {
        char subject[256];
        char issuer[256];
        X509_NAME_oneline(X509_get_subject_name(p_cert), subject, 256);
        X509_NAME_oneline(X509_get_issuer_name(p_cert), issuer, 256);
        _MLOG_("[" << subject << "] (Issuer: " << issuer << ")");
    }
    else {
        _WLOG_("No certificate from peer");
    }
    
    return 1; // return 1 to proceed for now
}

#ifdef COOKIE_ENABLED
// Generate cookie. Returns 1 on success, 0 otherwise
int generate_cookie(SSL* pSSL, unsigned char* cookie, unsigned int* cookie_len)
{
    char     buf[32];
    uint32_t buf_len = 0;
    uint8_t  result[EVP_MAX_MD_SIZE];
    uint32_t result_len = 0;
    
    DtlsCore* p = (DtlsCore*)SSL_get_ex_data(pSSL, 0);
    
    sprintf(buf, "%d", p->cookieID_);
    buf_len = strlen(buf);
    
    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), g_cookie_, COOKIE_LEN, (uint8_t*)buf, buf_len, result, &result_len);
    memcpy(cookie, result, result_len);
    
    _MLOG_(p->log_ << p->log2_ << "cookie generated with ID " << p->cookieID_ <<
          " (cookie len: " << result_len << ", buf len: " << *cookie_len << ")");
    
    *cookie_len = result_len;
    
    return 1;
}
                    
// Verify cookie. Returns 1 on success, 0 otherwise
int verify_cookie(SSL* pSSL, unsigned char* cookie, unsigned int cookie_len)
{
    char     buf[32];
    uint32_t buf_len = 0;
    uint8_t  result[EVP_MAX_MD_SIZE];
    uint32_t result_len = 0;
    
    DtlsCore* p = (DtlsCore*)SSL_get_ex_data(pSSL, 0);
    
    sprintf(buf, "%d", p->cookieID_);
    buf_len = strlen(buf);
    
    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), g_cookie_, COOKIE_LEN, (uint8_t*)buf, buf_len, result, &result_len);
    
    int matched = 0;

    if (cookie_len == result_len && memcmp(result, cookie, result_len) == 0) {
        _MLOG_(p->log_ << p->log2_ << "cookie " << p->cookieID_ << " matched");
        matched = 1;
    }
    else {
        _ELOG_(p->log_ << p->log2_ << "cookie " << p->cookieID_ << " mismatched");
    }
    
    return matched;
}
#endif

void ssl_state(const SSL* pSSL, int type, int val)
{
    std::ostringstream log;

    if (type & SSL_ST_CONNECT) log << "CONNECT";
    if (type & SSL_ST_ACCEPT) log << "ACCEPT";
    if (type & SSL_CB_LOOP) log << " LOOP";
    if (type & SSL_CB_EXIT) log << " EXIT";
    if (type & SSL_CB_HANDSHAKE_START) log << "HANDSHAKE START";
    if (type & SSL_CB_HANDSHAKE_DONE) log << "HANDSHAKE STOP";

    TlsCore* p = (TlsCore*)SSL_get_ex_data(pSSL, 0);
    
    _MLOG_(p->log_ << p->log2_ << SSL_state_string_long(pSSL) <<
          " (" << log.str() << " [0x" << Hex(type) << "], val: " << val << ")");
}
    
TlsCore::TlsCore(TlsCoreUser& rUser, bool bServer)
    : rCoreUser_(rUser)
    , bServer_(bServer)
    , pSSL_(0)
    , pBioSSL_(0)
    , pWrapSSL_(0)
    , pBioIO_(0)
{
    log_[0] = 0;
 
    strcpy(log2_, (bServer_ ? "TLS_S " : "TLS_C "));
}
    
void TlsCore::Init()
{
    InitSSL();
    
    SSL_set_info_callback(pSSL_, ssl_state);
    SSL_set_ex_data(pSSL_, 0, this);
    
    // From test example in openssl but following link that explains it more
    // https://stackoverflow.com/questions/9030661/openssl-perform-en-decryption-without-ssl-read-ssl-write
    //
    if (!BIO_new_bio_pair(&pWrapSSL_, TLS_BUF_SIZE, &pBioIO_, TLS_BUF_SIZE)) {
        ELOG("failed to create bio pair");
    }
    
    pBioSSL_ = BIO_new(BIO_f_ssl());
    if (!pBioSSL_) {
        ELOG("failed BIO_new(BIO_f_ssl)");
        return;
    }
    
    if (bServer_ == false) {
        SSL_set_connect_state(pSSL_);
    }
    else {
        SSL_set_accept_state(pSSL_);
    }
    
    SSL_set_bio(pSSL_, pWrapSSL_, pWrapSSL_);
    BIO_set_ssl(pBioSSL_, pSSL_, BIO_NOCLOSE);
    
    // if we are connect state (client) trigger the SSL
    // to start handlshake
    if (bServer_ == false) {
        char buf = 0;
        int r = BIO_write(pBioSSL_, &buf, 1);
        if (r < 0) {
            if (!BIO_should_retry(pBioSSL_)) {
                ELOG("TlsCore ctor failed on BIO_write");
            }
        }
        else {
            ELOG("Unexpected sequence of SSL start");
        }
    }
}

TlsCore::~TlsCore()
{
    if (pWrapSSL_) BIO_free(pWrapSSL_);
    if (pBioSSL_)  BIO_free(pBioSSL_);
    if (pBioIO_)   BIO_free(pBioIO_);
    if (pSSL_)     SSL_free(pSSL_);
    
    // don't delete global structures
}

void TlsCore::InitSSL()
{
    MLOG("Initialize TLS " << (bServer_ ? "Server" : "Client"));
    
    if (!pTlsCtx_) {
        MutexLock scoped(&ctxLock_);
        if (!pTlsCtx_) {
            SSL_CTX* p_ctx = SSL_CTX_new(SSLv23_method());
            SSL_CTX_set_options(p_ctx, SSL_OP_NO_SSLv3);
            InitCertificate(p_ctx);
            // prevent 0.1 percent failure case in double lock
            pTlsCtx_ = p_ctx;
        }
    }
    
    pSSL_ = SSL_new(pTlsCtx_);
    
    // Verify server certificate in client side
    if (!bServer_) {
        SSL_set_verify(pSSL_, SSL_VERIFY_PEER, ssl_verify_peer);
    }
}

void TlsCore::InitCertificate(SSL_CTX* pCtx, bool makeCerticate)
{
    _MLOG_("Openssl version: " << SSLeay_version(SSLEAY_VERSION));
    
    if (makeCerticate) {
        static EVP_PKEY* sp_pkey = MakeKey();
        static X509*     sp_cert = MakeCertificate(sp_pkey);
        
        SSL_CTX_use_certificate(pCtx, sp_cert);
        SSL_CTX_use_PrivateKey(pCtx, sp_pkey);
        
        if (fingerPrint_[0] == 0) {
            uint8_t  md[EVP_MAX_MD_SIZE];
            uint32_t md_len = 0;
            
            // set fingerprint
            X509_digest(sp_cert, EVP_sha256(), md, &md_len);
            char hex[3] = {};
            int  index  = 0;
            for(uint32_t i = 0; i < md_len; i++) {
                sprintf(hex, "%02X", md[i]);
                fingerPrint_[index++] = hex[0];
                fingerPrint_[index++] = hex[1];
                if (i < md_len-1) fingerPrint_[index++] = ':';
            }
            fingerPrint_[index] = '\0';
            
            _MLOG_("Certificate Fingerprint (" << md_len << "B): " << fingerPrint_);
        }
        
#ifdef COOKIE_ENABLED
        // certificate is initialize once only
        // initialize cookie here as well
        if (memcmp(g_cookie_, 0, COOKIE_LEN) == 0) {
            if (!RAND_bytes(g_cookie_, COOKIE_LEN)) {
                _ELOG_("error setting random cookie secret\n");
            }
        }
#endif
    }
    else {
        BIO*  pBioCert1_ = BIO_new_mem_buf((void*)cert_data_1, -1);
        X509* pCert1_    = PEM_read_bio_X509(pBioCert1_, NULL, 0, NULL);
        BIO*  pBioCert2_ = BIO_new_mem_buf((void*)cert_data_2, -1);
        X509* pCert2_    = PEM_read_bio_X509(pBioCert2_, NULL, 0, NULL);
        BIO*  pBioKey_   = BIO_new_mem_buf((void*)key_data, -1);
        RSA*  pRSA_      = PEM_read_bio_RSAPrivateKey(pBioKey_, NULL, 0, NULL);
        
        // https://www.openssl.org/docs/ssl/SSL_CTX_add_extra_chain_cert.html
        // The x509 certificate provided to SSL_CTX_add_extra_chain_cert()
        // will be freed by the library when the SSL_CTX is destroyed.
        // An application should not free the x509 object.
        SSL_CTX_use_certificate(pCtx, pCert1_);
        SSL_CTX_add_extra_chain_cert(pCtx, pCert2_);
        SSL_CTX_use_RSAPrivateKey(pCtx, pRSA_);
        
        if (!SSL_CTX_check_private_key(pCtx)) {
            _ELOG_("Invalid private key!");
        }
    }
}
    
void TlsCore::TriggerHandshake()
{
    // we don't feed any data when we send handshake
    ProcessData(0, 0, PT_ENCRYPT);
}

bool TlsCore::IsInHandshake()
{
    return (SSL_is_init_finished(pSSL_) == false);
}

const char* TlsCore::GetVersion()
{
    const char* p = "NO SSL!";
    
    if (pSSL_) {
        p = SSL_get_version(pSSL_);
    }
    
    return p;
}
    
uint32_t TlsCore::ProcessData(uint8_t* pData, uint32_t dataLen, ProcessType type)
{
    BIO* p_in_bio  = (type == PT_ENCRYPT ? pBioSSL_ : pBioIO_);
    BIO* p_out_bio = (type == PT_ENCRYPT ? pBioIO_  : pBioSSL_);
    
    const char* p_type_str = (type == PT_ENCRYPT ? "encrypt"  : "decrypt");
    
    uint32_t write_done = 0;
    bool     loop_again = false;
    
    const int MAX_COUNT = 1000; // this should be plenty
    int counter = MAX_COUNT;
    
    do {
        loop_again = false;
        
        // first check if we have data to write into input BIO
        if (write_done < dataLen) {
            int write_pending = (int)BIO_ctrl_get_write_guarantee(p_in_bio);
            if (write_pending > 0) {
                int writing = dataLen - write_done;
                if (writing > write_pending) {
                    MLOG("Reducing writing byte as write_guarantee is lower: " <<
                         writing << "B -> write_pending: " << write_pending << "B");                         
                    writing = write_pending;
                }
                
                int written = BIO_write(p_in_bio,
                                        pData + write_done,
                                        writing);
                if (written < 0) {
                    if (!BIO_should_retry(p_in_bio)) {
                        ELOG("BIO_write error on " << p_type_str);
                        rCoreUser_.OnInternalError();
                        break;
                    }
                }
                else if (written == 0) {
                    ELOG("SSL Startup failed - BIO_write");
                    rCoreUser_.OnInternalError();
                    break;
                }
                else {
                    if (written != writing) {
                        WLOG("Wrote less than expected - written: " << written <<
                             "B vs writing: " << writing << "B");
                    }
                    write_done += written;
                    
                    if (write_done < dataLen) {
                        DLOG("We still have " << dataLen - write_done << "B to go");
                        loop_again = true;
                    }
                }
            }
            else {
                WLOG("No room in BIO input to " << p_type_str);
            }
        }
        
        // read from virtual IO and send it
        size_t read_pending = BIO_ctrl_pending(p_out_bio);
        
        if (read_pending > 0) {
            Buffer::Ptr sp_output = rCoreUser_.GetTlsBuffer((uint32_t)read_pending+1);
            uint8_t* p_buf    = sp_output->getBuf();
            uint32_t buf_size = sp_output->size()-1;
            
            int read = BIO_read(p_out_bio, p_buf, buf_size);
            if (read < 0) {
                if (!BIO_should_retry(p_out_bio)) {
                    MLOG("No BIO_read and No Retry " << p_type_str << " (flags:" <<
                          BIO_get_flags(p_out_bio) << ", read_pending: " << read_pending <<
                          ", read: " << read << ")");
                    // https://www.openssl.org/docs/crypto/BIO_read.html#
                    // A 0 or -1 return is not necessarily an indication of an error.
                    // In particular when the source/sink is non-blocking or of a
                    // certain type it may merely be an indication that no data is
                    // currently available and that the application should retry
                    // the operation later.
                }
                else {
                    loop_again = true;
                }
            }
            else if (read == 0) {
                WLOG("SSL BIO_read failure (alert or start fail)");
                rCoreUser_.OnInternalError();
                break;
            }
            else {
                p_buf[read] = 0;
                sp_output->setSize((uint32_t)read);

                DLOG("TLS " << p_type_str << "ed " << write_done << "B (" <<
                     dataLen - write_done << "B left) -> " <<
                     read << "B sent to " <<
                     (type == PT_ENCRYPT ? "far end" : "App"));
                
                if (type == PT_ENCRYPT) {
                    rCoreUser_.OnDataEncrypted(sp_output);
                }
                else {
                    rCoreUser_.OnDataDecrypted(sp_output);
                }
                
                loop_again = true;
            }
        }
        
        if (loop_again && (--counter == 0)) {
            ELOG("Infinite loop counter reached: " << MAX_COUNT);
            break;
        }
    }
    while (loop_again);
    
    return write_done;
}

DtlsCore::DtlsCore(TlsCoreUser& rUser, bool bServer)
    : TlsCore(rUser, bServer)
#ifdef COOKIE_ENABLED
    , cookieID_(0)
#endif
{
    strcpy(log2_, (bServer_ ? "DTLS_S " : "DTLS_C "));
}

const char* DtlsCore::GetFingerPrint()
{
    // if finger print is not ready then create one
    if (fingerPrint_[0] == 0) {
        if (!pDtlsSCtx_) {
            InitDtlsCertificate(pDtlsSCtx_, true);
        }
    }
    
    return fingerPrint_;
}

void DtlsCore::InitDtlsCertificate(SSL_CTX*& rpCtx, bool bServer)
{
    MutexLock scoped(&ctxLock_);
    
    // rpCtx could be set if some other thread accessed right before
    if (!rpCtx) {
        SSL_CTX* p_ctx = SSL_CTX_new(bServer ?
                                     DTLS_server_method() :
                                     DTLS_client_method());        
        if (EC_KEY* p_ecdh = EC_KEY_new_by_curve_name(NID_secp384r1)) {
            if (SSL_CTX_set_tmp_ecdh(p_ctx, p_ecdh) != 1) {
                _ELOG_("SSL_CTX_set_tmp_ecdh failed");
            }
            EC_KEY_free(p_ecdh);
        }
        else {
            _ELOG_("EC_KEY_new_by_curve_name failed");
        }
        
        SSL_CTX_set_cipher_list(p_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
        SSL_CTX_set_session_cache_mode(p_ctx, SSL_SESS_CACHE_OFF);
        
        // create dynamic certificate for DTLS
        InitCertificate(p_ctx, true);
        
        SSL_CTX_set_read_ahead(p_ctx, 1);
        
#ifdef DTLS_SRTP
        const char* p_pf = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";
        if (SSL_CTX_set_tlsext_use_srtp(p_ctx, p_pf) != 0) {
            _ELOG_("SSL_set_tlsext_use_srtp failed");
        }
#endif
        
#ifdef COOKIE_ENABLED
        if (bServer) {
            SSL_CTX_set_cookie_generate_cb(p_ctx, generate_cookie);
            SSL_CTX_set_cookie_verify_cb(p_ctx, verify_cookie);
        }
#endif
        rpCtx = p_ctx; // prevent 0.1 percent failure case in double lock
    }
}
    
void DtlsCore::InitSSL()
{
    MLOG("Initialize DTLS " << (bServer_ ? "Server" : "Client"));
    
    SSL_CTX*& rp_ctx = (bServer_ ? pDtlsSCtx_ : pDtlsCCtx_);

    if (!rp_ctx) {
        InitDtlsCertificate(rp_ctx, bServer_);
    }
    
    pSSL_ = SSL_new(rp_ctx);

    SSL_set_verify(pSSL_, SSL_VERIFY_PEER, ssl_verify_peer);
    SSL_set_verify_depth(pSSL_, 4);
    
#ifdef COOKIE_ENABLED
    // Enable cookie exchange for server
    if (bServer_) {
        SSL_set_options(pSSL_, SSL_OP_COOKIE_EXCHANGE);
        pSSL_->d1->listen = 1; // manually set ssl context
                               // without this retransmission logic won't work
    }
    
    // assign unique id for this DtlsCore instance for unique cookie
    MutexLock scoped(&ctxLock_);
    cookieID_ = IDs_++;
#endif
}
    
bool DtlsCore::GetTimeout(int32_t& rTimeout)
{
    bool bResult = false;

#ifndef NO_DTLS_SUPPORT   
    if (pSSL_) {
        timeval tm;
        // 0 : no time out is set
        // 1 : yes time out is set and value is returned
        if (DTLSv1_get_timeout(pSSL_, &tm) == 1) {
            rTimeout  = tm.tv_sec * 1000;
            rTimeout += tm.tv_usec / 1000;
            bResult = true;
        }
    }
#endif    
    return bResult;
}

bool DtlsCore::HandleTimeout()
{
    bool result = false;
    
#ifndef NO_DTLS_SUPPORT
    int ret = DTLSv1_handle_timeout(pSSL_);
    if (ret == -1) {
        ELOG("DTLSv1_handle_timeout error");
    }
    else {
        MLOG("DTLSv1_handle_timeout " << (ret ? "triggered" : "ignored"))
    }
    
    if ((ret == 1) && IsInHandshake()) {
        TriggerHandshake();
        result = true;
    }
#endif
    
    return result;
}
    
bool DtlsCore::ClientHelloVerified()
{
#ifndef NO_DTLS_SUPPORT
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    if (SSL_get_state(pSSL_) == TLS_ST_SW_SRVR_HELLO) {
        return true;
    }
#else
    if (pSSL_->d1->listen == 0 &&
        pSSL_->state == SSL3_ST_SW_SRVR_HELLO_A) {
        return true;
    }
#endif
#endif    
    return false;
}
 
#ifdef DTLS_SRTP
const char* DtlsCore::GetSelectSrtpProfile()
{
    const char* p_name = "";
    if (SRTP_PROTECTION_PROFILE* p = SSL_get_selected_srtp_profile(pSSL_)) {
        p_name = p->name;
    }
        
    return p_name;
}
    
bool DtlsCore::GetSrtpKeyMaterial(uint8_t* material)
{
    bool result = true;
    if (!SSL_export_keying_material(pSSL_, material, SRTP_M_LEN * 2,
                                    "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
        ELOG("Failed to extract srtp key material");
        result = false;
    }
    return result;
}
#endif
    
} // namespace fuze
