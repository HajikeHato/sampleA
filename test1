1つめ


#include <windows.h>
#include <wincrypt.h>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

int main()
{
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;

    // 証明書ストアを開く
    hStore = CertOpenSystemStore(NULL, L"MY");
    if (!hStore)
    {
        std::cout << "証明書ストアを開くのに失敗しました。\n";
        return 1;
    }

    // 証明書を検索する
    pCertContext = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ANY,
        NULL,
        NULL);
    
    if (!pCertContext)
    {
        std::cout << "証明書を検索できませんでした。\n";
        CertCloseStore(hStore, 0);
        return 1;
    }

    // 秘密鍵を取得する
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProv;
    DWORD dwKeySpec;
    BOOL result = CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hCryptProv, &dwKeySpec, NULL);
    if (!result)
    {
        std::cout << "秘密鍵の取得に失敗しました。\n";
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return 1;
    }

    // 秘密鍵の取得が成功した場合、ここで秘密鍵を使って何かを行うことができます。
    // ただし、秘密鍵の取り扱いには非常に慎重に注意してください。

    // メモリ解放
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return 0;
}

2つめ


#include <iostream>
#include <string>
#include <windows.h>
#include <wincrypt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define MY_CERT_STORE_NAME L"MY" // 証明書ストアの名前 (MYは個人用ストア)

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    ERR_free_strings();
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = SSLv23_method(); // Use SSLv23_method() for TLS 1.0, TLS 1.1, and TLS 1.2 compatibility

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Error creating SSL context." << std::endl;
    }

    return ctx;
}

void configure_context(SSL_CTX* ctx, EC_KEY* ec_key) {
    // Set the ECDSA private key in the SSL context
    if (SSL_CTX_use_PrivateKey(ctx, EVP_PKEY_new_EC_KEY(ec_key)) <= 0) {
        std::cerr << "Error setting private key in SSL context." << std::endl;
        return;
    }
}

PCCERT_CONTEXT get_certificate_from_store() {
    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pCertContext = NULL;

    hCertStore = CertOpenSystemStore(NULL, MY_CERT_STORE_NAME);
    if (!hCertStore) {
        std::cerr << "Error opening certificate store." << std::endl;
        return NULL;
    }

    // Find the first certificate in the store
    pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
    if (!pCertContext) {
        std::cerr << "Error finding certificate in store." << std::endl;
    }

    CertCloseStore(hCertStore, 0);
    return pCertContext;
}

EC_KEY* extract_ec_key_from_certificate(PCCERT_CONTEXT pCertContext) {
    EVP_PKEY* pkey = X509_get0_pubkey(pCertContext->pCertInfo->pCertInfo);
    if (!pkey) {
        std::cerr << "Error getting public key from certificate." << std::endl;
        return NULL;
    }

    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        std::cerr << "Error extracting EC_KEY from public key." << std::endl;
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return ec_key;
}

int main() {
    SSL_CTX* ctx;
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;

    init_openssl();
    ctx = create_context();

    PCCERT_CONTEXT pCertContext = get_certificate_from_store();
    if (!pCertContext) {
        std::cerr << "Error getting certificate from store." << std::endl;
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 1;
    }

    EC_KEY* ec_key = extract_ec_key_from_certificate(pCertContext);
    if (!ec_key) {
        CertFreeCertificateContext(pCertContext);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 1;
    }

    configure_context(ctx, ec_key);

    // Create and bind the server socket (similar to the previous example)
    // ...

    // Accept incoming connections and handle them (similar to the previous example)
    // ...

    SSL_CTX_free(ctx);
    EC_KEY_free(ec_key);
    CertFreeCertificateContext(pCertContext);
    cleanup_openssl();
    return 0;
}
