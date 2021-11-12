
// https://stackoverflow.com/questions/57063250/can-i-create-openssl-ec-key-when-i-have-public-key-in-hex-format-using-c
void Example1()
{
    std::unique_ptr< ECDSA_SIG, std::function<void(ECDSA_SIG*)>> zSignature(ECDSA_SIG_new(), [](ECDSA_SIG* b) { ECDSA_SIG_free(b); });
    // Set up the signature... 
    BIGNUM* rr = NULL, * ss = NULL;

    std::string sSignatureR = "1B87DA77F29B7C891436B5477BFFBA919EDF42167F27EB525B94EB0A4D295FE8";
    std::string sSignatureS = "6E80B434A88D8609E63D3B2FA4E171C428CCAABEF84F5ECDB646E99AAE095983";

    BN_hex2bn(&rr, sSignatureR.c_str());
    BN_hex2bn(&ss, sSignatureS.c_str());

    ECDSA_SIG_set0(zSignature.get(), rr, ss);

    // Set up the public key.... 
    const char* sPubKeyString = "E3A7E51FE102286D071026111088F680761FDCD7031E3D56244BBE07451601E78AD08AD40EADCF380900985A1FAB94DE6D02DB91920F1144E9EBC4E248444969";

    char cx[65];
    BIGNUM* gx = NULL;
    BIGNUM* gy = NULL;

    std::unique_ptr< EC_KEY, std::function<void(EC_KEY*)>> zPublicKey(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), [](EC_KEY* b) { EC_KEY_free(b); });
    EC_KEY_set_asn1_flag(zPublicKey.get(), OPENSSL_EC_NAMED_CURVE);
    memcpy(cx, sPubKeyString, 64);
    cx[64] = 0;

    if (!BN_hex2bn(&gx, cx)) {
        std::cout << "Error getting to binary format" << std::endl;
    }

    if (!BN_hex2bn(&gy, &sPubKeyString[64])) {
        std::cout << "Error getting to binary format" << std::endl;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(zPublicKey.get(), gx, gy)) {
        std::cout << "setting public key attributes" << std::endl;
    }

    EC_KEY* pPubKey = zPublicKey.get();
    //PEM_read_bio_EC_PUBKEY(bo.get(), &pPubKey, NULL, NULL);


    if (EC_KEY_check_key(pPubKey) == 1)
    {
        printf("EC Key valid.\n");
    }
    else {
        printf("EC Key Invalid!\n");
    }

    std::string sRandomNumber = "bef2fc87919a11d8312dc118ece116b108377aa4d771b1c1e5aaed41b85d50"; //Message to sign (Given to arduino.....)

    std::string sHash;
    OpensslUtility::computeSHA256Hash(sRandomNumber, sHash);

    int iVerify = OpensslUtility::verify_signature((const unsigned char*)sHash.c_str(), zSignature.get(), pPubKey);

}



std::string OpensslUtility::HexToBytes(const std::string& hex)
{
    std::string bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

int OpensslUtility::verify_signature(const unsigned char* hash, const ECDSA_SIG* signature, EC_KEY* eckey)
{
    int verify_status = ECDSA_do_verify(hash, strlen((const char*)hash), signature, eckey);
    if (1 != verify_status)
    {
        printf("Failed to verify EC Signature\n");
        return -1;
    }

    printf("Verifed EC Signature\n");

    return 1;
}

std::string OpensslUtility::base64(const char* input, int length)
{
    std::unique_ptr< BIO, std::function<void(BIO*)>> b64(BIO_new(BIO_f_base64()), [](BIO* b) { BIO_free(b); });
    std::unique_ptr< BIO, std::function<void(BIO*)>> bmem(BIO_new(BIO_s_mem()), [](BIO* b) { BIO_free(b); });

    BUF_MEM* bptr;
    BIO* b64_ptr = b64.get();

    b64_ptr = BIO_push(b64.get(), bmem.get());
    BIO_write(b64_ptr, input, length);
    BIO_flush(b64_ptr);
    BIO_get_mem_ptr(b64_ptr, &bptr);

    std::unique_ptr< char, std::function<void(char*)>> buff((char*)malloc(bptr->length), [](char* b) { free(b); });

    memcpy(buff.get(), bptr->data, bptr->length - 1);
    buff.get()[bptr->length - 1] = 0;
    std::string sTo64(buff.get());

    return sTo64;
}


void Example2()
{
    std::unique_ptr< ECDSA_SIG, std::function<void(ECDSA_SIG*)>> zSignature(ECDSA_SIG_new(), [](ECDSA_SIG* b) { ECDSA_SIG_free(b); });
    // Set up the signature... 
    BIGNUM* rr = NULL, * ss = NULL;

    std::string sSignatureR = "1B87DA77F29B7C891436B5477BFFBA919EDF42167F27EB525B94EB0A4D295FE8";
    std::string sSignatureS = "6E80B434A88D8609E63D3B2FA4E171C428CCAABEF84F5ECDB646E99AAE095983";

    BN_hex2bn(&rr, sSignatureR.c_str());
    BN_hex2bn(&ss, sSignatureS.c_str());

    ECDSA_SIG_set0(zSignature.get(), rr, ss);

    // Set up the public key.... 
    const char* sPubKeyString = "E3A7E51FE102286D071026111088F680761FDCD7031E3D56244BBE07451601E78AD08AD40EADCF380900985A1FAB94DE6D02DB91920F1144E9EBC4E248444969";

    std::unique_ptr< EC_KEY, std::function<void(EC_KEY*)>> zPublicKey(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), [](EC_KEY* b) { EC_KEY_free(b); });
    EC_KEY_set_asn1_flag(zPublicKey.get(), OPENSSL_EC_NAMED_CURVE);

    EC_KEY* pPubKey = zPublicKey.get();


    std::string sKeyInAscii = OpensslUtility::HexToBytes(sPubKeyString);
    std::string sPub64(base64_encode(sKeyInAscii));
    std::string sKeyInPem = std::string("-----BEGIN PUBLIC KEY-----\n") + sPub64 + std::string("\n-----END PUBLIC KEY-----");

    const char* pzKey = sKeyInPem.c_str();
    std::unique_ptr< BIO, std::function<void(BIO*)>> bo(BIO_new(BIO_s_mem()), [](BIO* b) { BIO_free(b); });
    BIO_write(bo.get(), pzKey, strlen(pzKey));

    EC_KEY_set_asn1_flag(zPublicKey.get(), OPENSSL_EC_NAMED_CURVE);

    PEM_read_bio_EC_PUBKEY(bo.get(), &pPubKey, NULL, NULL);


    if (EC_KEY_check_key(pPubKey) == 1)
    {
        printf("EC Key valid.\n");
    }
    else {
        printf("EC Key Invalid!\n");
    }

    std::string sRandomNumber = "bef2fc87919a11d8312dc118ece116b108377aa4d771b1c1e5aaed41b85d50"; //Message to sign (Given to arduino.....)

    std::string sHash;
    OpensslUtility::computeSHA256Hash(sRandomNumber, sHash);

    int iVerify = OpensslUtility::verify_signature((const unsigned char*)sHash.c_str(), zSignature.get(), pPubKey);
