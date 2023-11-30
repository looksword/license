#ifndef RSAUTILS_H
#define RSAUTILS_H

#include "cryptopp564.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <stdexcept>

#include "rsa.h"
#include "osrng.h"
//#include "pem.h"
#include "base64.h"
#include "files.h"
#include "pssr.h"

using namespace CryptoPP;
using namespace std;

struct RSAKeyPair
{
    std::string publicKey;
    std::string privateKey;
};

std::string decryptByPublicKey(const std::string& publicKeyText, const std::string& text);
std::string encryptByPrivateKey(const std::string& privateKeyText, const std::string& text);
std::string decryptByPrivateKey(const std::string& privateKeyText, const std::string& cipherTextBase64);
std::string encryptByPublicKey(const std::string& publicKeyText, const std::string& text);

RSAKeyPair generateKeyPair();

void RSA_Test();

std::string SignWithRSA(const std::string& privateKeyText, const std::string& text);
bool VerifyWithRSA(const std::string& publicKeyText, const std::string& text, const std::string& signature);

#endif // RSAUTILS_H
