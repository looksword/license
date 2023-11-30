#ifndef ASEUTILS_H
#define ASEUTILS_H

#include "cryptopp564.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <stdexcept>

#include "aes.h"
#include "base32.h"
#include "base64.h"
#include "filters.h"
#include "hex.h"
#include "modes.h"
#include "osrng.h"
#include "sha.h"
#include "secblock.h"

using namespace CryptoPP;
using namespace std;

SecByteBlock encrypt(std::string content, std::string password);
SecByteBlock decrypt(SecByteBlock content, std::string password);
std::string ebotongDecrypto(std::string str);
std::string ebotongEncrypto(std::string str);
std::string parseByte2HexStr(const std::vector<unsigned char>& buf);
std::string encryptAES(const std::string& content, const std::string& password);
std::string decryptAES(const std::string& encryptResultStr, const std::string& password);

void ASE_Test();


#endif // ASEUTILS_H
