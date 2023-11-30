#ifndef ENCRYPTUTILS_H
#define ENCRYPTUTILS_H

#include "cryptopp564.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <stdexcept>

#include "hex.h"
#include "md5.h"
#include "filters.h"
#include "secblock.h"

using namespace CryptoPP;
using namespace std;

std::string toHexString(const CryptoPP::SecByteBlock& inputBlock);
std::string md5(const std::string& sourceString);

void MD5_Test();

#endif // ENCRYPTUTILS_H
