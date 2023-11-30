#include "encryptutils.h"

std::string toHexString(const CryptoPP::SecByteBlock& inputBlock) {
    std::string output;
    CryptoPP::ArraySource(
        inputBlock, inputBlock.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) // HexEncoder
    ); // ArraySource
    return output;
}

std::string md5(const std::string& sourceString) {
    CryptoPP::SecByteBlock digest(CryptoPP::MD5::DIGESTSIZE);
    CryptoPP::MD5 hash;
    hash.CalculateDigest(digest, reinterpret_cast<const byte*>(sourceString.data()), sourceString.size());

    return toHexString(digest);
}

void MD5_Test()
{
    printf("\r\n------MD5-------------------------------------\r\n");
    std::string content = "MD5 EXPRESS password xuanyu";
    std::cout << "Original content: " << content << std::endl;
    std::string encrypted = md5(content);
    std::cout << "MD5 content: " << encrypted << std::endl;
}

