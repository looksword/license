#include "aesutils.h"

SecByteBlock encrypt(std::string content, std::string password) {
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];

    try {
        // 使用SHA1PRNG生成密钥
        SHA1 hash;
        hash.CalculateDigest(key, (byte*)password.data(), password.size());

        // Zero Initialization Vector
        memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

        // Encryption
        CBC_Mode<AES>::Encryption encryption(key, sizeof(key), iv);

        std::string ciphertext;
        AutoSeededRandomPool prng;
        StringSource s(content, true,
            new StreamTransformationFilter(encryption, new StringSink(ciphertext), BlockPaddingSchemeDef::PKCS_PADDING));

        return SecByteBlock((byte*)ciphertext.data(), ciphertext.size());
    } catch(const Exception& e) {
        // Log or throw exception
        // std::cerr << e.what() << '\n';
        throw;
    }
}

SecByteBlock decrypt(SecByteBlock content, std::string password) {
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];

    try {
        // 使用SHA1PRNG生成密钥
        SHA1 hash; // CryptoPP中没有提供类似Java中SHA1PRNG的API，我们这里以SHA256为例
        hash.CalculateDigest(key, (byte*)password.data(), password.size());

        // Zero Initialization Vector
        memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

        // Decryption
        CBC_Mode<AES>::Decryption decryption(key, sizeof(key), iv);

        // The StreamTransformationFilter removes padding as required.
        std::string decryptedtext;
        auto cipher = new StreamTransformationFilter(decryption, new StringSink(decryptedtext));
        cipher->Put((byte*)content.data(), content.size());
        cipher->MessageEnd();

        return SecByteBlock((byte*)decryptedtext.data(), decryptedtext.size());
    } catch(const Exception& e) {
        // Log or throw exception
        // std::cerr << e.what() << '\n';
        throw;
    }
}

std::string ebotongDecrypto(std::string str) {
    std::string decoded;
    try {
        CryptoPP::StringSource ss(str, true,
                                  new CryptoPP::Base64Decoder(
                                  new CryptoPP::StringSink(decoded)
        ));
    } catch(const CryptoPP::Exception& e) {
        // Log or throw exception
         std::cout << e.what() << std::endl;
        throw;
    }
    return decoded;
}

std::string ebotongEncrypto(std::string str) {
    std::string encoded;
    try {
        StringSource ss(str, true,
            new Base64Encoder(
                new StringSink(encoded), false // set 'false' to disable line breaks
            )
        );
    } catch(const CryptoPP::Exception& e) {
        // Log or throw exception
        std::cout << e.what() << std::endl;
        throw;
    }

    // In this version of code we don't need to manually remove the line breaks
    return encoded;
}

std::string parseByte2HexStr(const std::vector<unsigned char>& buf) {
    std::stringstream ss;
    for(const auto& b : buf) {
        ss << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)b;
    }
    return ss.str();
}

CryptoPP::SecByteBlock parseHexStr2Byte(const std::string& hexStr) {
    if (hexStr.empty())
        return CryptoPP::SecByteBlock();

    CryptoPP::SecByteBlock bytes(hexStr.length() / 2);

    for (size_t i = 0; i < hexStr.length(); i+=2) {
        std::string byteString = hexStr.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes[i / 2] = byte;
    }

    return bytes;
}



std::string encryptAES(const std::string& content, const std::string& password) {
    // if (content.empty()) {
    //     throw std::invalid_argument("Content cannot be empty!");
    // }
    SecByteBlock encryptResult = encrypt(content, password);
    std::vector<unsigned char> encryptResultVec(encryptResult.begin(),encryptResult.end());
    std::string encryptResultStr = parseByte2HexStr(encryptResultVec);
    // Base64 encode
    encryptResultStr = ebotongEncrypto(encryptResultStr);
    return encryptResultStr;
}

std::string decryptAES(const std::string& encryptResultStr, const std::string& password) {
    // if (encryptResultStr.empty()) {
    //     throw std::invalid_argument("Encrypted string cannot be empty");
    // }
    // Base64 decode
    try {
        std::string decryptStr = ebotongDecrypto(encryptResultStr);
        SecByteBlock decryptFrom = parseHexStr2Byte(decryptStr);
        SecByteBlock decryptResult = decrypt(decryptFrom, password);
        return std::string(decryptResult.begin(), decryptResult.end());
    } catch (const std::exception& e) {  // When the encrypted string is not standardized, an error will be reported, which can be ignored, but needs to be considered where it is called
        std::cout << "decryptAES error: " << e.what() << std::endl;
        return {};
    }
}

void ASE_Test()
{
    printf("\r\n------ASE-------------------------------------\r\n");

    std::string content = "ase EXPRESS";
    std::string password = "00:ff:ac:08:fc:88";//"password:xuanyu";
    std::cout << "Original content: " << content << std::endl;

    // Assume that encryptAES and decryptAES are correctly defined.
    std::string encrypted = encryptAES(content, password);
    std::cout << "Encrypted content: " << encrypted << std::endl;

    std::string decrypted = decryptAES(encrypted, password);
    std::cout << "Decrypted content: " << decrypted << std::endl;
}
