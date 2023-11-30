#include "rsautils.h"

//std::string decryptByPublicKey(const std::string& publicKeyText, const std::string& text) {
//    // Load public key.
//    CryptoPP::ByteQueue bytes;
//    CryptoPP::StringSource ss(publicKeyText, true, new CryptoPP::Base64Decoder);
//    ss.TransferTo(bytes);
//    bytes.MessageEnd();
//    CryptoPP::RSA::PublicKey publicKey;
//    publicKey.Load(bytes);

//    // Decode the cyphertext.
//    std::string cipherText;
//    CryptoPP::StringSource ss2(text, true,
//        new CryptoPP::Base64Decoder(
//            new CryptoPP::StringSink(cipherText)
//        )
//    );

//    // Perform decryption.
//    CryptoPP::AutoSeededRandomPool prng;
//    CryptoPP::RSAES_OAEP_SHA_Decryptor d(publicKey);
//    std::string result;
//    CryptoPP::StringSource(cipherText, true,
//        new CryptoPP::PK_DecryptorFilter(prng, d,
//            new CryptoPP::StringSink(result)
//        )
//    );

//    return result;
//}

//std::string decryptByPublicKey(const std::string& publicKeyText, const std::string& cipherText) {
//    CryptoPP::AutoSeededRandomPool rng;
//    CryptoPP::ByteQueue bytes;
//    CryptoPP::Base64Decoder decoder;

//    // 解码提供的公钥
//    decoder.Put(reinterpret_cast<const byte*>(publicKeyText.data()), publicKeyText.size());
//    decoder.MessageEnd();
//    decoder.TransferTo(bytes);
//    bytes.MessageEnd();

//    // 加载公钥
//    CryptoPP::RSA::PublicKey publicKey;
//    publicKey.Load(bytes);

//    // 先对密文进行base64解码
//    std::string decodedCipherText;
//    CryptoPP::Base64Decoder cipherDecoder(new CryptoPP::StringSink(decodedCipherText));
//    cipherDecoder.Put((const byte*)cipherText.data(), cipherText.size());
//    cipherDecoder.MessageEnd();

//    // 解密密文
//    std::string recoveredText;
//    CryptoPP::RSAES_OAEP_SHA_Decryptor d(publicKey);
//    CryptoPP::StringSource(decodedCipherText, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(recoveredText)));

//    return recoveredText;
//}

//std::string decryptByPublicKey(const std::string& publicKeyText, const std::string& text)
//{
//    // Create a string source
//    CryptoPP::StringSource ss(publicKeyText, true /*pumpAll*/);

//    // Create a RSA public key
//    CryptoPP::RSA::PublicKey publicKey;
//    publicKey.Load(ss);

//    // Decode from Base64
//    std::string decoded;
//    CryptoPP::StringSource ss2(text, true,
//        new CryptoPP::Base64Decoder(
//            new CryptoPP::StringSink(decoded)
//        ) // Base64Decoder
//    ); // StringSource

//    // Decrypt
//    std::string recoveredText;
//    {
//        CryptoPP::AutoSeededRandomPool rng;
//        CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor decryptor(publicKey);

//        CryptoPP::StringSource ss3(decoded, true,
//            new CryptoPP::PK_DecryptorFilter(rng, decryptor,
//                new CryptoPP::StringSink(recoveredText)
//            ) // PK_DecryptorFilter
//        ); // StringSource
//    }

//    return recoveredText;
//}

//std::string decryptByPublicKey(const std::string& publicKeyText, const std::string& text)
//{
//    CryptoPP::ByteQueue bytes;
//    CryptoPP::StringSource ss(publicKeyText, true, new CryptoPP::Base64Decoder);
//    ss.TransferTo(bytes);
//    bytes.MessageEnd();
//    CryptoPP::RSA::PublicKey publicKey;
//    publicKey.Load(bytes);

//    std::string plainText;
//    CryptoPP::AutoSeededRandomPool rng;

//    try {
//        CryptoPP::RSAES_OAEP_SHA_Decryptor d(publicKey);

//        CryptoPP::StringSource ss2(text, true,
//            new CryptoPP::PK_DecryptorFilter(rng, d,
//                new CryptoPP::StringSink(plainText)
//            ) // PK_DecryptorFilter
//        ); // StringSource
//    } catch (CryptoPP::Exception& e) {
//        std::cerr << "decrypt by publickey error :" << e.what() << std::endl;
//    }


//    return plainText;
//}

std::string decryptByPublicKey(const std::string& publicKeyText, const std::string& cipherText) {
    // 1. 从字符串读取公钥
    StringSource ss(publicKeyText, true, new Base64Decoder);
    RSA::PublicKey publicKey;
    CryptoPP::ByteQueue bytes;
    ss.TransferTo(bytes);
    bytes.MessageEnd();
    publicKey.Load(bytes);


    // 2. 创建cipher对象并设置公钥
    RSAES_OAEP_SHA_Decryptor d(publicKey);

    AutoSeededRandomPool rng;
    std::string recovered;

    // 3. 解密
    StringSource(cipherText, true,
            new HexDecoder(
                new PK_DecryptorFilter(rng, d, new StringSink(recovered))));
    // 返回解密后的值
    return recovered;
}

std::string encryptByPrivateKey(const std::string& privateKeyText, const std::string& plainText) {
    // 1. 从字符串读取私钥
    StringSource ss(privateKeyText, true, new Base64Decoder);
    RSA::PrivateKey privateKey;
    CryptoPP::ByteQueue bytes;
    ss.TransferTo(bytes);
    bytes.MessageEnd();
    privateKey.Load(bytes);

    // 2. 创建cipher对象并设置私钥
    RSAES_OAEP_SHA_Encryptor e(privateKey);

    AutoSeededRandomPool rng;
    std::string cipher;

    // 3. 加密
    StringSource(plainText, true,
            new PK_EncryptorFilter(rng, e , new StringSink(cipher)));

    // 4. 结果使用 Base64 编码
    std::string encoded;
    Base64Encoder encoder;
    encoder.Attach( new StringSink( encoded ) );
    encoder.Put( (const byte*)cipher.data(), cipher.size() );
    encoder.MessageEnd();

    // 返回加密后的值
    return encoded;
}

//std::string encryptByPrivateKey(const std::string& privateKeyText, const std::string& text) {
//    // Load private key.
//    CryptoPP::ByteQueue bytes;
//    CryptoPP::StringSource ss(privateKeyText, true, new CryptoPP::Base64Decoder);
//    ss.TransferTo(bytes);
//    bytes.MessageEnd();
//    CryptoPP::RSA::PrivateKey privateKey;
//    privateKey.Load(bytes);

//    // Perform encryption.
//    CryptoPP::AutoSeededRandomPool prng;
//    CryptoPP::RSAES_OAEP_SHA_Encryptor e(privateKey);
//    std::string cipherText;
//    CryptoPP::StringSource(text, true,
//        new CryptoPP::PK_EncryptorFilter(prng, e,
//            new CryptoPP::Base64Encoder(
//                new CryptoPP::StringSink(cipherText)
//            )
//        )
//    );

//    return cipherText;
//}

//std::string encryptByPrivateKey(const std::string& privateKeyText, const std::string& text) {
//    CryptoPP::AutoSeededRandomPool rng;
//    CryptoPP::ByteQueue bytes;
//    CryptoPP::Base64Decoder decoder;

//    // 解码提供的私钥
//    decoder.Put(reinterpret_cast<const byte*>(privateKeyText.data()), privateKeyText.size());
//    decoder.MessageEnd();
//    decoder.TransferTo(bytes);
//    bytes.MessageEnd();

//    // 载入私钥
//    CryptoPP::RSA::PrivateKey privKey;
//    privKey.Load(bytes);

//    std::string cipherText;

//    // 加密明文
//    CryptoPP::RSAES_OAEP_SHA_Encryptor e(privKey);
//    CryptoPP::StringSource(text, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(cipherText)));

//    // 对加密的内容进行 base64 编码
//    std::string encoded;
//    CryptoPP::StringSource(cipherText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));

//    return encoded;
//}

//std::string encryptByPrivateKey(const std::string& privateKeyText, const std::string& text)
//{
//    // Create a string source
//    CryptoPP::StringSource ss(privateKeyText, true /*pumpAll*/);

//    // Create a RSA private key
//    CryptoPP::RSA::PrivateKey privateKey;
//    privateKey.Load(ss);

//    // Create a pipe that pumps into a Base64 encoder
//    CryptoPP::AutoSeededRandomPool rng;
//    std::string cipherText;
//    {
//        // Use RSAES scheme to encrypt the hash
//        CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor encryptor(privateKey);

//        CryptoPP::StringSource ss(text, true,
//            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
//                new CryptoPP::StringSink(cipherText)
//            ) // PK_EncryptorFilter
//        ); // StringSource

//    }

//    // Output the encrypted hash in base64 format
//    std::string encoded;
//    CryptoPP::StringSource ss2(cipherText, true,
//        new CryptoPP::Base64Encoder(
//            new CryptoPP::StringSink(encoded)
//        ) // Base64Encoder
//    ); // StringSource

//    return encoded;
//}

//std::string encryptByPrivateKey(const std::string& privateKeyText, const std::string& text)
//{
//    CryptoPP::ByteQueue bytes;
//    CryptoPP::StringSource ss(privateKeyText, true, new CryptoPP::Base64Decoder);
//    ss.TransferTo(bytes);
//    bytes.MessageEnd();
//    CryptoPP::RSA::PrivateKey privateKey;
//    privateKey.Load(bytes);

//    CryptoPP::SHA256 hash;
//    std::string digest;
//    CryptoPP::StringSource ss1(text, true,
//        new CryptoPP::HashFilter(hash,
//            new CryptoPP::HexEncoder(
//                new CryptoPP::StringSink(digest))));

//    std::string signature;
//    CryptoPP::AutoSeededRandomPool rng;
//    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(privateKey);
//    CryptoPP::StringSource ss2(digest, true,
//        new CryptoPP::SignerFilter(rng, signer,
//            new CryptoPP::HexEncoder(
//                new CryptoPP::StringSink(signature))));

//    return signature;
//}

std::string SignWithRSA(const std::string& privateKeyText, const std::string& text) {
    // 创建RSA私钥对象
    CryptoPP::RSA::PrivateKey privateKey;

    // 将Base64形式的私钥解码为二进制
    CryptoPP::StringSource ss(privateKeyText, true, new CryptoPP::Base64Decoder);

    // 从二进制形式加载私钥
    privateKey.Load(ss);

    // 创建随机数生成器
    CryptoPP::AutoSeededRandomPool rng;

    // 创建签名对象
    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(privateKey);

    std::string signature;
    // 在消息上签名
    CryptoPP::StringSource ss1(text, true, new CryptoPP::SignerFilter(rng, signer,
       new CryptoPP::HexEncoder(new CryptoPP::StringSink(signature))));

    return signature;
}

bool VerifyWithRSA(const std::string& publicKeyText, const std::string& text, const std::string& signature) {
    // 创建RSA公钥对象
    CryptoPP::RSA::PublicKey publicKey;

    // 将Base64形式的公钥解码为二进制
    CryptoPP::StringSource ss(publicKeyText, true, new CryptoPP::Base64Decoder);

    // 从二进制形式加载公钥
    publicKey.Load(ss);

    // 创建随机数生成器
    CryptoPP::AutoSeededRandomPool rng;

    // 创建验证对象
    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(publicKey);

    std::string decoded_signature;
    CryptoPP::StringSource ss2(signature, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(decoded_signature)));
    std::cout << "Decrypted public content: " << decoded_signature << std::endl;
    bool result;
    // 在消息上进行验证
    CryptoPP::StringSource ss1(decoded_signature + text, true,
        new CryptoPP::SignatureVerificationFilter(
            verifier, new CryptoPP::ArraySink(
                reinterpret_cast<byte*>(&result), sizeof(result))));

    return result;
}

std::string decryptByPrivateKey(const std::string& privateKeyText, const std::string& cipherTextBase64) {
    // Load the private key.
    CryptoPP::ByteQueue bytes;
    try {
        CryptoPP::StringSource ss(privateKeyText, true, new CryptoPP::Base64Decoder);
        ss.TransferTo(bytes);
        bytes.MessageEnd();
    } catch(const CryptoPP::Exception& e) {
        std::cout << e.what() << std::endl;
        throw;
    }
    CryptoPP::RSA::PrivateKey privateKey;
    try {
        privateKey.Load(bytes);
    } catch(const CryptoPP::Exception& e) {
        std::cout << e.what() << std::endl;
        throw;
    }

    // Decode the cyphertext.
    std::string cipherText;
    try {
        CryptoPP::StringSource ss2(cipherTextBase64, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(cipherText)
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cout << e.what() << std::endl;
        throw;
    }

    // Perform decryption.
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
    std::string result;
    try {
        CryptoPP::StringSource(cipherText, true,
            new CryptoPP::PK_DecryptorFilter(prng, d,
                new CryptoPP::StringSink(result)
            )
        );
    } catch(const CryptoPP::Exception& e) {
        std::cout << e.what() << std::endl;
        throw;
    }

    return result;
}

std::string encryptByPublicKey(const std::string& publicKeyText, const std::string& text) {
    // Load the public key.
    CryptoPP::ByteQueue bytes;
    CryptoPP::StringSource ss(publicKeyText, true, new CryptoPP::Base64Decoder);
    ss.TransferTo(bytes);
    bytes.MessageEnd();
    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Load(bytes);

    // Perform encryption.
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);
    std::string cipherText;
    CryptoPP::StringSource(text, true,
        new CryptoPP::PK_EncryptorFilter(prng, e,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(cipherText)
            )
        )
    );

    return cipherText;
}

//// Function to generate a private and public key pair.
//RSAKeyPair generateKeyPair() {
//    // Generate private key and public key.
//    CryptoPP::AutoSeededRandomPool rng;
//    CryptoPP::InvertibleRSAFunction params;
//    params.Initialize(rng, 1024);

//    CryptoPP::RSA::PrivateKey privateKey;
//    privateKey.Initialize(params.GetModulus(), params.GetPublicExponent(), params.GetPrivateExponent());

//    CryptoPP::RSA::PublicKey publicKey;
//    publicKey.Initialize(params.GetModulus(), params.GetPublicExponent());

//    // Save keys in strings.
//    std::string publicKeyString, privateKeyString;

//    // Save public key in string.
//    {
//        publicKeyString.clear();
//        CryptoPP::Base64Encoder sink1(new CryptoPP::StringSink(publicKeyString));
//        publicKey.DEREncode(sink1);
//        sink1.MessageEnd();
//    }

//    // Save private key in string.
//    {
//        privateKeyString.clear();
//        CryptoPP::Base64Encoder sink2(new CryptoPP::StringSink(privateKeyString));
//        privateKey.DEREncode(sink2);
//        sink2.MessageEnd();
//    }

//    return RSAKeyPair(publicKeyString, privateKeyString);
//}

//// Function to generate a private and public key pair.
//RSAKeyPair generateKeyPair() {
//    // Generate private key and public key.
//    CryptoPP::AutoSeededRandomPool rng;

//    CryptoPP::RSA::PrivateKey privateKey;
//    privateKey.GenerateRandomWithKeySize(rng, 1024);

//    CryptoPP::RSA::PublicKey publicKey(privateKey);

//    // Save keys in strings.
//    std::string publicKeyString, privateKeyString;

//    // Save public key in string.
//    {
//        publicKeyString.clear();
//        CryptoPP::Base64Encoder sink1(new CryptoPP::StringSink(publicKeyString));
//        publicKey.DEREncode(sink1);
//        sink1.MessageEnd();
//    }

//    // Save private key in string.
//    {
//        privateKeyString.clear();
//        CryptoPP::Base64Encoder sink2(new CryptoPP::StringSink(privateKeyString));
//        privateKey.DEREncode(sink2);
//        sink2.MessageEnd();
//    }

//    return RSAKeyPair(publicKeyString, privateKeyString);
//}

//// Function to generate a private and public key pair.
//RSAKeyPair generateKeyPair() {
//    CryptoPP::AutoSeededRandomPool rng;

//    // Generate keys
//    CryptoPP::RSA::PrivateKey privateKey;
//    CryptoPP::RSA::PublicKey publicKey;

//    privateKey.GenerateRandomWithKeySize(rng, 1024);
//    privateKey.MakePublicKey(publicKey);

//    // Save keys in strings.
//    std::string privateKeyString, publicKeyString;

//    // Save private key in string
//    {
//        CryptoPP::Base64Encoder privateKeySink(new CryptoPP::StringSink(privateKeyString));
//        privateKey.DEREncode(privateKeySink);
//        privateKeySink.MessageEnd();
//    }

//    // Save public key in string.
//    {
//        CryptoPP::Base64Encoder publicKeySink(new CryptoPP::StringSink(publicKeyString));
//        publicKey.DEREncode(publicKeySink);
//        publicKeySink.MessageEnd();
//    }

//    return RSAKeyPair(publicKeyString, privateKeyString);
//}

RSAKeyPair generateKeyPair() {
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rng, 1024);

    CryptoPP::RSA::PublicKey rsaPublic;
    rsaPublic.AssignFrom(rsaPrivate);

    std::string publicKeyString, privateKeyString;

    // Save the public key to a string
    {
        CryptoPP::Base64Encoder publicKeyEncoder(nullptr, false);
        rsaPublic.DEREncode(publicKeyEncoder);
        publicKeyEncoder.MessageEnd();
        CryptoPP::word64 size = publicKeyEncoder.MaxRetrievable();
        if (size)
        {
            publicKeyString.resize(size);
            publicKeyEncoder.Get((byte*)&publicKeyString[0], publicKeyString.size());
        }
    }

    // Save the private key to a string
    {
        CryptoPP::Base64Encoder privateKeyEncoder(nullptr, false);
        rsaPrivate.DEREncode(privateKeyEncoder);
        privateKeyEncoder.MessageEnd();
        CryptoPP::word64 size = privateKeyEncoder.MaxRetrievable();
        if (size)
        {
            privateKeyString.resize(size);
            privateKeyEncoder.Get((byte*)&privateKeyString[0], privateKeyString.size());
        }
    }

    return RSAKeyPair{ publicKeyString, privateKeyString };
}


void RSA_Test()
{
    RSAKeyPair newrsakeypair = generateKeyPair();

    printf("\r\n------RSA-------------------------------------\r\n");

    std::string content = "rsa EXPRESS password xuanyu";
    std::cout << "Original content: " << content << std::endl;

//    std::string encryptedpub = encryptByPublicKey(newrsakeypair.publicKey, content);
//    std::cout << "Encrypted public content: " << encryptedpub << std::endl;

//    std::string decryptedpri = decryptByPrivateKey(newrsakeypair.privateKey, encryptedpub);
//    std::cout << "Decrypted private content: " << decryptedpri << std::endl;

    printf("\r\n------RSA2-------------------------------------\r\n");

    std::string encryptedpri = encryptByPrivateKey(newrsakeypair.privateKey, content);
    std::cout << "Encrypted private content: " << encryptedpri << std::endl;

    std::string decryptedpub = decryptByPublicKey(newrsakeypair.publicKey, encryptedpri);
    std::cout << "Decrypted public content: " << decryptedpub << std::endl;

//    printf("\r\n------Sign-------------------------------------\r\n");
//    std::string encryptedpri = SignWithRSA(newrsakeypair.privateKey, content);
//    std::cout << "Encrypted private content: " << encryptedpri << std::endl;
//    if(VerifyWithRSA(newrsakeypair.publicKey, content, encryptedpri))
//    {
//        printf("success.\r\n");
//    }
//    else
//    {
//        printf("failed.\r\n");
//    }

}


