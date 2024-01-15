//
//
// AES (Advanced Encryption Standard) for C++ strings using CommomCode library.
// Made by GrimReaper31, 15/01/2024.
//


#include <CommonCrypto/CommonCrypto.h>
#include <string>
#include <vector>

class AESCryptor {
public:
    AESCryptor(const std::string& key, const std::string& iv) {
        std::copy_n(key.begin(), kCCKeySizeAES256, aes_key);
        std::copy_n(iv.begin(), kCCBlockSizeAES128, aes_iv);
    }

    std::string encrypt(const std::string& plaintext) {
        std::vector<char> data(plaintext.begin(), plaintext.end());
        size_t dataOutAvailable = data.size() + kCCBlockSizeAES128;
        std::vector<char> dataOut(dataOutAvailable);

        size_t dataOutMoved;
        CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, aes_key, kCCKeySizeAES256, aes_iv, data.data(), data.size(), dataOut.data(), dataOutAvailable, &dataOutMoved);

        if (status != kCCSuccess) {
            return "";
        }

        return std::string(dataOut.begin(), dataOut.begin() + dataOutMoved);
    }

    std::string decrypt(const std::string& ciphertext) {
        std::vector<char> data(ciphertext.begin(), ciphertext.end());
        size_t dataOutAvailable = data.size();
        std::vector<char> dataOut(dataOutAvailable);

        size_t dataOutMoved;
        CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, aes_key, kCCKeySizeAES256, aes_iv, data.data(), data.size(), dataOut.data(), dataOutAvailable, &dataOutMoved);

        if (status != kCCSuccess) {
            return "";
        }

        return std::string(dataOut.begin(), dataOut.begin() + dataOutMoved);
    }
    
    std::string toHexString(const std::string& input) {
        static const char hexDigits[] = "0123456789ABCDEF";

        std::string output;
        output.reserve(input.length() * 2);
        for (unsigned char c : input) {
            output.push_back(hexDigits[c >> 4]);
            output.push_back(hexDigits[c & 15]);
        }
        return output;
    }
    
    std::string fromHexString(const std::string& hex) {
        if (hex.length() % 2 != 0) {
            return "";
        }
        std::string output;
        output.reserve(hex.length() / 2);
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char byte = static_cast<char>(std::stoul(byteString, nullptr, 16));
            output.push_back(byte);
        }
        return output;
    }


private:
    unsigned char aes_key[kCCKeySizeAES256];
    unsigned char aes_iv[kCCBlockSizeAES128];
};
