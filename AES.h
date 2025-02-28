// AES.h
//
// AES (Advanced Encryption Standard) for C++ strings using CommomCrypto library.
// Made by GrimReaper31, 15/01/2024.
//

#ifndef AESCryptor_h
#define AESCryptor_h

#include <CommonCrypto/CommonCrypto.h>
#include <string>
#include <vector>

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

class AESCryptor {
public:
    AESCryptor(const std::string& key, const std::string& iv) {
        if (key.size() < kCCKeySizeAES256) {
            throw std::invalid_argument("key.size() < 32 bytes");
        }
        
        if (iv.size() < kCCBlockSizeAES128) {
            throw std::invalid_argument("iv.size() < 16 bytes");
        }
        
        std::copy_n(key.begin(), kCCKeySizeAES256, aes_key);
        std::copy_n(iv.begin(), kCCBlockSizeAES128, aes_iv);
    }
    
    template <size_t KeySize, size_t IVSize>
    constexpr AESCryptor(const char (&key)[KeySize], const char (&iv)[IVSize]) {
        static_assert(KeySize >= kCCKeySizeAES256 + 1, "key.size() < 32 bytes");
        static_assert(IVSize >= kCCBlockSizeAES128 + 1, "iv.size() < 16 bytes");
        
        std::copy_n(key, kCCKeySizeAES256, aes_key);
        std::copy_n(iv, kCCBlockSizeAES128, aes_iv);
    }

    
    std::string DecryptHex(const std::string& hexCiphertext) const noexcept {
        std::string binaryCiphertext = FromHexString(hexCiphertext);
        if (binaryCiphertext.empty()) {
            return "";
        }
        return Decrypt(binaryCiphertext);
    }
    
    std::string EncryptHex(const std::string& plaintext) const noexcept {
        std::string ciphertext = Encrypt(plaintext);
        if (ciphertext.empty()) {
            return "";
        }
        return ToHexString(ciphertext);
    }

#ifdef __OBJC__
    NSString* NSDecryptHex(const std::string& hexCiphertext) const noexcept {
        std::string decryptedText = DecryptHex(hexCiphertext);
        if (decryptedText.empty()) {
            return nil;
        }
        return ToNSString(decryptedText);
    }

    NSString* NSEncryptHex(const std::string& plaintext) const noexcept {
        std::string ciphertextHex = EncryptHex(plaintext);
        if (ciphertextHex.empty()) {
            return nil;
        }
        return ToNSString(ciphertextHex);
    }
#endif
    
private:
    std::string Encrypt(const std::string& plaintext) const noexcept {
        std::vector<unsigned char> data(plaintext.begin(), plaintext.end());
        size_t dataOutAvailable = data.size() + kCCBlockSizeAES128;
        std::vector<unsigned char> dataOut(dataOutAvailable);

        size_t dataOutMoved;
        CCCryptorStatus status = CCCrypt(
            kCCEncrypt,
            kCCAlgorithmAES,
            kCCOptionPKCS7Padding,
            aes_key,
            kCCKeySizeAES256,
            aes_iv,
            data.data(),
            data.size(),
            dataOut.data(),
            dataOutAvailable,
            &dataOutMoved
        );

        if (status != kCCSuccess) {
            return "";
        }

        return std::string(reinterpret_cast<char*>(dataOut.data()), dataOutMoved);
    }

    std::string Decrypt(const std::string& ciphertext) const noexcept {
        std::vector<unsigned char> data(ciphertext.begin(), ciphertext.end());
        size_t dataOutAvailable = data.size();
        std::vector<unsigned char> dataOut(dataOutAvailable);

        size_t dataOutMoved;
        CCCryptorStatus status = CCCrypt(
            kCCDecrypt,
            kCCAlgorithmAES,
            kCCOptionPKCS7Padding,
            aes_key,
            kCCKeySizeAES256,
            aes_iv,
            data.data(),
            data.size(),
            dataOut.data(),
            dataOutAvailable,
            &dataOutMoved
        );

        if (status != kCCSuccess) {
            return "";
        }

        return std::string(reinterpret_cast<char*>(dataOut.data()), dataOutMoved);
    }

    std::string ToHexString(const std::string& input) const noexcept {
        static const char hexDigits[] = "0123456789ABCDEF";

        std::string output;
        output.reserve(input.length() * 2);
        for (unsigned char c : input) {
            output.push_back(hexDigits[c >> 4]);
            output.push_back(hexDigits[c & 0x0F]);
        }
        return output;
    }

    std::string FromHexString(const std::string& hex) const noexcept {
        if (hex.length() % 2 != 0) {
            return "";
        }
        std::string output;
        output.reserve(hex.length() / 2);
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            try {
                char byte = static_cast<char>(std::stoul(byteString, nullptr, 16));
                output.push_back(byte);
            } catch (...) {
                return "";
            }
        }
        return output;
    }

#ifdef __OBJC__
    NSString* ToNSString(const std::string& input) const noexcept {
        return [NSString stringWithUTF8String:input.c_str()];
    }
#endif

private:
    unsigned char aes_key[kCCKeySizeAES256];
    unsigned char aes_iv[kCCBlockSizeAES128];
};

#endif /* AESCryptor_h */

