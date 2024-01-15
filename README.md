### AESCryptor
# Overview
AESCryptor is a C++ class that provides AES encryption and decryption functionalities using the CommonCrypto library. It supports AES-256 encryption and uses PKCS#7 padding.

# Prerequisites
C++ Compiler (supporting C++11 or higher)
macOS or iOS development environment (as CommonCrypto is part of these platforms)

# Example
```cpp
Copy code
#include <CommonCrypto/CommonCrypto.h>
#include <string>
#include "AESCryptor.h"

int main() {
    std::string key = "0123456789abcdef0123456789abcdef";  // 32 bytes for AES-256
    std::string iv = "0123456789abcdef";                    // 16 bytes

    AESCryptor cryptor(key, iv);

    std::string plaintext = "Hello, World!";
    std::string encrypted = cryptor.encrypt(plaintext);
    std::string hexEncrypted = cryptor.toHexString(encrypted);

    std::string decrypted = cryptor.decrypt(cryptor.fromHexString(hexEncrypted));

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encrypted (Hex): " << hexEncrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
}
```
# Note
Ensure that the key and IV lengths are appropriate for AES-256 (key: 32 bytes, IV: 16 bytes). The class does not perform length checks or error handling for incorrect key/IV lengths.
