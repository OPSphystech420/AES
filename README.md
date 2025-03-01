# AESCryptor

AESCryptor is a C++ class that provides AES encryption and decryption functionalities using the CommonCrypto library. It supports AES-256 encryption and uses PKCS#7 padding.

## Prerequisites

- C++ Compiler supporting C++11 or higher
- macOS or iOS development environment (CommonCrypto is part of these platforms)

## Installation

Include `AES.h` in your project and link against the CommonCrypto framework.

## Usage

### Example

```cpp
#include <CommonCrypto/CommonCrypto.h>
#include <string>
#include <iostream>
#include "AES.h"

int main() {
    std::string key = "0123456789abcdef0123456789abcdef";  // 32 bytes for AES-256
    std::string iv = "0123456789abcdef";                    // 16 bytes

    try {
        AESCryptor cryptor(key, iv);

        std::string plaintext = "Hello, World!";
        std::string encryptedHex = cryptor.EncryptHex(plaintext);
        std::string decrypted = cryptor.DecryptHex(encryptedHex);

        std::cout << "Plaintext: " << plaintext << std::endl;
        std::cout << "Encrypted (Hex): " << encryptedHex << std::endl;
        std::cout << "Decrypted: " << decrypted << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
```

### Expected Output

```
Plaintext: Hello, World!
Encrypted (Hex): 4AF6287D964F3BF6301684747A381A75
Decrypted: Hello, World!
```

## Objective-C++ Integration

For macOS and iOS applications, AESCryptor supports `NSString*` encryption and decryption.

### Note
Ensure that the key and IV lengths are appropriate for AES-256 (key: 32 bytes, IV: 16 bytes). The class does not perform length checks or error handling for incorrect key/IV lengths.
