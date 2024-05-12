# le7-cryptography
Le7 Cryptography is a lightweight PHP library designed for password encryption, decryption, verification, and random password generation. This library is dependency-free, requiring only the PHP OpenSSL extension

A small PHP library designed for encrypting, decrypting, verifying passwords, and generating random passwords securely. It relies solely on PHP's OpenSSL extension and has no additional dependencies.

## Features

- Strong Encryption: Utilizes OpenSSL for robust password encryption and decryption using various algorithms such as AES-128, AES-192, AES-256, and DES-EDE3.
- Password Generation: Generates random passwords of customizable lengths, allowing you to specify the character set for password generation.
- Password Verification: Verifies whether a provided password matches a previously encrypted password, ensuring secure authentication.

## Requires

- PHP 8.0 or higher
- PHP ext-openssl
- composer

## Installation

To install the Cryptography Library, simply clone the repository or download the source files and include them in your PHP project.

```shell
git clone https://github.com/username/repository.git
```

## Usage

You can specify the key directly when creating the class object, or use a custom one for each encryption/decryption operation.

```php
// Include the Cryptography class
use rnr1721\Core\Cryptography;

// Initialize Cryptography with a key and method (optional)
$crypto = new Cryptography('your_secret_key', 'AES-256-CBC');

// Encrypt a password
$encryptedPassword = $crypto->encryptPassword('my_password');

// Decrypt an encrypted password
$decryptedPassword = $crypto->decryptPassword($encryptedPassword);

// Generate a random password
$randomPassword = $crypto->generateRandomPassword();

// Verify a password against its encrypted counterpart
$isPasswordValid = $crypto->verifyPassword('my_password', $encryptedPassword);
```

Or you can use key for each operations

```php
// Include the Cryptography class
use rnr1721\Core\Cryptography;

// Initialize Cryptography with a key and method (optional)
$crypto = new Cryptography();

// Encrypt a password
$encryptedPassword = $crypto->encryptPassword('my_password','your_secret_key','AES-256-CBC');

// Decrypt an encrypted password
$decryptedPassword = $crypto->decryptPassword($encryptedPassword,'your_secret_key','AES-256-CBC');

// Generate a random password. Length is optional, default is 7
$randomPassword = $crypto->generateRandomPassword(7);

// Verify a password against its encrypted counterpart
$isPasswordValid = $crypto->verifyPassword('my_password', $encryptedPassword,'your_secret_key','AES-256-CBC');
```

Also you can set symbols, allowed for random password generation

```php
// Include the Cryptography class
use rnr1721\Core\Cryptography;

// Initialize Cryptography with a key and method (optional)
$crypto = new Cryptography('your_secret_key', 'AES-256-CBC');

$crypto->setDefaultPasswordChars('abcdefgh');

$newPassword = $crypto->generateRandomPassword(5);

```

And you can get array of allowed methods

```php
// Include the Cryptography class
use rnr1721\Core\Cryptography;
$crypto = new Cryptography('your_secret_key', 'AES-256-CBC');
$allowedMethods = $crypto->getAllowedMethods();
```

## Contributing
Contributions are welcome! Please feel free to submit bug reports, feature requests, or pull requests. For major changes, please open an issue first to discuss the proposed changes.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
