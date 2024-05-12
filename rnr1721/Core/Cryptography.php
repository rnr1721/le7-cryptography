<?php

declare(strict_types=1);

namespace rnr1721\Core;

use rnr1721\Core\Exceptions\CryptographyException;
use function openssl_cipher_iv_length,
             openssl_random_pseudo_bytes,
             openssl_encrypt,
             openssl_decrypt,
             base64_encode,
             base64_decode,
             substr,
             rand,
             strlen,
             array_key_exists,
             implode;

/**
 * Class Cryptography
 * Provides methods for encrypting and decrypting passwords using OpenSSL.
 */
class Cryptography
{

    /**
     * Allowed encryption methods
     * 
     * @var array
     */
    private array $allowedMethods = [
        'AES-128-CBC' => 'AES with a 128-bit key in CBC mode',
        'AES-192-CBC' => 'AES with a 192-bit key in CBC mode',
        'AES-256-CBC' => 'AES with a 256-bit key in CBC mode',
        'DES-EDE3-CBC' => 'Triple DES (3DES) in CBC mode'
    ];

    /**
     * Symbols than can be used for random password generation
     * 
     * @var string
     */
    private string $passwordChars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * Default encryption method. If not set, will be used parameters from methods
     * 
     * @var string
     */
    private string $method;

    /**
     * Default encryption key. If not set, will be used parameters from methods
     * 
     * @var string
     */
    private string $key;

    /**
     * Constructor for the Cryptography class.
     * 
     * @param string $key The encryption key to be used. Default is empty.
     * @param string $method The encryption method to be used (default: AES-256-CBC).
     */
    public function __construct(string $key = '', string $method = 'AES-256-CBC')
    {
        $this->key = $key;
        $this->method = $method;
    }

    /**
     * Encrypts the given password using OpenSSL.
     * 
     * @param string $password The password to be encrypted.
     * @param string $key (Optional) The encryption key to be used (default: class key).
     * @param string $method (Optional) The encryption method to be used (default: class method).
     * @return string The encrypted password.
     * @throws CryptographyException If the password or key is empty, or if the method is invalid.
     */
    public function encryptPassword(string $password, string $key = '', string $method = ''): string
    {
        $keyCurrent = empty($key) ? $this->key : $key;
        $methodCurrent = empty($method) ? $this->method : $method;
        $this->checkForEmpty($password, $keyCurrent, $methodCurrent);
        $ivLength = openssl_cipher_iv_length($methodCurrent);
        $iv = openssl_random_pseudo_bytes($ivLength);
        $encrypted = openssl_encrypt($password, $methodCurrent, $keyCurrent, OPENSSL_RAW_DATA, $iv);
        $result = base64_encode($iv . $encrypted);
        return $result;
    }

    /**
     * Decrypts the given encrypted password using OpenSSL.
     * 
     * @param string $encryptedPassword The encrypted password to be decrypted.
     * @param string $key (Optional) The encryption key to be used (default: class key).
     * @param string $method (Optional) The encryption method to be used (default: class method).
     * @return string The decrypted password.
     * @throws CryptographyException If the encrypted password or key is empty, or if the method is invalid or if password can not be decrypted.
     */
    public function decryptPassword(string $encryptedPassword, string $key = '', string $method = ''): string
    {
        $keyCurrent = empty($key) ? $this->key : $key;
        $methodCurrent = empty($method) ? $this->method : $method;
        $this->checkForEmpty($encryptedPassword, $keyCurrent, $methodCurrent);
        $ivLength = openssl_cipher_iv_length($methodCurrent);
        $ivWithCiphertext = base64_decode($encryptedPassword);
        $iv = substr($ivWithCiphertext, 0, $ivLength);
        $ciphertext = substr($ivWithCiphertext, $ivLength);
        $result = openssl_decrypt($ciphertext, $methodCurrent, $keyCurrent, OPENSSL_RAW_DATA, $iv);
        if ($result === false) {
            throw new CryptographyException('Password can not be decrypted');
        }
        return $result;
    }

    /**
     * Generates a random password with the specified length.
     * 
     * @param int $length The length of the generated password. Default is 7
     * @return string The generated random password.
     * @throws CryptographyException If the specified length is not a positive integer.
     */
    public function generateRandomPassword(int $length = 7): string
    {
        if ($length <= 0) {
            throw new CryptographyException("Password length must be a positive integer");
        }
        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= $this->passwordChars[rand(0, strlen($this->passwordChars) - 1)];
        }
        return $password;
    }

    /**
     * Generates a random password of the specified length, encrypts it, and returns
     * both the original and encrypted passwords.
     * 
     * @param int $length The length of the generated password. Default is 7
     * @param string $key (Optional) The encryption key to be used (default: class key).
     * @param string $method (Optional) The encryption method to be used (default: class method).
     * @return array An associative array containing the original and encrypted passwords.
     */
    public function encryptRandomPassword(int $length = 7, string $key = '', string $method = ''): array
    {
        $newPassword = $this->generateRandomPassword($length);
        $password = $this->encryptPassword($newPassword, $key, $method);

        return [
            'password' => $newPassword,
            'password_encrypted' => $password
        ];
    }

    /**
     * Verifies whether the provided password matches the encrypted password.
     * 
     * @param string $password The password to be verified.
     * @param string $encryptedPassword The encrypted password to compare against.
     * @param string $key (Optional) The encryption key used for encryption (default: class key).
     * @param string $method (Optional) The encryption method used for encryption (default: class method).
     * @return bool True if the passwords match, false otherwise.
     */
    public function verifyPassword(string $password, string $encryptedPassword, string $key = '', string $method = ''): bool
    {
        try {
            $decryptedPassword = $this->decryptPassword($encryptedPassword, $key, $method);
            return $password === $decryptedPassword ? true : false;
        } catch (CryptographyException $ex) {
            unset($ex);
            return false;
        }
    }

    /**
     * Returns the list of allowed encryption methods.
     * 
     * @return array The list of allowed encryption methods.
     */
    public function getAllowedMethods(): array
    {
        return $this->allowedMethods;
    }

    /**
     * Sets the characters to be used for generating random passwords.
     * 
     * @param string $passwordChars The characters to be used for password generation.
     * @return self
     */
    public function setDefaultPasswordChars(string $passwordChars): self
    {
        $this->passwordChars = $passwordChars;
        return $this;
    }

    /**
     * Checks if the given password, key, and method are empty, and throws an exception if so.
     * Also checks if the given method is valid.
     * 
     * @param string $password The password to be checked.
     * @param string $key The key to be checked.
     * @param string $method The method to be checked.
     * @throws CryptographyException If the password, key, or method is empty, or if the method is invalid.
     */
    private function checkForEmpty(string $password, string $key, string $method): void
    {
        if (empty($password)) {
            throw new CryptographyException("Empty password to encrypt");
        }
        if (empty($key)) {
            throw new CryptographyException("Empty key to encrypt password");
        }
        if (!array_key_exists($method, $this->allowedMethods)) {
            $allowedMethodsString = implode(',', $this->allowedMethods);
            throw new CryptographyException("Invalid encryption method. Allowed is" . ' ' . $allowedMethodsString);
        }
    }
}
