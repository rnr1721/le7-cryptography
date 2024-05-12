<?php

declare(strict_types=1);

namespace rnr1721\Core\Contracts;

use rnr1721\Core\Exceptions\CryptographyException;

/**
 * Interface CryptographyInterface
 * Provides methods for encrypting and decrypting passwords.
 */
interface CryptographyInterface
{

    /**
     * Encrypts the given password.
     * 
     * @param string $password The password to be encrypted.
     * @param string $key (Optional) The encryption key to be used.
     * @param string $method (Optional) The encryption method to be used.
     * @return string The encrypted password.
     * @throws CryptographyException If the password or key is empty, or if the method is invalid.
     */
    public function encryptPassword(string $password, string $key = '', string $method = ''): string;

    /**
     * Decrypts the given encrypted password.
     * 
     * @param string $encryptedPassword The encrypted password to be decrypted.
     * @param string $key (Optional) The encryption key to be used.
     * @param string $method (Optional) The encryption method to be used.
     * @return string The decrypted password.
     * @throws CryptographyException If the encrypted password or key is empty, or if the method is invalid or if password can not be decrypted.
     */
    public function decryptPassword(string $encryptedPassword, string $key = '', string $method = ''): string;

    /**
     * Generates a random password with the specified length.
     * 
     * @param int $length The length of the generated password. Default is 7
     * @return string The generated random password.
     * @throws CryptographyException If the specified length is not a positive integer.
     */
    public function generateRandomPassword(int $length = 7): string;

    /**
     * Generates a random password of the specified length, encrypts it, and returns
     * both the original and encrypted passwords.
     * 
     * @param int $length The length of the generated password. Default is 7
     * @param string $key (Optional) The encryption key to be used (default: class key).
     * @param string $method (Optional) The encryption method to be used (default: class method).
     * @return array An associative array containing the original and encrypted passwords.
     */
    public function encryptRandomPassword(int $length = 7, string $key = '', string $method = ''): array;

    /**
     * Verifies whether the provided password matches the encrypted password.
     * 
     * @param string $password The password to be verified.
     * @param string $encryptedPassword The encrypted password to compare against.
     * @param string $key (Optional) The encryption key used for encryption (default: class key).
     * @param string $method (Optional) The encryption method used for encryption (default: class method).
     * @return bool True if the passwords match, false otherwise.
     */
    public function verifyPassword(string $password, string $encryptedPassword, string $key = '', string $method = ''): bool;

    /**
     * Returns the list of allowed encryption methods.
     * 
     * @return array The list of allowed encryption methods.
     */
    public function getAllowedMethods(): array;
}
