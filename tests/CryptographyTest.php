<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rnr1721\Core\Cryptography;
use rnr1721\Core\Exceptions\CryptographyException;

final class CryptographyTest extends TestCase
{

    /**
     * Test encryption and decryption with default key.
     */
    public function testEncryptDecrypt(): void
    {
        $cryptographyTmp = new Cryptography('');

        $password = 'my_password';

        $methods = $cryptographyTmp->getAllowedMethods();

        foreach (array_keys($methods) as $method) {
            $cryptography = new Cryptography('my_secret_key', $method);
            $encryptedPassword = $cryptography->encryptPassword($password);
            $decryptedPassword = $cryptography->decryptPassword($encryptedPassword);

            $this->assertEquals($password, $decryptedPassword);
        }
    }

    /**
     * Test encryption and decryption with custom key.
     */
    public function testEncryptDecryptCustomKey(): void
    {

        $cryptographyTmp = new Cryptography('');

        $methods = $cryptographyTmp->getAllowedMethods();

        foreach (array_keys($methods) as $method) {

            $cryptography = new Cryptography('', $method);
            $password = 'my_password';

            $key = 'my_secret_key';

            $encryptedPassword = $cryptography->encryptPassword($password, $key);
            $decryptedPassword = $cryptography->decryptPassword($encryptedPassword, $key);

            $this->assertEquals($password, $decryptedPassword);
        }
    }

    /**
     * Test generation of random password and encryption/decryption of it.
     */
    public function testGenerateRandomPassword(): void
    {
        $cryptography = new Cryptography('my_secret_key');
        $length = 10;

        $randomPassword = $cryptography->generateRandomPassword($length);

        $this->assertEquals($length, strlen($randomPassword));

        $randomEncryptedPassword = $cryptography->encryptRandomPassword(5, 'my_secret_key_2', 'AES-256-CBC');

        $randomDecryptedPassword = $cryptography->decryptPassword($randomEncryptedPassword['password_encrypted'], 'my_secret_key_2', 'AES-256-CBC');

        $this->assertEquals(2, count($randomEncryptedPassword));
        $this->assertEquals(5, strlen($randomEncryptedPassword['password']));
        $this->assertEquals($randomDecryptedPassword, $randomEncryptedPassword['password']);
    }

    /**
     * Test password verification.
     */
    public function testVerifyPassword(): void
    {
        $cryptography = new Cryptography('my_secret_key');
        $password = 'my_password';
        $encryptedPassword = $cryptography->encryptPassword($password);

        $isValid = $cryptography->verifyPassword($password, $encryptedPassword);

        $isNotValid = $cryptography->verifyPassword('wrongpassword', $encryptedPassword);

        $this->assertTrue($isValid);
        $this->assertFalse($isNotValid);
    }

    /**
     * Test decryption with invalid encrypted password.
     */
    public function testDecryptPasswordWithInvalidPassword(): void
    {
        $cryptography = new Cryptography('my_secret_key', 'AES-256-CBC');
        $invalidEncryptedPassword = 'invalid_encrypted_password';

        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('Password can not be decrypted');
        $cryptography->decryptPassword($invalidEncryptedPassword);
    }

    /**
     * Test encryption with empty password.
     */
    public function testEncryptPasswordWithEmptyData(): void
    {
        $cryptography = new Cryptography('my_secret_key', 'AES-256-CBC');
        $emptyPassword = '';

        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('Empty password to encrypt');
        $cryptography->encryptPassword($emptyPassword);
    }

    /**
     * Test decryption with empty encrypted password.
     */
    public function testDecryptPasswordWithEmptyData(): void
    {
        $cryptography = new Cryptography('my_secret_key', 'AES-256-CBC');
        $emptyEncryptedPassword = '';

        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('Empty password to encrypt');
        $cryptography->decryptPassword($emptyEncryptedPassword);
    }

    /**
     * Test encryption with empty key.
     */
    public function testEncryptPasswordWithEmptyKey(): void
    {
        $cryptography = new Cryptography('', 'AES-256-CBC');
        $password = 'my_password';

        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('Empty key to encrypt password');
        $cryptography->encryptPassword($password);
    }

    /**
     * Test decryption with empty key.
     */
    public function testDecryptPasswordWithEmptyKey(): void
    {
        $cryptography = new Cryptography('', 'AES-256-CBC');
        $encryptedPassword = 'my_encrypted_password';

        $this->expectException(CryptographyException::class);
        $this->expectExceptionMessage('Empty key to encrypt password');
        $cryptography->decryptPassword($encryptedPassword);
    }
}
