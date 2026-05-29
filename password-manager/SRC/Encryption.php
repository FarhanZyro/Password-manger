<?php
declare(strict_types=1);

class Encryption
{
    private const CIPHER     = 'aes-256-cbc';
    private const KEY_BYTES  = 32;
    private const IV_BYTES   = 16;
    private const PBKDF2_ALG = 'sha256';

    private int $pbkdf2Iterations;

    public function __construct(int $pbkdf2Iterations = 100000)
    {
        $this->pbkdf2Iterations = $pbkdf2Iterations;
    }

    public function generateKey(): string
    {
        return random_bytes(self::KEY_BYTES);
    }

    public function encryptKey(string $rawKey, string $loginPassword, string $salt = ''): string
    {
        if ($salt === '') $salt = random_bytes(16);
        $wrappingKey = $this->deriveKey($loginPassword, $salt);
        $iv          = random_bytes(self::IV_BYTES);
        $cipher      = openssl_encrypt($rawKey, self::CIPHER, $wrappingKey, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) throw new RuntimeException('Key encryption failed.');
        return base64_encode($salt . $iv . $cipher);
    }

    public function decryptKey(string $stored, string $loginPassword): string
    {
        $blob        = base64_decode($stored, true);
        $salt        = substr($blob, 0, 16);
        $iv          = substr($blob, 16, self::IV_BYTES);
        $cipher      = substr($blob, 16 + self::IV_BYTES);
        $wrappingKey = $this->deriveKey($loginPassword, $salt);
        $rawKey      = openssl_decrypt($cipher, self::CIPHER, $wrappingKey, OPENSSL_RAW_DATA, $iv);
        if ($rawKey === false) throw new RuntimeException('Key decryption failed.');
        return $rawKey;
    }

    public function rekeyWithNewPassword(string $stored, string $old, string $new): string
    {
        $rawKey = $this->decryptKey($stored, $old);
        return $this->encryptKey($rawKey, $new);
    }

    public function encryptPassword(string $plainPassword, string $rawKey): string
    {
        $iv     = random_bytes(self::IV_BYTES);
        $cipher = openssl_encrypt($plainPassword, self::CIPHER, $rawKey, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) throw new RuntimeException('Password encryption failed.');
        return base64_encode($iv . $cipher);
    }

    public function decryptPassword(string $stored, string $rawKey): string
    {
        $blob   = base64_decode($stored, true);
        $iv     = substr($blob, 0, self::IV_BYTES);
        $cipher = substr($blob, self::IV_BYTES);
        $plain  = openssl_decrypt($cipher, self::CIPHER, $rawKey, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) throw new RuntimeException('Password decryption failed.');
        return $plain;
    }

    private function deriveKey(string $password, string $salt): string
    {
        return hash_pbkdf2(self::PBKDF2_ALG, $password, $salt,
            $this->pbkdf2Iterations, self::KEY_BYTES, true);
    }
}