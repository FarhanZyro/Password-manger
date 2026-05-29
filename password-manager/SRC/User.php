<?php
declare(strict_types=1);

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Encryption.php';

class User
{
    private ?int    $id           = null;
    private ?string $login        = null;
    private ?string $passwordHash = null;
    private ?string $encryptedKey = null;
    private ?string $decryptedKey = null;

    private PDO        $db;
    private Encryption $enc;
    private int        $bcryptCost;

    public function __construct(PDO $db, Encryption $enc, int $bcryptCost = 12)
    {
        $this->db         = $db;
        $this->enc        = $enc;
        $this->bcryptCost = $bcryptCost;
    }

    public function register(string $login, string $plainPassword): bool
    {
        $stmt = $this->db->prepare('SELECT id FROM users WHERE login = ? LIMIT 1');
        $stmt->execute([$login]);
        if ($stmt->fetch()) throw new RuntimeException("Login '{$login}' is already taken.");

        $hash  = password_hash($plainPassword, PASSWORD_BCRYPT, ['cost' => $this->bcryptCost]);
        $rawKey = $this->enc->generateKey();
        $encKey = $this->enc->encryptKey($rawKey, $plainPassword);

        $stmt = $this->db->prepare(
            'INSERT INTO users (login, password_hash, encrypted_key) VALUES (?, ?, ?)');
        $stmt->execute([$login, $hash, $encKey]);
        return true;
    }

    public function login(string $login, string $plainPassword): bool
    {
        $stmt = $this->db->prepare(
            'SELECT id, login, password_hash, encrypted_key FROM users WHERE login = ? LIMIT 1');
        $stmt->execute([$login]);
        $row = $stmt->fetch();

        if (!$row || !password_verify($plainPassword, $row['password_hash'])) return false;

        $this->id           = (int) $row['id'];
        $this->login        = $row['login'];
        $this->passwordHash = $row['password_hash'];
        $this->encryptedKey = $row['encrypted_key'];
        $this->decryptedKey = $this->enc->decryptKey($row['encrypted_key'], $plainPassword);
        return true;
    }

    public function changePassword(string $oldPassword, string $newPassword): bool
    {
        $this->assertAuthenticated();
        if (!password_verify($oldPassword, $this->passwordHash)) return false;

        $newHash   = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => $this->bcryptCost]);
        $newEncKey = $this->enc->rekeyWithNewPassword($this->encryptedKey, $oldPassword, $newPassword);

        $stmt = $this->db->prepare(
            'UPDATE users SET password_hash = ?, encrypted_key = ? WHERE id = ?');
        $stmt->execute([$newHash, $newEncKey, $this->id]);

        $this->passwordHash = $newHash;
        $this->encryptedKey = $newEncKey;
        return true;
    }

    public function getId(): int           { $this->assertAuthenticated(); return $this->id; }
    public function getLogin(): string     { $this->assertAuthenticated(); return $this->login; }
    public function getDecryptedKey(): string { $this->assertAuthenticated(); return $this->decryptedKey; }
    public function isLoggedIn(): bool     { return $this->id !== null && $this->decryptedKey !== null; }

    private function assertAuthenticated(): void
    {
        if (!$this->isLoggedIn()) throw new RuntimeException('Not authenticated.');
    }
}