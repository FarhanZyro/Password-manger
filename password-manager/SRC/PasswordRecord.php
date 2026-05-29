<?php
declare(strict_types=1);

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Encryption.php';

class PasswordRecord
{
    private ?int      $id                = null;
    private int       $userId;
    private string    $siteName          = '';
    private string    $encryptedPassword = '';
    private ?DateTime $createdAt         = null;

    private PDO        $db;
    private Encryption $enc;

    public function __construct(PDO $db, Encryption $enc, int $userId)
    {
        $this->db     = $db;
        $this->enc    = $enc;
        $this->userId = $userId;
    }

    public function save(string $siteName, string $plainPassword, string $rawKey): bool
    {
        $this->siteName          = $siteName;
        $this->encryptedPassword = $this->enc->encryptPassword($plainPassword, $rawKey);

        $stmt = $this->db->prepare(
            'INSERT INTO password_records (user_id, site_name, encrypted_password) VALUES (?, ?, ?)');
        $stmt->execute([$this->userId, $this->siteName, $this->encryptedPassword]);

        $this->id        = (int) $this->db->lastInsertId();
        $this->createdAt = new DateTime();
        return true;
    }

    public function loadById(int $id): bool
    {
        $stmt = $this->db->prepare(
            'SELECT * FROM password_records WHERE id = ? AND user_id = ? LIMIT 1');
        $stmt->execute([$id, $this->userId]);
        $row = $stmt->fetch();
        if (!$row) return false;

        $this->id                = (int) $row['id'];
        $this->siteName          = $row['site_name'];
        $this->encryptedPassword = $row['encrypted_password'];
        $this->createdAt         = new DateTime($row['created_at']);
        return true;
    }

    public function delete(): bool
    {
        if ($this->id === null) throw new RuntimeException('Record not saved yet.');
        $stmt = $this->db->prepare(
            'DELETE FROM password_records WHERE id = ? AND user_id = ?');
        $stmt->execute([$this->id, $this->userId]);
        $this->id = null;
        return true;
    }

    public static function getAllForUser(PDO $db, Encryption $enc, int $userId): array
    {
        $stmt = $db->prepare(
            'SELECT * FROM password_records WHERE user_id = ? ORDER BY site_name ASC');
        $stmt->execute([$userId]);

        $records = [];
        foreach ($stmt->fetchAll() as $row) {
            $rec                      = new self($db, $enc, $userId);
            $rec->id                  = (int) $row['id'];
            $rec->siteName            = $row['site_name'];
            $rec->encryptedPassword   = $row['encrypted_password'];
            $rec->createdAt           = new DateTime($row['created_at']);
            $records[]                = $rec;
        }
        return $records;
    }

    public function getId(): int               { return $this->id; }
    public function getSiteName(): string      { return $this->siteName; }
    public function getCreatedAt(): ?DateTime  { return $this->createdAt; }

    public function getDecryptedPassword(string $rawKey): string
    {
        return $this->enc->decryptPassword($this->encryptedPassword, $rawKey);
    }
}