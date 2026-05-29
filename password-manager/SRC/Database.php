<?php
declare(strict_types=1);

class Database
{
    private static ?Database $instance = null;
    private PDO $pdo;

    private function __construct(array $cfg)
    {
        $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s',
            $cfg['host'], $cfg['dbname'], $cfg['charset']);

        $this->pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }

    private function __clone() {}

    public static function getInstance(?array $cfg = null): self
    {
        if (self::$instance === null) {
            if ($cfg === null) {
                throw new RuntimeException('Database not yet initialised.');
            }
            self::$instance = new self($cfg);
        }
        return self::$instance;
    }

    public function getConnection(): PDO
    {
        return $this->pdo;
    }
}