<?php
declare(strict_types=1);

class PasswordGenerator
{
    private const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    private const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const NUMBERS   = '0123456789';
    private const SPECIAL   = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    private int $length;
    private int $lowercaseCount;
    private int $uppercaseCount;
    private int $numbersCount;
    private int $specialCount;

    public function __construct(int $length, int $lower, int $upper, int $numbers, int $special)
    {
        $this->length         = $length;
        $this->lowercaseCount = $lower;
        $this->uppercaseCount = $upper;
        $this->numbersCount   = $numbers;
        $this->specialCount   = $special;
    }

    public static function fromPercents(int $length, float $lPct, float $uPct, float $nPct, float $sPct): self
    {
        $l = (int) round($length * $lPct / 100);
        $u = (int) round($length * $uPct / 100);
        $n = (int) round($length * $nPct / 100);
        $s = (int) round($length * $sPct / 100);
        $l += $length - ($l + $u + $n + $s); // absorb rounding remainder
        return new self($length, $l, $u, $n, $s);
    }

    public function generate(): string
    {
        $this->validate();
        $chars = array_merge(
            $this->pick(self::LOWERCASE, $this->lowercaseCount),
            $this->pick(self::UPPERCASE, $this->uppercaseCount),
            $this->pick(self::NUMBERS,   $this->numbersCount),
            $this->pick(self::SPECIAL,   $this->specialCount)
        );
        $this->shuffle($chars);
        return implode('', $chars);
    }

    public function validate(): void
    {
        $sum = $this->lowercaseCount + $this->uppercaseCount
             + $this->numbersCount   + $this->specialCount;
        if ($sum !== $this->length)
            throw new InvalidArgumentException("Counts ({$sum}) must equal length ({$this->length}).");
        if ($this->length < 1)
            throw new InvalidArgumentException('Length must be at least 1.');
    }

    // Getters
    public function getLength(): int         { return $this->length; }
    public function getLowercaseCount(): int { return $this->lowercaseCount; }
    public function getUppercaseCount(): int { return $this->uppercaseCount; }
    public function getNumbersCount(): int   { return $this->numbersCount; }
    public function getSpecialCount(): int   { return $this->specialCount; }

    // Setters
    public function setLength(int $n): void        { $this->length = $n; }
    public function setLowercaseCount(int $n): void { $this->lowercaseCount = $n; }
    public function setUppercaseCount(int $n): void { $this->uppercaseCount = $n; }
    public function setNumbersCount(int $n): void   { $this->numbersCount = $n; }
    public function setSpecialCount(int $n): void   { $this->specialCount = $n; }

    private function pick(string $charset, int $count): array
    {
        $result = [];
        $max    = strlen($charset) - 1;
        for ($i = 0; $i < $count; $i++) $result[] = $charset[random_int(0, $max)];
        return $result;
    }

    private function shuffle(array &$arr): void
    {
        for ($i = count($arr) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$arr[$i], $arr[$j]] = [$arr[$j], $arr[$i]];
        }
    }
}