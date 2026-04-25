<?php

namespace PolkitGuard;

class Severity
{
    public const LOW = 1;
    public const MEDIUM = 2;
    public const HIGH = 3;
    public const CRITICAL = 4;

    public static function fromInt(int $value): int
    {
        return match ($value) {
            4 => self::CRITICAL,
            3 => self::HIGH,
            2 => self::MEDIUM,
            default => self::LOW,
        };
    }

    public static function toString(int $severity): string
    {
        return match ($severity) {
            self::CRITICAL => 'CRITICAL',
            self::HIGH => 'HIGH',
            self::MEDIUM => 'MEDIUM',
            default => 'LOW',
        };
    }
}