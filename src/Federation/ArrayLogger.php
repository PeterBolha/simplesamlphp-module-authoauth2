<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Federation;

use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * PSR-3 logger collecting entries into an array, for display on the admin
 * federation pages (mirrors the oidc module's debug ArrayLogger).
 */
class ArrayLogger implements LoggerInterface
{
    public const int WEIGHT_EMERGENCY = 8;
    public const int WEIGHT_ALERT = 7;
    public const int WEIGHT_CRITICAL = 6;
    public const int WEIGHT_ERROR = 5;
    public const int WEIGHT_WARNING = 4;
    public const int WEIGHT_NOTICE = 3;
    public const int WEIGHT_INFO = 2;
    public const int WEIGHT_DEBUG = 1;

    protected int $weight;

    /** @var list<string> */
    protected array $entries = [];

    public function __construct(int $weight = self::WEIGHT_DEBUG)
    {
        $this->setWeight($weight);
    }

    public function setWeight(int $weight): void
    {
        $this->weight = max(self::WEIGHT_DEBUG, min($weight, self::WEIGHT_EMERGENCY));
    }

    /**
     * @return list<string>
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    public function emergency(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::EMERGENCY, $message, $context);
    }

    public function alert(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::ALERT, $message, $context);
    }

    public function critical(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::CRITICAL, $message, $context);
    }

    public function error(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::ERROR, $message, $context);
    }

    public function warning(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::WARNING, $message, $context);
    }

    public function notice(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::NOTICE, $message, $context);
    }

    public function info(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::INFO, $message, $context);
    }

    public function debug(\Stringable|string $message, array $context = []): void
    {
        $this->log(LogLevel::DEBUG, $message, $context);
    }

    /**
     * @param mixed $level
     */
    public function log($level, \Stringable|string $message, array $context = []): void
    {
        $weight = match ((string) $level) {
            LogLevel::EMERGENCY => self::WEIGHT_EMERGENCY,
            LogLevel::ALERT => self::WEIGHT_ALERT,
            LogLevel::CRITICAL => self::WEIGHT_CRITICAL,
            LogLevel::ERROR => self::WEIGHT_ERROR,
            LogLevel::WARNING => self::WEIGHT_WARNING,
            LogLevel::NOTICE => self::WEIGHT_NOTICE,
            LogLevel::INFO => self::WEIGHT_INFO,
            LogLevel::DEBUG => self::WEIGHT_DEBUG,
            default => throw new InvalidArgumentException("Unrecognized log level '$level'"),
        };

        if ($this->weight > $weight) {
            return;
        }

        $this->entries[] = sprintf(
            '%s %s %s%s',
            gmdate('Y-m-d\TH:i:s.v\Z'),
            strtoupper((string) $level),
            (string) $message,
            $context === [] ? '' : ' Context: ' . var_export($context, true),
        );
    }
}
