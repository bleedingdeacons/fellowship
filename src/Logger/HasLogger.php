<?php

declare(strict_types=1);

namespace Fellowship\Logger;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Safe logging trait — silently no-ops if the shared logger mu-plugin
 * (deployed by Sentinel) is not available.
 *
 * This file is a local copy so the trait resolves via this plugin's own
 * autoloader with no cross-plugin dependency at class-load time.
 */
trait HasLogger
{
    private static ?\Sentinel_Log_Channel $loggerChannel = null;

    protected static function logChannel(): string
    {
        $parts = explode('\\', static::class);
        return sanitize_key(end($parts));
    }

    public static function log(): ?\Sentinel_Log_Channel
    {
        if (self::$loggerChannel === null && function_exists('wp_log')) {
            self::$loggerChannel = wp_log(static::logChannel());
        }
        return self::$loggerChannel;
    }

    /** @param array<string, mixed> $context */
    public static function logEmergency(string $message, array $context = []): void
    {
        static::log()?->emergency($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logAlert(string $message, array $context = []): void
    {
        static::log()?->alert($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logCritical(string $message, array $context = []): void
    {
        static::log()?->critical($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logError(string $message, array $context = []): void
    {
        static::log()?->error($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logWarning(string $message, array $context = []): void
    {
        static::log()?->warning($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logNotice(string $message, array $context = []): void
    {
        static::log()?->notice($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logInfo(string $message, array $context = []): void
    {
        static::log()?->info($message, $context);
    }

    /** @param array<string, mixed> $context */
    public static function logDebug(string $message, array $context = []): void
    {
        static::log()?->debug($message, $context);
    }
}
