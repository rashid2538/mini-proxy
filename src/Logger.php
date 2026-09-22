<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Minimal leveled file logger for miniProxy.
 *
 * Logging is best-effort: failures never break the proxied request. The front
 * controller wires the destination and verbosity from LOG_FILE / LOG_LEVEL.
 * When no file is configured, every method is a no-op.
 *
 * Levels (least → most verbose): error, access, info, debug.
 * A configured level logs that level and everything below it in verbosity
 * (i.e. `debug` logs everything, `error` logs only errors).
 */
class Logger
{
    public const DEBUG = 100;
    public const INFO = 200;
    public const ACCESS = 250;
    public const ERROR = 400;

    /** Path of the log file; empty string disables logging. */
    private static string $logFile = '';

    /** Minimum level that gets written. Default: errors + access lines. */
    private static int $minLevel = self::ACCESS;

    /** Rotate the log file once it exceeds this size (bytes). */
    private const MAX_FILE_SIZE = 20_971_520; // 20 MB

    public static function setLogFile(string $path): void
    {
        self::$logFile = trim($path);
    }

    /**
     * Sets the minimum log verbosity from a level name.
     *
     * @param string $level One of 'error', 'access', 'info', 'debug'.
     */
    public static function setLevel(string $level): void
    {
        self::$minLevel = match (strtolower($level)) {
            'debug' => self::DEBUG,
            'info' => self::INFO,
            'error' => self::ERROR,
            default => self::ACCESS,
        };
    }

    public static function isEnabled(): bool
    {
        return self::$logFile !== '';
    }

    /** True when access-log lines will actually be written. */
    public static function accessEnabled(): bool
    {
        return self::$logFile !== '' && self::$minLevel <= self::ACCESS;
    }

    /**
     * Appends a single line to the log file if its level passes the threshold.
     *
     * @param string $message The message to log.
     * @param int    $level   Log level (Logger::DEBUG / INFO / ACCESS / ERROR).
     */
    public static function log(string $message, int $level = self::INFO): void
    {
        $file = self::$logFile;
        if ($file === '' || $level < self::$minLevel) {
            return;
        }

        if (is_file($file) && filesize($file) > self::MAX_FILE_SIZE) {
            @rename($file, $file . '.1');
        }

        $label = match ($level) {
            self::DEBUG => 'DEBUG',
            self::INFO => 'INFO',
            self::ACCESS => 'ACCESS',
            default => 'ERROR',
        };

        $line = sprintf("[%s] %-6s %s\n", date('Y-m-d H:i:s'), $label, $message);
        @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }

    public static function debug(string $message): void
    {
        self::log($message, self::DEBUG);
    }

    public static function info(string $message): void
    {
        self::log($message, self::INFO);
    }

    public static function error(string $message): void
    {
        self::log($message, self::ERROR);
    }

    /**
     * Logs a single proxied request in a grep-friendly format:
     *
     *   IP METHOD URL STATUS BYTES DURATION_SECONDS
     *
     * @param string $ip       Client IP address.
     * @param string $method   Request method (GET, POST, ...).
     * @param string $url      The proxied target URL.
     * @param int    $status   Response status code.
     * @param int    $bytes    Response body size in bytes.
     * @param float  $duration Request duration in seconds.
     */
    public static function access(
        string $ip,
        string $method,
        string $url,
        int $status,
        int $bytes = 0,
        float $duration = 0.0
    ): void {
        self::log(
            sprintf('%s %s %s %d %d %.3f', $ip, $method, $url, $status, $bytes, $duration),
            self::ACCESS
        );
    }
}