<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Log\LogManager;
use Psr\Log\LoggerInterface;

/**
 * The one place the package writes log lines.
 *
 * Lines go to the channel named by `authorization.log_channel`, or to the
 * application's default channel when it names none. A name that is not a
 * channel in `logging.channels` falls back to the default channel too, rather
 * than to Laravel's emergency logger. Logging never aborts a check: a logger
 * that fails is ignored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthorizationLog
{
    /**
     * Write a warning.
     *
     * @param  string  $message
     * @param  array<string, mixed>  $context
     * @return void
     */
    public static function warning(string $message, array $context = []): void
    {
        self::write('warning', $message, $context);
    }

    /**
     * Write a debug line.
     *
     * @param  string  $message
     * @param  array<string, mixed>  $context
     * @return void
     */
    public static function debug(string $message, array $context = []): void
    {
        self::write('debug', $message, $context);
    }

    /**
     * Write a line at the given level, ignoring any failure of the logger.
     *
     * @param  string  $level
     * @param  string  $message
     * @param  array<string, mixed>  $context
     * @return void
     */
    private static function write(string $level, string $message, array $context): void
    {
        // @codeCoverageIgnoreStart
        // Defensive: Laravel's `logger()` helper is always loaded under a
        // booted framework, so this is reachable only outside one.
        if (!\function_exists('logger')) {
            return;
        }

        // @codeCoverageIgnoreEnd
        try {
            $channel = self::channel(logger());

            $level === 'warning' ? $channel->warning($message, $context) : $channel->debug($message, $context);
        } catch (\Throwable) { // @phpstan-ignore catch.neverThrown
            // Intentional: logging must never abort an authorization check.
        }
    }

    /**
     * Resolve the channel to write to: the configured one when it exists,
     * otherwise the default. A logger that is not Laravel's log manager is
     * written to directly.
     *
     * @param  \Psr\Log\LoggerInterface  $logger
     * @return \Psr\Log\LoggerInterface
     */
    private static function channel(LoggerInterface $logger): LoggerInterface
    {
        if (!$logger instanceof LogManager) {
            return $logger;
        }

        $name = config('authorization.log_channel');

        return \is_string($name) && $name !== '' && config("logging.channels.{$name}") !== null
            ? $logger->channel($name)
            : $logger->channel();
    }
}
