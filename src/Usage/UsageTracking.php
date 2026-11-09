<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use SineMacula\Laravel\Authorization\Config\UsageConfigValidator;

/**
 * The settings of grant usage tracking (N94, N101), read from
 * `authorization.usage` and checked as the config is checked at boot (see
 * `Config\UsageConfigValidator`), so a setting changed after boot is refused
 * rather than replaced by another.
 *
 * Tracking is off unless `enabled` is true. Observations are bucketed by
 * `interval` seconds, 3600 by default: a bucket starts at a whole multiple of
 * the interval since the Unix epoch, in UTC, so every worker agrees where each
 * starts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UsageTracking
{
    /** @var int The length of a bucket, in seconds, when none is configured. */
    public const int INTERVAL = 3600;

    /** @var int How many observations a worker holds before it flushes them, when none is configured. */
    public const int BATCH = 1000;

    /** @var int How many days coverage is kept, when none is configured. */
    public const int RETENTION = 400;

    /**
     * Determine whether grant usage is tracked.
     *
     * @return bool
     */
    public static function isEnabled(): bool
    {
        return UsageConfigValidator::enabled(config('authorization.usage.enabled', false));
    }

    /**
     * Return the length of a bucket, in seconds.
     *
     * @return int
     */
    public static function interval(): int
    {
        return UsageConfigValidator::whole('interval', config('authorization.usage.interval', self::INTERVAL));
    }

    /**
     * Return how many observations a worker holds before it flushes them.
     *
     * @return int
     */
    public static function batch(): int
    {
        return UsageConfigValidator::whole('batch', config('authorization.usage.batch', self::BATCH));
    }

    /**
     * Return how many days coverage is kept.
     *
     * @return int
     */
    public static function retention(): int
    {
        return UsageConfigValidator::whole('retention', config('authorization.usage.retention', self::RETENTION));
    }

    /**
     * Return the queue connection the recording job is sent to, or null for the
     * default.
     *
     * @return string|null
     */
    public static function connection(): ?string
    {
        return UsageConfigValidator::name('connection', config('authorization.usage.connection'));
    }

    /**
     * Return the queue the recording job is sent to, or null for the
     * connection's default.
     *
     * @return string|null
     */
    public static function queue(): ?string
    {
        return UsageConfigValidator::name('queue', config('authorization.usage.queue'));
    }

    /**
     * Return the start of the bucket the timestamp falls in, as a UTC
     * timestamp.
     *
     * @param  int  $timestamp
     * @param  int  $interval
     * @return int
     */
    public static function bucketOf(int $timestamp, int $interval): int
    {
        return (int) \floor($timestamp / $interval) * $interval;
    }
}
