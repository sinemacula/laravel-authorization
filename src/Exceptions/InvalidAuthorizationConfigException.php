<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown at boot time when the shipped `authorization` config is malformed — a
 * misspelled class name in `permission_enums`, a `gate.on_conflict` value
 * outside the three accepted sentinels, a `principal_resolver` that does not
 * implement the contract, a `cache.store` that the Laravel cache manager cannot
 * resolve, and so on.
 *
 * The exception carries the offending config key and the concrete reason so the
 * developer sees the exact fix path instead of a deep stack trace from the
 * first `can()` call in production.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidAuthorizationConfigException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $configKey
     * @param  string  $reason
     */
    public function __construct(

        /** Dotted config key that triggered the failure. */
        private readonly string $configKey,

        /** Human-readable explanation of why the value failed validation. */
        private readonly string $reason,
    ) {
        parent::__construct(
            "Invalid authorization config at '{$configKey}': {$reason}",
            500,
        );
    }

    /**
     * Return the config key that triggered the failure.
     *
     * @return string
     */
    public function getConfigKey(): string
    {
        return $this->configKey;
    }

    /**
     * Return the reason the value failed validation.
     *
     * @return string
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
