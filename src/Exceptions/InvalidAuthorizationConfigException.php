<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;

/**
 * Thrown at boot time when the shipped `authorization` config is malformed — a
 * misspelled class name in `permission_enums`, a `gate.enabled` switch that is
 * not strictly true or false, a `subject_resolver` that does not implement the
 * contract, a `cache.store` that the Laravel cache manager cannot resolve, and
 * so on.
 *
 * The exception carries the offending config key and the concrete reason so the
 * developer sees the exact fix path instead of a deep stack trace from the
 * first `can()` call in production.
 *
 * It also carries the refusal in a structured form the configuration report
 * lists (see `Diagnostics\ConfigIssue`): a stable code, what the setting
 * expects, written by the package, and the type of the value found. Unlike the
 * reason, none of them holds the value itself, so the report can show them
 * without showing what the configuration holds.
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
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode  $issue
     * @param  string|null  $expected
     * @param  string|null  $gotType
     */
    public function __construct(

        /** Dotted config key that triggered the failure. */
        private readonly string $configKey,

        /** Human-readable explanation of why the value failed validation. */
        private readonly string $reason,

        /** The stable code of the refusal. */
        private readonly IssueCode $issue = IssueCode::INVALID_VALUE,

        /** What the setting expects, written by the package and holding no configured value, or null when it is not stated. */
        private readonly ?string $expected = null,

        /** The type of the value refused, or null when it is not stated. */
        private readonly ?string $gotType = null,
    ) {
        parent::__construct(\sprintf('Invalid authorization config at \'%s\': %s', $configKey, $reason), 500);
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

    /**
     * Return the stable code of the refusal.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode
     */
    public function getIssue(): IssueCode
    {
        return $this->issue;
    }

    /**
     * Return what the setting expects, written by the package and holding no
     * configured value, or null when it is not stated.
     *
     * @return string|null
     */
    public function getExpected(): ?string
    {
        return $this->expected;
    }

    /**
     * Return the type of the value refused, or null when it is not stated.
     *
     * @return string|null
     */
    public function getGotType(): ?string
    {
        return $this->gotType;
    }
}
