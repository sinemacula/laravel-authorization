<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validation of a config key that names the class implementing one of
 * the package's contracts, shared by the validators of such keys.
 *
 * The value must name an existing class implementing the contract. Null is
 * refused with the reason the key's validator gives, rather than read as "no
 * implementation", so a missing class fails at boot instead of changing what
 * the package does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ImplementationConfigValidator
{
    /**
     * Validate that the value names a class implementing the contract, throwing
     * under the key when it does not.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  class-string  $contract
     * @param  string  $required
     * @return void
     *
     * @phpstan-assert class-string $value
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(string $key, mixed $value, string $contract, string $required): void
    {
        [$issue, $reason] = match (true) {
            $value                        === null => [IssueCode::REQUIRED, $required],
            !\is_string($value) || $value === ''   => [IssueCode::INVALID_TYPE, 'expected a class-string, got ' . \get_debug_type($value) . '.'],
            !\class_exists($value)                 => [IssueCode::UNKNOWN_CLASS, "class '{$value}' does not exist."],
            !\is_a($value, $contract, true)        => [IssueCode::NOT_IMPLEMENTED, "class '{$value}' does not implement {$contract}."],
            default                                => [null, ''],
        };

        if ($issue !== null) {
            throw new InvalidAuthorizationConfigException($key, $reason, $issue, "the name of a class implementing {$contract}", \get_debug_type($value));
        }
    }
}
