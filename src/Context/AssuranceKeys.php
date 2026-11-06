<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;

/**
 * The assurance keys of the authentication context, which no condition may test
 * (AUTHZ-8.9, N37).
 *
 * An assurance key is a key of `authentication`, or of a namespace the
 * authentication context contributes beside it (such as `mfa`), any segment of
 * whose path after the namespace is one of the fixed names below, so
 * `authentication.amr` and `mfa.multifactor.enabled` are both assurance keys.
 * The package declares none of them itself, but whatever the declaring context
 * or configuration says, the key catalogue declares each one untestable, and a
 * policy that tests one, or reads one through a `${…}` reference, is refused on
 * write and pointed at the `authentication_requirement` operator: separate
 * scalar tests could be met by a fresh weak proof and a stale strong one
 * together, which the requirement checker never allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AssuranceKeys
{
    /** @var list<string> The names that make a key of the authentication context an assurance key. */
    public const array NAMES = ['assurance_level', 'auth_time', 'seconds_since_step_up', 'last_verified_at', 'verification_age', 'multifactor', 'amr'];

    /** @var string The namespace the authentication context always supplies. */
    public const string NAMESPACE = 'authentication';

    /** @var string Why a policy may not read an assurance key, and what to write instead. */
    public const string REASON = 'is an assurance key, which no condition may test or reference; state the requirement with the '
        . AuthenticationRequirement::OPERATOR . ' operator on the key \'' . AuthenticationRequirement::KEY . '\' instead.';

    /**
     * Determine whether the dot path is an assurance key, given the namespaces
     * the authentication context contributes beside `authentication`.
     *
     * @param  string  $path
     * @param  list<string>  $namespaces
     * @return bool
     */
    public static function isAssuranceKey(string $path, array $namespaces = []): bool
    {
        $segments  = \explode('.', $path);
        $namespace = \array_shift($segments);

        return ($namespace === self::NAMESPACE || \in_array($namespace, $namespaces, true))
            && \array_intersect($segments, self::NAMES) !== [];
    }
}
