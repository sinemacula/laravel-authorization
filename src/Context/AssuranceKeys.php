<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;

/**
 * The assurance keys of the authentication context, which no condition may test
 * (AUTHZ-8.9, N37, N104).
 *
 * An assurance key is a key of `authentication`, or of a namespace the
 * authentication context contributes beside it (such as `mfa`), any segment of
 * whose path after the namespace is one of the fixed names below, or one of the
 * names the authentication context declares itself (see
 * `AuthenticationContext::assuranceKeys()`), so `authentication.amr` and
 * `mfa.multifactor.enabled` are both assurance keys. A declared name is exact,
 * or ends in one `*` and matches every segment starting with what comes before
 * it, as `provider_*` matches `provider_name`.
 *
 * The package declares none of them itself, but whatever the declaring context
 * or configuration says, the key catalogue declares each one untestable, and a
 * policy that tests one, or reads one through a `${…}` reference, is refused on
 * write and pointed at the `authentication_requirement` operator: separate
 * scalar tests could be met by a fresh weak proof and a stale strong one
 * together, which the requirement checker never allows.
 *
 * A declared name that is not a string, is empty, holds a `.` or has a `*`
 * anywhere but at its end is refused with `InvalidArgumentException`, so a
 * malformed declaration fails closed rather than leaving a key testable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AssuranceKeys
{
    /** @var list<string> The names that make a key of the authentication context an assurance key, whatever the context declares. */
    public const array NAMES = ['assurance_level', 'auth_time', 'seconds_since_step_up', 'last_verified_at', 'verification_age', 'multifactor', 'amr'];

    /** @var string The namespace the authentication context always supplies. */
    public const string NAMESPACE = 'authentication';

    /** @var string Why a policy may not read an assurance key, and what to write instead. */
    public const string REASON = 'is an assurance key, which no condition may test or reference; state the requirement with the '
        . AuthenticationRequirement::OPERATOR . ' operator on the key \'' . AuthenticationRequirement::KEY . '\' instead.';

    /** @var string What a declared name may be: something with no `.` or `*`, then at most one trailing `*`. */
    public const string NAME_PATTERN = '/\A[^.*]+\*?\z/';

    /** @var string The form a declared name must take, as a refusal states it. */
    private const string NAME_FORM = 'a name with no \'.\', or a name followed by one trailing \'*\'';

    /** @var list<string> The names that make a key an assurance key: the fixed ones, then those declared. */
    public array $names;

    /**
     * Create the assurance keys of `authentication` and the namespaces given,
     * with the names declared beside the fixed ones, refusing a declaration
     * that is not a list of names in the accepted form, as made by the owner
     * named.
     *
     * @param  list<string>  $namespaces
     * @param  array<array-key, mixed>  $declared
     * @param  string  $owner
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The namespaces the authentication context contributes beside `authentication`. */
        public array $namespaces = [],

        // The names declared beside the fixed ones, each in the accepted form.
        array $declared = [],

        // Who made the declaration, as a refusal names it.
        string $owner = 'The authentication context',
    ) {
        $this->names = [...self::NAMES, ...self::validated($declared, $owner)];
    }

    /**
     * Return the assurance keys of the authentication context: those of the
     * namespaces it supplies, under the fixed names and the names it declares.
     * Without a context only `authentication` holds assurance keys, under the
     * fixed names.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext|null  $context
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(?AuthenticationContext $context): self
    {
        return $context === null
            ? new self
            : new self($context->namespaces(), $context->assuranceKeys(), 'Authentication context \'' . $context::class . '\'');
    }

    /**
     * Determine whether the dot path is an assurance key, given the namespaces
     * the authentication context contributes beside `authentication` and the
     * names it declares.
     *
     * @param  string  $path
     * @param  list<string>  $namespaces
     * @param  list<string>  $declared
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function isAssuranceKey(string $path, array $namespaces = [], array $declared = []): bool
    {
        return (new self($namespaces, $declared))->matches($path);
    }

    /**
     * Determine whether the dot path is one of these assurance keys: its
     * namespace is `authentication` or a contributed one, and a segment after
     * the namespace is one of the names, or starts with a declared prefix.
     *
     * @param  string  $path
     * @return bool
     */
    public function matches(string $path): bool
    {
        $segments  = \explode('.', $path);
        $namespace = \array_shift($segments);

        return ($namespace === self::NAMESPACE || \in_array($namespace, $this->namespaces, true))
            && \array_filter($segments, $this->isName(...)) !== [];
    }

    /**
     * Determine whether the segment is one of the names, or starts with what
     * comes before the `*` of a prefix.
     *
     * @param  string  $segment
     * @return bool
     */
    private function isName(string $segment): bool
    {
        foreach ($this->names as $name) {
            if ($name === $segment || (\str_ends_with($name, '*') && \str_starts_with($segment, \substr($name, 0, -1)))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the declared names, refusing a declaration that is not a list of
     * names in the accepted form.
     *
     * @param  array<array-key, mixed>  $declared
     * @param  string  $owner
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private static function validated(array $declared, string $owner): array
    {
        if (!\array_is_list($declared)) {
            throw new \InvalidArgumentException("{$owner} must declare its assurance keys as a list, each " . self::NAME_FORM . '.');
        }

        foreach ($declared as $name) {
            if (!\is_string($name) || \preg_match(self::NAME_PATTERN, $name) !== 1) {
                $given = \is_string($name) ? "'{$name}'" : \get_debug_type($name);

                throw new \InvalidArgumentException("{$owner} declares the assurance key {$given}, which must be " . self::NAME_FORM . '.');
            }
        }

        return $declared;
    }
}
