<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Authentication context contract (AUTHZ-8.2, AUTHZ-13.2).
 *
 * Supplies the `authentication` namespace of the context, and any namespace it
 * contributes beside it (`mfa` or `sso`, under their own names), whose keys it
 * declares in the context key catalogue. It is trusted: its values come from
 * the authentication the application knows about, never from what the caller
 * passes, and only rebinding this contract replaces it.
 *
 * The shipped default supplies what Laravel knows: the default guard's name and
 * the signed-in user's key and morph type. Under the suite it is
 * `laravel-authentication`'s authentication context, with its key names.
 *
 * It also declares the names that make a key of its namespaces an assurance key
 * (AUTHZ-8.9, N104), beside the package's fixed `AssuranceKeys::NAMES`, so a
 * sibling package's assurance keys are as untestable as the package's own.
 *
 * `namespaces()` and `assuranceKeys()` must answer the same for the life of the
 * process: they are read once, after every service provider has registered, at
 * boot by the configuration validation and at first use by the context key
 * catalogue, never while providers register, so a context a later provider
 * binds is the one read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthenticationContext
{
    /**
     * Return the namespaces the context supplies, `authentication` among them.
     * None may be another reserved namespace or one a context source supplies,
     * which is checked at boot.
     *
     * @return list<string>
     */
    public function namespaces(): array;

    /**
     * Return the names that make a key of the context's namespaces an assurance
     * key, beside the package's fixed `AssuranceKeys::NAMES`; none for a
     * context that adds no assurance key of its own.
     *
     * A key is an assurance key when any segment of its path after the
     * namespace is one of these names. Each entry is either an exact name, such
     * as `recovery_code`, or a name followed by one trailing `*`, such as
     * `provider_*`, which matches every segment starting with what comes before
     * the `*`. Nothing else is accepted: an entry that is not a string, is
     * empty, holds a `.` or has a `*` anywhere but at its end is refused at
     * boot, and fails closed wherever it is read.
     *
     * @return list<string>
     */
    public function assuranceKeys(): array;

    /**
     * Return the values of the namespaces for the current check, keyed by
     * namespace, then nested by key. A namespace left out is absent, so its
     * keys are missing.
     *
     * @return array<string, array<string, mixed>>
     */
    public function values(): array;
}
