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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthenticationContext
{
    /**
     * Return the namespaces the context supplies, `authentication` among them.
     * None may be another reserved namespace or one a context source supplies.
     *
     * @return list<string>
     */
    public function namespaces(): array;

    /**
     * Return the values of the namespaces for the current check, keyed by
     * namespace, then nested by key. A namespace left out is absent, so its
     * keys are missing.
     *
     * @return array<string, array<string, mixed>>
     */
    public function values(): array;
}
