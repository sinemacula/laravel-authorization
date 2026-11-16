<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

/**
 * An authentication context with key names of its own under `authentication`,
 * as `laravel-authentication`'s has, which its owner declares to the key
 * catalogue.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SiblingAuthenticationContext implements AuthenticationContext
{
    /** @var array<string, string> The keys the context supplies, by path within `authentication`, with their types. */
    public const array KEYS = ['identity_id' => 'string', 'session_id' => 'string'];

    /**
     * Return `authentication` alone.
     *
     * @return list<string>
     */
    #[\Override]
    public function namespaces(): array
    {
        return ['authentication'];
    }

    /**
     * Return no assurance key names of its own.
     *
     * @return list<string>
     */
    #[\Override]
    public function assuranceKeys(): array
    {
        return [];
    }

    /**
     * Return the identity and session under `authentication`.
     *
     * @return array<string, array<string, mixed>>
     */
    #[\Override]
    public function values(): array
    {
        return ['authentication' => ['identity_id' => 'identity-1', 'session_id' => 'session-1']];
    }
}
