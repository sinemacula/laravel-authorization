<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

/**
 * An authentication context that contributes the namespaces it is given beside
 * `authentication`, as `laravel-authentication`'s contributes `mfa` and `sso`,
 * and declares the assurance key names it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ContributingAuthenticationContext implements AuthenticationContext
{
    /**
     * Create a new contributing authentication context.
     *
     * @param  list<string>  $contributed
     * @param  array<array-key, mixed>  $assuranceKeys
     */
    public function __construct(

        /** The namespaces the context contributes beside `authentication`. */
        private array $contributed,

        /** The assurance key names the context declares, malformed ones included. */
        private array $assuranceKeys = [],
    ) {}

    /**
     * Return `authentication` and the namespaces the context contributes.
     *
     * @return list<string>
     */
    #[\Override]
    public function namespaces(): array
    {
        return ['authentication', ...$this->contributed];
    }

    /**
     * Return the assurance key names the context was given, as given.
     *
     * @return list<string>
     */
    #[\Override]
    public function assuranceKeys(): array
    {
        /** @var list<string> */
        return $this->assuranceKeys;
    }

    /**
     * Return no values.
     *
     * @return array<string, array<string, mixed>>
     */
    #[\Override]
    public function values(): array
    {
        return [];
    }
}
