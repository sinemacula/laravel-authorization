<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions\Stubs;

use SineMacula\Laravel\Authorization\Concerns\ValidatesAuthorizationName;

/**
 * Stub model that uses the base `ValidatesAuthorizationName` trait without
 * overriding `getAuthorizationNameKind()` — exercises the trait's default label
 * fallback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class StubAuthorizationEntity // @phpstan-ignore class.missingExtends
{
    use ValidatesAuthorizationName;

    /** @var array<string, mixed> */
    public array $attributes = [];

    /**
     * Expose the protected kind resolver for the test.
     *
     * @return string
     */
    public function resolveKind(): string
    {
        return $this->getAuthorizationNameKind();
    }
}
