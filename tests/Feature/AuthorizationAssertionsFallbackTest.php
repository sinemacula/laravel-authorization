<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Testing\AuthorizationAssertions;
use Tests\Feature\Stubs\StandaloneAssertions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Coverage for the `app()` fallback branch of
 * `AuthorizationAssertions::actingAsIdentity`. The trait keeps a `$this->app`
 * reference path for Laravel's testing base class but drops to the global
 * `app()` helper for consumers who compose the trait into arbitrary assertion
 * utilities.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(AuthorizationAssertions::class)]
final class AuthorizationAssertionsFallbackTest extends TestCase
{
    /**
     * A standalone class that uses the trait without owning an `$app` property
     * falls back to `app()` and still swaps the resolver correctly.
     *
     * @return void
     */
    public function testAppHelperFallbackSwapsResolver(): void
    {
        $user   = StubIdentity::create(['id' => '4356ef82-867e-4edb-8906-e7457c1e23e9']);
        $helper = new StandaloneAssertions;

        $helper->swap($user);

        // Container-level side-effect: the manager is rebuilt under the swapped
        // principal.
        self::assertSame($user, $this->app->make(AuthorizationManager::class)->currentPrincipal()); // @phpstan-ignore method.nonObject
    }
}
