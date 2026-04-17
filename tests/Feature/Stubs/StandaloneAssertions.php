<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Testing\AuthorizationAssertions;

/**
 * Standalone consumer of `AuthorizationAssertions` that exposes the
 * trait's container-lookup without inheriting from the shipped
 * `Tests\TestCase` (which binds `$this->app` through Laravel's
 * testing trait). Used to drive the `app()` helper fallback when
 * the calling class has no `$app` property.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class StandaloneAssertions
{
    use AuthorizationAssertions;

    /**
     * Delegate to the trait's `actingAsIdentity` method from outside
     * a PHPUnit test case so the branch that falls back to the
     * global `app()` helper is exercised.
     *
     * @param  object  $principal
     * @return void
     */
    public function swap(object $principal): void
    {
        $this->actingAsIdentity($principal);
    }
}
