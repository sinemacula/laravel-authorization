<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;

/**
 * Unit tests for one grant route grant usage tracking records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRoute::class)]
final class GrantRouteTest extends TestCase
{
    /**
     * A route is keyed by its kind, target, path and its grant's grantee and
     * scope, and is observed in a bucket with its stored grant.
     *
     * @return void
     */
    public function testARouteIsKeyedAndObserved(): void
    {
        $grant  = new StoredGrant(GrantTarget::ROLE, 'r1', new Reference('user', 'u'), 'tenant', 't', 'web', 50);
        $target = new Reference('permission', 'p');
        $route  = GrantRoute::to(SourceKind::ROLE_PERMISSION, $target, ['r1', 'r2'], $grant);

        self::assertSame(GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, new Reference('user', 'u'), ['tenant', 't', 'web'], ['r1', 'r2']), $route->key);
        self::assertSame(['grant_key' => $route->key, ...$grant->toArray(), 'last_observed_at' => 3600], $route->observedIn(3600));
    }
}
