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
     * scope, is observed in a bucket with its stored grant, and round-trips
     * through its plain values.
     *
     * @return void
     */
    public function testARouteIsKeyedObservedAndRoundTrips(): void
    {
        $grant  = new StoredGrant(GrantTarget::ROLE, 'r1', new Reference('user', 'u'), 'tenant', 't', 'web', 50);
        $target = new Reference('permission', 'p');
        $route  = GrantRoute::to(SourceKind::ROLE_PERMISSION, $target, ['r1', 'r2'], $grant);

        self::assertSame(GrantUsageKey::of(SourceKind::ROLE_PERMISSION, $target, new Reference('user', 'u'), ['tenant', 't', 'web'], ['r1', 'r2']), $route->key);
        self::assertSame(['grant_key' => $route->key, ...$grant->toArray(), 'last_observed_at' => 3600], $route->observedIn(3600));
        self::assertEquals($route, GrantRoute::fromArray($route->toArray()));
        self::assertSame(['key' => $route->key, 'grant' => $grant->toArray()], $route->toArray());
    }

    /**
     * Values that are not a route's are refused.
     *
     * @return void
     */
    public function testValuesOfAnotherShapeAreRefused(): void
    {
        foreach (['route', ['key' => 5, 'grant' => []], ['grant' => []]] as $values) {
            try {
                GrantRoute::fromArray($values);
                self::fail('A route of another shape was read.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('A grant route is not the shape grant usage tracking keeps.', $exception->getMessage());
            }
        }

        $this->expectException(\UnexpectedValueException::class);

        GrantRoute::fromArray(['key' => 'k', 'grant' => 'grant']);
    }
}
