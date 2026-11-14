<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\RouteMap;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;

/**
 * Unit tests for what a resolution found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Resolution::class)]
final class ResolutionTest extends TestCase
{
    /**
     * A resolution with nothing else said never expires and may be stored.
     *
     * @return void
     */
    public function testDefaultsToStableWithoutExpiry(): void
    {
        $resolution = new Resolution(['posts:read']);

        self::assertSame(['posts:read'], $resolution->value);
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }

    /**
     * A resolution keeps no routes unless given them, and keeps those given.
     *
     * @return void
     */
    public function testRoutesAreKeptOnlyWhenGiven(): void
    {
        $routes = new RouteMap([new StoredGrant(GrantTarget::PERMISSION, 'p', new Reference('user', 'u'), null, null, null, null)], [['k', 0]], ['posts:read' => [0]]);

        self::assertNull((new Resolution(['posts:read']))->routes);
        self::assertSame($routes, (new Resolution(['posts:read'], null, true, $routes))->routes);
    }

    /**
     * A resolution names no activation unless given them, and keeps those
     * given.
     *
     * @return void
     */
    public function testActivationsAreKeptOnlyWhenGiven(): void
    {
        $activations = ['policy-1' => ['activation-1']];

        self::assertSame([], (new Resolution(['posts:read']))->activations);
        self::assertSame($activations, (new Resolution(['posts:read'], null, true, null, $activations))->activations);
    }
}
