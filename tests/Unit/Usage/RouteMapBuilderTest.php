<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\RouteMap;
use SineMacula\Laravel\Authorization\Usage\RouteMapBuilder;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;

/**
 * Unit tests for building a route map: each grant and each route kept once, and
 * each name given the routes behind it once each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RouteMapBuilder::class)]
final class RouteMapBuilderTest extends TestCase
{
    /**
     * A route is kept once by its key and a grant once by its object, however
     * often each is given; a name is given each route once, in the order first
     * given.
     *
     * @return void
     */
    public function testEachGrantAndRouteIsKeptOnce(): void
    {
        $role   = new StoredGrant(GrantTarget::ROLE, 'r', new Reference('user', 'u'), null, null, null, 9);
        $direct = new StoredGrant(GrantTarget::PERMISSION, 'p', new Reference('user', 'u'), null, null, null, 9);
        $map    = new RouteMapBuilder;

        $granted = $map->route(new GrantRoute('granted', $role));

        self::assertSame(0, $granted);
        self::assertSame(1, $map->route(new GrantRoute('carried', $role)));
        self::assertSame(0, $map->route(new GrantRoute('granted', $direct)));
        self::assertSame(2, $map->route(new GrantRoute('direct', $direct)));

        $map->give('posts:read', 2, $granted, 1, $granted);
        $map->give('posts:edit', 1);
        $map->give('posts:read', 1);

        self::assertEquals(new RouteMap([$role, $direct], [['granted', 0], ['carried', 0], ['direct', 1]], ['posts:read' => [2, 0, 1], 'posts:edit' => [1]]), $map->build());
        self::assertEquals(new RouteMap, (new RouteMapBuilder)->build());
    }
}
