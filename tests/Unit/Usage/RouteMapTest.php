<?php

declare(strict_types = 1);

namespace Tests\Unit\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\GrantRoute;
use SineMacula\Laravel\Authorization\Usage\RouteMap;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;

/**
 * Unit tests for the routes one resolution keeps, each grant and route once,
 * referenced by what each gives.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RouteMap::class)]
final class RouteMapTest extends TestCase
{
    /**
     * The routes behind a name are built from the routes and grants it
     * references, in order; a name it does not hold has none; and the map
     * round-trips through its plain values, a numeric name included.
     *
     * @return void
     */
    public function testRoutesAreBuiltFromWhatTheyReference(): void
    {
        $role   = new StoredGrant(GrantTarget::ROLE, 'r', new Reference('user', 'u'), 'tenant', 't', 'web', 9);
        $direct = new StoredGrant(GrantTarget::PERMISSION, 'p', new Reference('user', 'u'), null, null, null, null);
        $map    = new RouteMap([$role, $direct], [['granted', 0], ['carried', 0], ['direct', 1]], ['posts:read' => [2, 0, 1], '7' => [0]]);

        self::assertEquals([new GrantRoute('direct', $direct), new GrantRoute('granted', $role), new GrantRoute('carried', $role)], $map->routesFor('posts:read'));
        self::assertEquals([new GrantRoute('granted', $role)], $map->routesFor('7'));
        self::assertSame([], $map->routesFor('posts:write'));
        self::assertSame(['posts:read', '7'], $map->names());
        self::assertSame(['grants' => [$role->toArray(), $direct->toArray()], 'routes' => $map->routes, 'index' => $map->index], $map->toArray());
        self::assertEquals($map, RouteMap::fromArray($map->toArray()));
        self::assertEquals(new RouteMap, RouteMap::fromArray(['grants' => [], 'routes' => [], 'index' => []]));
    }

    /**
     * Return values a route map refuses, each with the message it refuses them
     * with.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function corrupt(): iterable
    {
        $grant = (new StoredGrant(GrantTarget::ROLE, 'r', new Reference('user', 'u'), null, null, null, null))->toArray();
        $shape = 'A route map is not the shape grant usage tracking keeps.';
        $route = 'A route of a route map is not a key and the index of its grant.';
        $index = 'A route map lists a route it does not hold.';

        yield 'not an array' => ['map', $shape];
        yield 'no grants' => [['routes' => [], 'index' => []], $shape];
        yield 'no routes' => [['grants' => [], 'index' => []], $shape];
        yield 'no index' => [['grants' => [], 'routes' => []], $shape];
        yield 'a route that is not a list' => [['grants' => [$grant], 'routes' => ['k'], 'index' => []], $route];
        yield 'a route with no key' => [['grants' => [$grant], 'routes' => [[5, 0]], 'index' => []], $route];
        yield 'a route of no grant held' => [['grants' => [$grant], 'routes' => [['k', 1]], 'index' => []], $route];
        yield 'a route of a negative grant' => [['grants' => [$grant], 'routes' => [['k', -1]], 'index' => []], $route];
        yield 'a route of a grant that is not an index' => [['grants' => [$grant], 'routes' => [['k', '0']], 'index' => []], $route];
        yield 'an index that is not a list' => [['grants' => [$grant], 'routes' => [['k', 0]], 'index' => ['posts:read' => 0]], $index];
        yield 'an index of no route held' => [['grants' => [$grant], 'routes' => [['k', 0]], 'index' => ['posts:read' => [0, 1]]], $index];
        yield 'an index of a negative route' => [['grants' => [$grant], 'routes' => [['k', 0]], 'index' => ['posts:read' => [-1]]], $index];
    }

    /**
     * Values that are not a route map, or that reference a grant or a route the
     * map does not hold, are refused.
     *
     * @param  mixed  $values
     * @param  string  $message
     * @return void
     */
    #[DataProvider('corrupt')]
    public function testValuesOfAnotherShapeAreRefused(mixed $values, string $message): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        RouteMap::fromArray($values);
    }
}
