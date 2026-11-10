<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

/**
 * The grant routes behind what one resolution found, while grant usage is
 * tracked (N100), kept once each and referenced: the distinct stored grants,
 * the distinct routes, each its key and the index of the grant it starts from,
 * and, for each permission by its name or each policy by its key, the indexes
 * of the routes that give it.
 *
 * A role's grant, and the ancestor it reaches, gives every permission or policy
 * the role carries, so its route is kept once and referenced by each, and an
 * entry stays proportional to the grants and what they give, never to their
 * product. The routes behind one permission or policy are built only when a
 * decision asks for them.
 *
 * @phpstan-type RouteMapArray array{
 *     grants: list<array<string, int|string|null>>,
 *     routes: list<array{string, int}>,
 *     index: array<string, list<int>>
 * }
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RouteMap
{
    /**
     * Create a new route map.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Usage\StoredGrant>  $grants
     * @param  list<array{string, int}>  $routes
     * @param  array<string, list<int>>  $index
     */
    public function __construct(

        /** The distinct stored grants the routes start from. */
        public array $grants = [],

        /** The distinct routes, each its key and the index of its grant. */
        public array $routes = [],

        /** The indexes of the routes behind each permission by its name, or each policy by its key. */
        public array $index = [],
    ) {}

    /**
     * Return the routes behind the permission or policy, in the order they were
     * found; none for one the resolution did not find.
     *
     * @param  string  $name
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    public function routesFor(string $name): array
    {
        $routes = [];

        foreach ($this->index[$name] ?? [] as $index) {
            [$key, $grant] = $this->routes[$index];

            $routes[] = new GrantRoute($key, $this->grants[$grant]);
        }

        return $routes;
    }

    /**
     * Return the names of the permissions, or the keys of the policies, the map
     * holds routes for.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return \array_map(\strval(...), \array_keys($this->index));
    }

    /**
     * Return the map as the plain values a cache entry holds.
     *
     * @return RouteMapArray
     */
    public function toArray(): array
    {
        return [
            'grants' => \array_map(static fn (StoredGrant $grant): array => $grant->toArray(), $this->grants),
            'routes' => $this->routes,
            'index'  => $this->index,
        ];
    }

    /**
     * Return the map the plain values describe, refusing values that do not
     * have its shape, or that reference a grant or route it does not hold.
     *
     * @param  mixed  $values
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromArray(mixed $values): self
    {
        if (!\is_array($values) || !\is_array($values['grants'] ?? null) || !\is_array($values['routes'] ?? null) || !\is_array($values['index'] ?? null)) {
            throw new \UnexpectedValueException('A route map is not the shape grant usage tracking keeps.');
        }

        $grants = \array_map(StoredGrant::fromArray(...), \array_values($values['grants']));
        $routes = \array_map(static fn (mixed $route): array => self::routeOf($route, \count($grants)), \array_values($values['routes']));
        $index  = [];

        foreach ($values['index'] as $name => $list) {
            $index[(string) $name] = self::indexesOf($list, \count($routes));
        }

        return new self($grants, $routes, $index);
    }

    /**
     * Return the stored route, its key and the index of its grant, refusing one
     * that is not that shape or names a grant the map does not hold.
     *
     * @param  mixed  $route
     * @param  int  $grants
     * @return array{string, int}
     *
     * @throws \UnexpectedValueException
     */
    private static function routeOf(mixed $route, int $grants): array
    {
        if (!\is_array($route) || !\is_string($route[0] ?? null) || !self::isIndex($route[1] ?? null, $grants)) {
            throw new \UnexpectedValueException('A route of a route map is not a key and the index of its grant.');
        }

        /** @var int $grant */
        $grant = $route[1];

        return [$route[0], $grant];
    }

    /**
     * Return the stored list of route indexes, refusing one that is not a list
     * of the indexes of routes the map holds.
     *
     * @param  mixed  $list
     * @param  int  $routes
     * @return list<int>
     *
     * @throws \UnexpectedValueException
     */
    private static function indexesOf(mixed $list, int $routes): array
    {
        if (!\is_array($list) || \array_filter($list, static fn (mixed $index): bool => !self::isIndex($index, $routes)) !== []) {
            throw new \UnexpectedValueException('A route map lists a route it does not hold.');
        }

        /** @var list<int> */
        return \array_values($list);
    }

    /**
     * Determine whether the value is an index into a list of the count.
     *
     * @param  mixed  $value
     * @param  int  $count
     * @return bool
     */
    private static function isIndex(mixed $value, int $count): bool
    {
        return \is_int($value) && $value >= 0 && $value < $count;
    }
}
