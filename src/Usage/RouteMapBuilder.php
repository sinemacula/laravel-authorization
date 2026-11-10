<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

/**
 * Builds a route map (see `RouteMap`) as a resolution finds its routes: each
 * grant and each route kept once, however many permissions or policies it
 * gives, and each permission or policy given the routes behind it, each once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RouteMapBuilder
{
    /** @var list<\SineMacula\Laravel\Authorization\Usage\StoredGrant> The distinct stored grants. */
    private array $grants = [];

    /** @var array<int, int> The index of each stored grant kept, by its object's id. */
    private array $grantIndexes = [];

    /** @var list<array{string, int}> The distinct routes, each its key and the index of its grant. */
    private array $routes = [];

    /** @var array<string, int> The index of each route kept, by its key. */
    private array $routeIndexes = [];

    /** @var array<string, array<int, int>> The indexes of the routes behind each permission or policy, each once. */
    private array $index = [];

    /**
     * Keep the route, once, and return its index.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\GrantRoute  $route
     * @return int
     */
    public function route(GrantRoute $route): int
    {
        if (isset($this->routeIndexes[$route->key])) {
            return $this->routeIndexes[$route->key];
        }

        $grant = $this->grantIndexes[\spl_object_id($route->grant)] ??= \array_push($this->grants, $route->grant) - 1;

        $this->routes[] = [$route->key, $grant];

        return $this->routeIndexes[$route->key] = \count($this->routes) - 1;
    }

    /**
     * Give the permission or policy the routes of the indexes, each once.
     *
     * @param  string  $name
     * @param  int  ...$routes
     * @return void
     */
    public function give(string $name, int ...$routes): void
    {
        foreach ($routes as $route) {
            $this->index[$name][$route] = $route;
        }
    }

    /**
     * Return the map built.
     *
     * @return \SineMacula\Laravel\Authorization\Usage\RouteMap
     */
    public function build(): RouteMap
    {
        return new RouteMap($this->grants, $this->routes, \array_map(\array_values(...), $this->index));
    }
}
