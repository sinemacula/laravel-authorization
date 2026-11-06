<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;

/**
 * A scope registry backed by the permission catalogue and the scope map
 * (AUTHZ-13.5): a credential may carry every scope the map names, whose
 * patterns the application's boot already checked against the catalogue, and
 * every other scope that names a permission the package or the application
 * declares, or a pattern covering at least one, as an unmapped scope names an
 * action or an action pattern itself.
 *
 * The package binds no scope registry. An application binds this one where its
 * credentials' scopes are issued, and the container builds it:
 * `$this->app->bind(ScopeRegistry::class, CatalogueScopeRegistry::class)`. The
 * catalogue is read the first time a scope is asked about, and kept for the
 * registry's lifetime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CatalogueScopeRegistry implements ScopeRegistry
{
    /** @var list<string>|null The name of every permission declared, each once, once read. */
    private ?array $names = null;

    /**
     * Create a new catalogue scope registry.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionCatalogue  $catalogue
     * @param  \SineMacula\Laravel\Authorization\Support\SessionScopes  $map
     */
    public function __construct(

        /** The permissions the package and the application declare. */
        private readonly PermissionCatalogue $catalogue,

        /** The scope map, `authorization.session.scopes`. */
        private readonly SessionScopes $map,
    ) {}

    /**
     * Determine whether a credential may carry the scope: the map names it, or
     * it names a declared permission or a pattern covering at least one.
     *
     * @param  string  $scope
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    #[\Override]
    public function isValid(string $scope): bool
    {
        if ($this->map->isMapped($scope)) {
            return true;
        }

        foreach ($this->names() as $name) {
            if (SessionCaps::covers([$scope], $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return every scope a credential may carry by name: each scope the map
     * names, then each declared permission the map does not name.
     *
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    #[\Override]
    public function scopes(): array
    {
        $mapped = $this->map->names();

        return [...$mapped, ...\array_values(\array_diff($this->names(), $mapped))];
    }

    /**
     * Return the name of every permission declared, each once, reading them on
     * first use.
     *
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function names(): array
    {
        $name = static fn (PermissionDefinition $definition): string => $definition->name;

        return $this->names ??= \array_values(\array_unique(\array_map($name, $this->catalogue->definitions())));
    }
}
