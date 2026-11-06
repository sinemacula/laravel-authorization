<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Concerns\HasContainerInstance;

/**
 * The abilities the package answers through Laravel's Gate (AUTHZ-9.1): the
 * exact name of every permission the permission catalogue holds, whatever its
 * guard. That is the package's own permissions (see `PackagePermissions`) and
 * every permission the configured enums and providers declare.
 *
 * An ability is held only when it is one of those names exactly: a name is
 * never read as a pattern, so `posts:*` is held only when a permission of that
 * name is declared. A permission row that exists only in the database is not
 * declared, so it is not held.
 *
 * The Gate asks on every check, so the names are read through the permission
 * catalogue the first time an ability is asked about and kept as a set for the
 * instance's lifetime, which is one request or job: the Gate registrar binds it
 * with `scoped()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeclaredAbilities
{
    use HasContainerInstance;

    /** @var array<string, true>|null The name of every permission declared, as the keys of a set, once read. */
    private ?array $names = null;

    /**
     * Create a new set of declared abilities.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionCatalogue  $catalogue
     */
    public function __construct(

        /** The permissions the package, the configured enums and the configured providers declare. */
        private readonly PermissionCatalogue $catalogue,
    ) {}

    /**
     * Determine whether the ability is the exact name of a declared permission.
     *
     * @param  string  $ability
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    public function holds(string $ability): bool
    {
        $this->names ??= \array_fill_keys(\array_map(static fn (PermissionDefinition $definition): string => $definition->name, $this->catalogue->definitions()), true);

        return isset($this->names[$ability]);
    }
}
