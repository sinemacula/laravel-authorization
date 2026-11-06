<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;

/**
 * The actions the application declares: every permission name of the configured
 * permission enums and providers (AUTHZ-3.8), whatever its guard, read through
 * the permission catalogue. The package's own permissions (see
 * `PackagePermissions`), which the permission catalogue holds too, are left
 * out: they are not the application's, so with nothing configured the catalogue
 * is empty and covers no pattern, not even `*`. The policy validator accepts a
 * pattern covering one of the package's own whatever this catalogue holds.
 *
 * A pattern covers a name when it is the name, or when it matches the name with
 * `fnmatch` and `FNM_NOESCAPE`, as statements match actions. The names are read
 * through the permission catalogue the first time a pattern is asked about and
 * kept for the catalogue's lifetime, which is one request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeclaredActionCatalogue implements ActionCatalogue
{
    /** @var list<string>|null The name of every permission the application declares, once read; a name declared for two guards is listed twice. */
    private ?array $names = null;

    /**
     * Create a new declared action catalogue.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionCatalogue  $catalogue
     */
    public function __construct(

        /** The permission catalogue: the package's own permissions, which are left out, and those the configured enums and providers declare. */
        private readonly PermissionCatalogue $catalogue,
    ) {}

    /**
     * Determine whether the action pattern covers at least one permission name
     * the application declares.
     *
     * @param  string  $pattern
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    #[\Override]
    public function covers(string $pattern): bool
    {
        foreach ($this->names() as $name) {
            if ($pattern === $name || \fnmatch($pattern, $name, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the name of every permission the application declares, the
     * package's own left out, reading them on first use.
     *
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function names(): array
    {
        if ($this->names !== null) {
            return $this->names;
        }

        $names = [];

        foreach ($this->catalogue->definitions() as $definition) {
            if (PackagePermissions::isDeclared($definition->name)) {
                continue;
            }

            $names[] = $definition->name;
        }

        return $this->names = $names;
    }
}
