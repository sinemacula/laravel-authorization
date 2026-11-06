<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;

/**
 * The actions the code declares: every permission name of the configured
 * permission enums and providers (AUTHZ-3.8), whatever its guard.
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
    /** @var list<string>|null Every declared permission name, once read. */
    private ?array $names = null;

    /**
     * Create a new declared action catalogue.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionCatalogue  $catalogue
     */
    public function __construct(

        /** The permissions the configured enums and providers declare. */
        private readonly PermissionCatalogue $catalogue,
    ) {}

    /**
     * Determine whether the action pattern covers at least one declared
     * permission name.
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
     * Return every declared permission name, reading them on first use.
     *
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function names(): array
    {
        return $this->names ??= \array_values(\array_unique(\array_map(
            static fn (PermissionDefinition $definition): string => $definition->name,
            $this->catalogue->definitions(),
        )));
    }
}
