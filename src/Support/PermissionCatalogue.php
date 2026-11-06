<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * The platform's permission catalogue as the package and the application
 * declare it in code.
 *
 * Holds the permissions the package declares for its own services first (see
 * `PackagePermissions`), then reads every case of every enum in
 * `authorization.permission_enums`, through the `#[Permission]` attribute on
 * the case, and every definition each class in
 * `authorization.permission_providers` returns, resolving the providers through
 * the container. Each name is checked against the configured permission model's
 * name rules and each guard must be null or a non-empty string. A permission
 * declared twice for the same guard is kept once when both declarations agree
 * and refused when their description or category differ.
 *
 * Nothing here touches the database. The configured classes are assumed to have
 * passed the config validation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionCatalogue
{
    /**
     * Create a new permission catalogue.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionMetadataReader  $reader
     */
    public function __construct(

        /** Configuration holding the enums, the providers and the model. */
        private ConfigRepository $config,

        /** Container the providers are resolved through. */
        private Container $container,

        /** Reader turning an enum case into its permission definitions. */
        private PermissionMetadataReader $reader,
    ) {}

    /**
     * Return every permission the package, the configured enums and the
     * configured providers declare, in the order they are declared, the
     * package's first.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    public function definitions(): array
    {
        $definitions = [];

        foreach ([...self::packageDefinitions(), ...$this->enumDefinitions(), ...$this->providerDefinitions()] as [$source, $definition]) {
            $this->assertValid($source, $definition);

            $existing = $definitions[$definition->key()] ?? $definition;

            if (!$existing->hasMetadata($definition->description, $definition->category)) {
                throw new InvalidPermissionCatalogueException($source, "'{$definition->name}' is already declared for the same guard with a different description or category.");
            }

            $definitions[$definition->key()] = $existing;
        }

        return \array_values($definitions);
    }

    /**
     * Return the definitions the package declares for its own services, each
     * with the class that declares it.
     *
     * @return list<array{string, \SineMacula\Laravel\Authorization\Support\PermissionDefinition}>
     */
    private static function packageDefinitions(): array
    {
        return \array_map(static fn (PermissionDefinition $definition): array => [PackagePermissions::class, $definition], (new PackagePermissions)->permissions());
    }

    /**
     * Return the definitions every case of every configured enum declares, each
     * with the case that declares it.
     *
     * @return list<array{string, \SineMacula\Laravel\Authorization\Support\PermissionDefinition}>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function enumDefinitions(): array
    {
        /** @var list<class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>> $enums */
        $enums       = $this->config->get('authorization.permission_enums', []);
        $definitions = [];

        foreach ($enums as $enum) {
            foreach ($enum::cases() as $case) {
                foreach ($this->reader->definitions($case) as $definition) {
                    $definitions[] = [$enum . '::' . $case->name, $definition];
                }
            }
        }

        return $definitions;
    }

    /**
     * Return the definitions every configured provider returns, each with the
     * provider that returns it.
     *
     * @return list<array{string, \SineMacula\Laravel\Authorization\Support\PermissionDefinition}>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function providerDefinitions(): array
    {
        /** @var list<class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionProvider>> $providers */
        $providers   = $this->config->get('authorization.permission_providers', []);
        $definitions = [];

        foreach ($providers as $provider) {
            /** @var array<mixed> $declared */
            $declared = $this->container->make($provider)->permissions();

            foreach ($declared as $definition) {
                if (!$definition instanceof PermissionDefinition) {
                    $reason = 'permissions() must return ' . PermissionDefinition::class . ' instances, got ' . \get_debug_type($definition) . '.';

                    throw new InvalidPermissionCatalogueException($provider, $reason);
                }

                $definitions[] = [$provider, $definition];
            }
        }

        return $definitions;
    }

    /**
     * Refuse a definition whose name breaks the configured permission model's
     * name rules, or whose guard is an empty string.
     *
     * @param  string  $source
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionDefinition  $definition
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function assertValid(string $source, PermissionDefinition $definition): void
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $model */
        $model = $this->config->get('authorization.models.permission', Permission::class);

        if (!$model::isValidAuthorizationName($definition->name)) {
            $reason = "'{$definition->name}' is not a valid permission name: allowed characters are letters, digits,"
                . ' \'_\', \'-\', \':\', \'.\' and \'*\', at most 191 of them.';

            throw new InvalidPermissionCatalogueException($source, $reason);
        }

        if ($definition->guard === '') {
            throw new InvalidPermissionCatalogueException($source, "the guard of '{$definition->name}' must be null or a non-empty string.");
        }
    }
}
