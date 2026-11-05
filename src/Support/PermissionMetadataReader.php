<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;

/**
 * Reads the `#[Permission]` attribute of a permission enum case and turns the
 * case into the permission definitions it declares.
 *
 * A case without the attribute reads as one with every field null: one
 * guard-agnostic permission with no description or category. A case whose
 * attribute lists guards declares one permission per guard. An empty guard list
 * declares nothing and is refused; the catalogue refuses an empty guard name,
 * as it does for a provider's definitions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionMetadataReader
{
    /**
     * Return the `#[Permission]` attribute on the given case, or an attribute
     * with every field null when the case has none.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @return \SineMacula\Laravel\Authorization\Attributes\Permission
     */
    public function read(PermissionEnum $case): PermissionMeta
    {
        $attributes = (new \ReflectionEnumUnitCase($case, $case->name))->getAttributes(PermissionMeta::class);

        return $attributes === [] ? new PermissionMeta : $attributes[0]->newInstance();
    }

    /**
     * Return the permission definitions the given case declares, one for each
     * guard its attribute lists, or one guard-agnostic definition.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    public function definitions(PermissionEnum $case): array
    {
        $metadata = $this->read($case);

        /** @var string $name */
        $name        = $case->value;
        $definitions = [];

        foreach ($this->guards($case, $metadata) as $guard) {
            $definitions[] = new PermissionDefinition(
                name: $name,
                description: $metadata->description,
                category: $metadata->category,
                guard: $guard,
            );
        }

        return $definitions;
    }

    /**
     * Return the guards the attribute declares, or a single null guard when it
     * declares none.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @param  \SineMacula\Laravel\Authorization\Attributes\Permission  $metadata
     * @return list<string|null>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     */
    private function guards(PermissionEnum $case, PermissionMeta $metadata): array
    {
        if ($metadata->guards === []) {
            throw new InvalidPermissionCatalogueException($case::class . '::' . $case->name, 'the guard list is empty; leave it out for a guard-agnostic permission.');
        }

        return $metadata->guards ?? [null];
    }
}
