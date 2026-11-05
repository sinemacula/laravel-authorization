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
 * declares nothing and is refused, as is a guard that is not a non-empty string
 * and an attribute that cannot be instantiated (repeated, or given an argument
 * of the wrong type). Each refusal names the case at fault.
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
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException
     *
     * @phpstan-ignore throws.unusedType
     */
    public function read(PermissionEnum $case): PermissionMeta
    {
        $attributes = (new \ReflectionEnumUnitCase($case, $case->name))->getAttributes(PermissionMeta::class);

        if ($attributes === []) {
            return new PermissionMeta;
        }

        // A repeated attribute, or an argument of the wrong type, fails to
        // instantiate with an Error, which PHPStan does not track.
        try {
            return $attributes[0]->newInstance();
        } catch (\Error $error) { // @phpstan-ignore catch.neverThrown
            throw new InvalidPermissionCatalogueException(self::source($case), 'the #[Permission] attribute cannot be read: ' . $error->getMessage());
        }
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
        $name = $case->value;

        if (!\is_string($name)) {
            throw new InvalidPermissionCatalogueException(self::source($case), 'the enum must be backed by strings, since each case\'s value is a permission name.');
        }

        $metadata    = $this->read($case);
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
        $guards = $metadata->guards;

        if ($guards === null) {
            return [null];
        }

        if ($guards === []) {
            throw new InvalidPermissionCatalogueException(self::source($case), 'the guard list is empty; leave it out for a guard-agnostic permission.');
        }

        foreach ($guards as $guard) {
            if (!self::isGuardName($guard)) {
                $got    = $guard === '' ? 'an empty string' : \get_debug_type($guard);
                $reason = "every guard must be a non-empty string, got {$got}; leave the list out for a guard-agnostic permission.";

                throw new InvalidPermissionCatalogueException(self::source($case), $reason);
            }
        }

        return $guards;
    }

    /**
     * Determine whether the given guard list entry is a guard name: a non-empty
     * string. The attribute's type is only a docblock, so an entry can be
     * anything.
     *
     * @param  mixed  $guard
     * @return bool
     */
    private static function isGuardName(mixed $guard): bool
    {
        return \is_string($guard) && $guard !== '';
    }

    /**
     * Name the given case as the declaration at fault: `Enum::CASE`.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @return string
     */
    private static function source(PermissionEnum $case): string
    {
        return $case::class . '::' . $case->name;
    }
}
