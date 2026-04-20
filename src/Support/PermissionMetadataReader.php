<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;

/**
 * Reader for `#[Permission]` attributes attached to enum cases.
 *
 * Returns the attribute instance when present; otherwise returns a default
 * (all-null) instance so callers can treat the metadata as uniform without
 * null-checking every field.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionMetadataReader
{
    /**
     * Return the `#[Permission]` attribute for the given enum case.
     *
     * When no attribute is present, a default instance with all fields set to
     * null is returned.
     *
     * @param  \ReflectionEnumUnitCase  $case
     * @return \SineMacula\Laravel\Authorization\Attributes\Permission
     */
    public function read(\ReflectionEnumUnitCase $case): PermissionMeta
    {
        $attributes = $case->getAttributes(PermissionMeta::class);

        if ($attributes === []) {
            return new PermissionMeta;
        }

        return $attributes[0]->newInstance();
    }
}
