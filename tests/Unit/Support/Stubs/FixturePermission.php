<?php

declare(strict_types = 1);

namespace Tests\Unit\Support\Stubs;

use SineMacula\Laravel\Authorization\Attributes\Permission as PermissionMeta;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;

/**
 * Fixture enum exercising the metadata reader against cases with and without
 * the `#[Permission]` attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum FixturePermission: string implements PermissionEnum
{
    #[PermissionMeta(
        description: 'View applications',
        category: 'Applications',
        guards: ['web', 'api'],
    )]
    case VIEW_APPLICATIONS = 'applications:view';

    case DELETE_APPLICATIONS = 'applications:delete';

    /**
     * Return the permission string used by the authorization engine.
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->value;
    }
}
