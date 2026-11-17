<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Exceptions\UndeclaredPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Decides whether a name or pattern covers a declared permission: one of the
 * package's own (see `PackagePermissions`) or an action of the bound
 * `ActionCatalogue`. A policy's action patterns, the session scope map, and
 * every permission the services create, rename or grant are held to it, so a
 * wildcard permission must cover a declared action as a policy's pattern must.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DeclaredPermissions
{
    /**
     * Determine whether the pattern covers a permission of the package's own or
     * an action of the catalogue.
     *
     * @param  string  $pattern
     * @param  \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue  $catalogue
     * @return bool
     */
    public static function covers(string $pattern, ActionCatalogue $catalogue): bool
    {
        return PackagePermissions::covers($pattern) || $catalogue->covers($pattern);
    }

    /**
     * Refuse a permission name that covers no declared permission, asking the
     * bound action catalogue.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UndeclaredPermissionException
     */
    public static function assert(string $name): void
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue $catalogue */
        $catalogue = Container::getInstance()->make(ActionCatalogue::class);

        if (!self::covers($name, $catalogue)) {
            throw new UndeclaredPermissionException($name);
        }
    }

    /**
     * Refuse a permission whose stored name covers no declared permission, so a
     * grant is judged on the row it writes, never on a name changed in hand.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UndeclaredPermissionException
     */
    public static function assertStored(Permission $permission): void
    {
        $name = $permission->getOriginal('name');

        self::assert(\is_string($name) ? $name : '');
    }
}
