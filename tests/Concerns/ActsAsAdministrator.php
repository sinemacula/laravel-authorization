<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Services\GrantService;
use Tests\Feature\Stubs\StubIdentity;

/**
 * Makes the acting contexts of administrators for tests of delegated
 * administration: an identity granted the administration actions it may take,
 * platform-wide, as trusted work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ActsAsAdministrator
{
    /**
     * Return the acting context of a new identity with the id, granted each of
     * the actions as a permission, platform-wide, or none for an empty list.
     *
     * @param  list<string>  $actions
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \Throwable
     */
    protected static function administrator(array $actions = ['authorization:*'], string $id = 'admin-1'): ActingContext
    {
        $admin = StubIdentity::query()->create(['id' => $id]);

        foreach ($actions as $action) {
            /** @var \SineMacula\Laravel\Authorization\Models\Permission $permission */
            $permission = Permission::query()->firstOrCreate(['name' => $action]);

            GrantService::instance()?->grantPermission($admin, $permission);
        }

        return ActingContext::for($admin);
    }
}
