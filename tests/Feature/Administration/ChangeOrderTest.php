<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ChangeOrder;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for the order a batch of delegated changes is decided in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChangeOrder::class)]
final class ChangeOrderTest extends TestCase
{
    /**
     * Changes are ordered kind by kind, in the order the kinds first appear,
     * and listed whatever their keys.
     *
     * @return void
     */
    public function testChangesAreOrderedKindByKind(): void
    {
        $post       = Permission::create(['name' => 'posts:a']);
        $permission = self::revoke(PackagePermissions::PERMISSION_REVOKE, $post);
        $role       = self::revoke(PackagePermissions::ROLE_REVOKE, Role::create(['name' => 'editor']));
        $again      = self::revoke(PackagePermissions::PERMISSION_REVOKE, $post);

        self::assertSame([$permission, $again, $role], ChangeOrder::of(['x' => $permission, 'y' => $role, 'z' => $again]));
        self::assertSame([$role, $permission], ChangeOrder::of([$role, $permission]));
        self::assertSame([], ChangeOrder::of([]));
    }

    /**
     * Within a kind, changes are ordered by their tenant, then their
     * application, then their record, whatever order they are given in.
     *
     * @return void
     */
    public function testChangesOfAKindAreOrderedByWhereTheyHold(): void
    {
        $first  = Permission::create(['name' => 'posts:a']);
        $second = Permission::create(['name' => 'posts:b']);

        [$low, $high] = \strcmp($first->id, $second->id) < 0 ? [$first, $second] : [$second, $first];

        $admin   = self::revoke(PackagePermissions::PERMISSION_REVOKE, $high, new GrantScope(null, 'admin'));
        $billing = self::revoke(PackagePermissions::PERMISSION_REVOKE, $low, new GrantScope(null, 'billing'));
        $lower   = self::revoke(PackagePermissions::PERMISSION_REVOKE, $low, new GrantScope(null, 'admin'));
        $tenant  = self::revoke(PackagePermissions::PERMISSION_REVOKE, $low, new GrantScope(new Reference('tenant', 't-1'), 'admin'));

        self::assertSame([$lower, $admin, $billing, $tenant], ChangeOrder::of([$tenant, $billing, $admin, $lower]));
        self::assertSame([$lower, $admin, $billing, $tenant], ChangeOrder::of([$admin, $tenant, $lower, $billing]));
    }

    /**
     * Within a kind, records with the same key are told apart by their type.
     *
     * @return void
     */
    public function testRecordsWithTheSameKeyAreOrderedByType(): void
    {
        $permission = new Permission(['name' => 'posts:a']);
        $role       = new Role(['name' => 'editor']);
        $key        = (string) Str::uuid();

        $permission->forceFill(['id' => $key])->save();
        $role->forceFill(['id' => $key])->save();

        [$low, $high] = \serialize($permission->getMorphClass()) < \serialize($role->getMorphClass()) ? [$permission, $role] : [$role, $permission];

        $one   = self::revoke(PackagePermissions::PERMISSION_REVOKE, $high);
        $other = self::revoke(PackagePermissions::PERMISSION_REVOKE, $low);

        self::assertSame([$other, $one], ChangeOrder::of([$one, $other]));
        self::assertSame([$other, $one], ChangeOrder::of([$other, $one]));
    }

    /**
     * Changes to definitions, which name no grant, keep the order they are
     * given in within their kind.
     *
     * @return void
     */
    public function testDefinitionsKeepTheirOrderWithinAKind(): void
    {
        $editor = OperationResource::definition(PackagePermissions::ROLE_UPDATE, Role::create(['name' => 'editor']), ['description' => 'x']);
        $author = OperationResource::definition(PackagePermissions::ROLE_UPDATE, Role::create(['name' => 'author']), ['description' => 'x']);

        self::assertSame([$editor, $author], ChangeOrder::of([$editor, $author]));
        self::assertSame([$author, $editor], ChangeOrder::of([$author, $editor]));
    }

    /**
     * Return the revocation of the record from one user, at platform scope
     * unless a scope is given.
     *
     * @param  string  $action
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope|null  $scope
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function revoke(string $action, Model $target, ?GrantScope $scope = null): OperationResource
    {
        return OperationResource::revoke($action, new Reference('user', '1'), $target, $scope ?? GrantScope::platform());
    }
}
