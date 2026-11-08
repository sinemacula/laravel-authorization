<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `OperationResource`, the resource a delegated
 * administration check is about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationResource::class)]
final class OperationResourceTest extends TestCase
{
    /**
     * A grant names its action, its target by type, key and name under its
     * kind, the grantee, the application, the reach and the expiry in UTC,
     * never only narrows, and is decided in the intended tenant.
     *
     * @return void
     */
    public function testAGrantNamesWhatItHandsOut(): void
    {
        $role   = Role::create(['name' => 'editor']);
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = new Reference('stub_tenant', 'tenant-a');
        $expiry = Carbon::parse('2026-07-02 14:00:00', 'Europe/Paris');
        $grant  = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $role, new GrantScope($tenant, 'admin', false), $expiry);

        self::assertInstanceOf(AuthorizableResource::class, $grant);
        self::assertSame(PackagePermissions::ROLE_GRANT, $grant->action);
        self::assertFalse($grant->isNarrowing);
        self::assertSame($tenant, $grant->tenant);
        self::assertSame(OperationResource::PROPOSED, $grant->id);
        self::assertNull($grant->impersonator);
        self::assertSame([
            'action'       => PackagePermissions::ROLE_GRANT,
            'narrowing'    => false,
            'impersonated' => false,
            'target_type'  => $role->getMorphClass(),
            'target_id'    => $role->id,
            'role'         => 'editor',
            'grantee_type' => $user->getMorphClass(),
            'grantee_id'   => 'user-1',
            'application'  => 'admin',
            'subtree'      => false,
            'expires_at'   => '2026-07-02T12:00:00+00:00',
        ], $grant->attributes());
    }

    /**
     * A key a grant does not name, an application or an expiry, is left out.
     *
     * @return void
     */
    public function testAKeyWithNoValueIsLeftOut(): void
    {
        $permission = Permission::create(['name' => 'posts:edit']);
        $attributes = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, new Reference('user', '1'), $permission, GrantScope::platform())->attributes();

        self::assertSame('posts:edit', $attributes['permission']);
        self::assertTrue($attributes['subtree']);
        self::assertArrayNotHasKey('application', $attributes);
        self::assertArrayNotHasKey('expires_at', $attributes);
        self::assertArrayNotHasKey('role', $attributes);
        self::assertArrayNotHasKey('change', $attributes);
    }

    /**
     * A removal is judged narrowing from its action and target: revoking a
     * permission is, removing a boundary is not.
     *
     * @return void
     */
    public function testARemovalIsJudgedFromItsActionAndTarget(): void
    {
        $permission = Permission::create(['name' => 'posts:edit']);
        $policy     = Policy::create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]]);
        $revoke     = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, new Reference('user', '1'), $permission, GrantScope::platform());
        $remove     = OperationResource::revoke(PackagePermissions::BOUNDARY_REMOVE, new Reference('user', '1'), $policy, GrantScope::platform());

        self::assertTrue($revoke->isNarrowing);
        self::assertTrue($revoke->attributes()['narrowing']);
        self::assertArrayNotHasKey('expires_at', $revoke->attributes());
        self::assertFalse($remove->isNarrowing);
        self::assertSame('cap', $remove->attributes()['policy']);
    }

    /**
     * A change to a definition is decided in its owner's tenant, names the
     * record and the proposed change, and never only narrows; a record not yet
     * saved has no key.
     *
     * @return void
     */
    public function testADefinitionIsDecidedInItsOwnersTenant(): void
    {
        $role    = Role::create(['name' => 'editor', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        $rename  = OperationResource::definition(PackagePermissions::ROLE_RENAME, $role, ['name' => 'author']);
        $created = OperationResource::definition(PackagePermissions::PERMISSION_CREATE, new Permission, ['name' => 'posts:edit']);

        self::assertEquals(new Reference('stub_tenant', 'tenant-a'), $rename->tenant);
        self::assertFalse($rename->isNarrowing);
        self::assertSame(['name' => 'author'], $rename->attributes()['change']);
        self::assertSame('editor', $rename->attributes()['role']);
        self::assertNull($created->tenant);
        self::assertArrayNotHasKey('target_id', $created->attributes());
        self::assertArrayNotHasKey('permission', $created->attributes());
        self::assertArrayNotHasKey('change', OperationResource::definition(PackagePermissions::ROLE_DELETE, $role)->attributes());
        self::assertArrayNotHasKey('role', OperationResource::definition(PackagePermissions::ROLE_DELETE, new StubIdentity(['id' => 'x']))->attributes());
    }

    /**
     * A record that is neither a role, a permission nor a policy is never named
     * under a kind, whatever name it has.
     *
     * @return void
     */
    public function testOnlyAPackageRecordsNameIsNamed(): void
    {
        $named = OperationResource::definition(PackagePermissions::ROLE_DELETE, new StubIdentity(['id' => 'x', 'name' => 'Ann']))->attributes();

        self::assertArrayNotHasKey('', $named);
        self::assertSame([], \array_intersect_key($named, ['role' => true, 'permission' => true, 'policy' => true]));
    }

    /**
     * A change that changes nothing names the grantee, the scope and, when
     * there is one, the target, only narrows, and is decided in the scope's
     * tenant.
     *
     * @return void
     */
    public function testAnUnchangedOperationOnlyNarrows(): void
    {
        $tenant = new Reference('stub_tenant', 'tenant-a');
        $role   = Role::create(['name' => 'editor']);
        $kept   = OperationResource::unchanged(PackagePermissions::ROLE_GRANT, new Reference('user', '1'), $role, new GrantScope($tenant, 'admin', false));
        $none   = OperationResource::unchanged(PackagePermissions::BOUNDARY_REMOVE, new Reference('user', '1'), null, GrantScope::platform());

        self::assertTrue($kept->isNarrowing);
        self::assertSame($tenant, $kept->tenant);
        self::assertSame([
            'action'       => PackagePermissions::ROLE_GRANT,
            'narrowing'    => true,
            'impersonated' => false,
            'target_type'  => $role->getMorphClass(),
            'target_id'    => $role->id,
            'role'         => 'editor',
            'grantee_type' => 'user',
            'grantee_id'   => '1',
            'application'  => 'admin',
            'subtree'      => false,
            'unchanged'    => true,
        ], $kept->attributes());
        self::assertNull($none->tenant);
        self::assertSame(['action', 'narrowing', 'impersonated', 'grantee_type', 'grantee_id', 'subtree', 'unchanged'], \array_keys($none->attributes()));
    }

    /**
     * A resource acted on by an operation with an id, while impersonated,
     * carries both, and offers the impersonator to policies; the rest is kept.
     *
     * @return void
     */
    public function testAnOperationActingOnItCarriesItsIdAndImpersonator(): void
    {
        $role     = Role::create(['name' => 'editor']);
        $proposed = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, new Reference('user', '1'), $role, GrantScope::platform());
        $acted    = $proposed->actedBy(new Reference('support', '9'), 'operation-1');

        self::assertSame('operation-1', $acted->id);
        self::assertEquals(new Reference('support', '9'), $acted->impersonator);
        self::assertSame($proposed->isNarrowing, $acted->isNarrowing);
        self::assertSame(PackagePermissions::ROLE_REVOKE, $acted->action);
        self::assertSame(
            ['impersonated' => true, 'impersonator_type' => 'support', 'impersonator_id' => '9'],
            \array_intersect_key($acted->attributes(), ['impersonated' => true, 'impersonator_type' => true, 'impersonator_id' => true]),
        );
        self::assertSame('operation-1', $acted->actedBy(null)->id);
        self::assertNull($acted->actedBy(null)->impersonator);
        $impersonation = ['impersonated' => true, 'impersonator_type' => true, 'impersonator_id' => true];

        self::assertSame(\array_diff_key($proposed->attributes(), $impersonation), \array_diff_key($acted->attributes(), $impersonation));
    }

    /**
     * Each grant, removal and unchanged change holds what it changes as values:
     * the grantee's reference, the target, the scope and the expiry in UTC; it
     * changes nothing only when unchanged; a definition holds none, and is
     * never unchanged; acting on the resource keeps them.
     *
     * @return void
     */
    public function testItHoldsTheChangeAsValues(): void
    {
        $role   = Role::create(['name' => 'editor']);
        $user   = StubIdentity::create(['id' => 'user-1']);
        $scope  = new GrantScope(new Reference('stub_tenant', 'tenant-a'), 'admin', false);
        $expiry = Carbon::parse('2026-07-02 14:00:00', 'Europe/Paris');
        $grant  = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $role, $scope, $expiry);
        $revoke = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, $user, $role, $scope);
        $kept   = OperationResource::unchanged(PackagePermissions::ROLE_REVOKE, $user, null, $scope);

        $change = $grant->change;

        self::assertNotNull($change);
        self::assertEquals(Reference::of($user), $change->grantee);
        self::assertSame($role, $change->target);
        self::assertSame($scope, $change->scope);
        self::assertSame('2026-07-02T12:00:00+00:00', $change->expiresAt?->format(\DATE_ATOM));
        self::assertFalse($grant->isUnchanged());
        self::assertSame([$role, null], [$revoke->change?->target, $revoke->change?->expiresAt]);
        self::assertFalse($revoke->isUnchanged());
        self::assertNull($kept->change?->target);
        self::assertTrue($kept->isUnchanged());
        self::assertSame($grant->change, $grant->actedBy(new Reference('support', '9'), 'operation-1')->change);
        self::assertNull(OperationResource::definition(PackagePermissions::ROLE_RENAME, $role)->change);
        self::assertFalse(OperationResource::definition(PackagePermissions::ROLE_RENAME, $role)->isUnchanged());
    }

    /**
     * A grant of what the grantee holds live in the same scope that lasts no
     * longer only narrows, and says so to policies; one of what it does not
     * hold does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantThatOnlyShortensOnlyNarrows(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $edit = Permission::create(['name' => 'posts:edit']);
        $read = Permission::create(['name' => 'posts:read']);

        GrantService::instance()?->grantPermission($user, $edit);

        $again = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, $edit, GrantScope::platform(), Carbon::now()->addDay());
        $fresh = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, $read, GrantScope::platform(), Carbon::now()->addDay());

        self::assertTrue($again->isNarrowing);
        self::assertTrue($again->attributes()['narrowing']);
        self::assertFalse($fresh->isNarrowing);
    }

    /**
     * A grant's descriptor is the same operation under
     * `authorization:permission.grantable`: its tenant, id, impersonator,
     * change and attributes kept, the action replaced, never narrowing nor
     * unchanged.
     *
     * @return void
     */
    public function testAGrantsDescriptorNamesTheSameDelegation(): void
    {
        $edit   = Permission::create(['name' => 'posts:edit']);
        $tenant = new Reference('stub_tenant', 'tenant-a');
        $grant  = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, new Reference('user', '1'), $edit, new GrantScope($tenant, 'admin'))
            ->actedBy(new Reference('support', '9'), 'operation-1');
        $kept       = OperationResource::unchanged(PackagePermissions::PERMISSION_GRANT, new Reference('user', '1'), $edit, GrantScope::platform());
        $descriptor = $grant->grantable();

        self::assertSame(PackagePermissions::PERMISSION_GRANTABLE, $descriptor->action);
        self::assertFalse($descriptor->isNarrowing);
        self::assertSame($tenant, $descriptor->tenant);
        self::assertSame('operation-1', $descriptor->id);
        self::assertEquals(new Reference('support', '9'), $descriptor->impersonator);
        self::assertSame($grant->change, $descriptor->change);
        self::assertSame(
            [...$grant->attributes(), 'action' => PackagePermissions::PERMISSION_GRANTABLE],
            $descriptor->attributes(),
        );
        self::assertArrayNotHasKey('unchanged', $kept->grantable()->attributes());
        self::assertFalse($kept->grantable()->attributes()['narrowing']);
    }

    /**
     * Its reference is a record of the operation type, keyed by the operation's
     * id, in the intended tenant, handing the resource on as its source, as
     * `check()` resolves it.
     *
     * @return void
     */
    public function testItsReferenceIsTheOperationInTheIntendedTenant(): void
    {
        $tenant    = new Reference('stub_tenant', 'tenant-a');
        $role      = Role::create(['name' => 'editor']);
        $operation = OperationResource::grant(PackagePermissions::ROLE_GRANT, new Reference('user', '1'), $role, new GrantScope($tenant))->actedBy(null, 'operation-1');
        $reference = $operation->toResourceReference();

        self::assertEquals(new ResourceReference('authorization:operation:operation-1', 'authorization:operation', 'operation-1', $tenant, null, $operation), $reference);
        self::assertSame($operation, $reference->source);
        self::assertEquals($reference, ResourceReferences::of($operation));
    }
}
