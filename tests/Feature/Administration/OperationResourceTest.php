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
