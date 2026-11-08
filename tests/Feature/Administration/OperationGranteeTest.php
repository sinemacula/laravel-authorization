<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\OperationGrantee;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `OperationGrantee`, who an operation is for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationGrantee::class)]
final class OperationGranteeTest extends TestCase
{
    /**
     * A grant or a removal for an identity or a principal is for a subject; one
     * for a role, a resource policy's attachment and a change to a definition
     * are not.
     *
     * @return void
     */
    public function testOnlyAGrantOrRemovalForAnIdentityIsForASubject(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $edit   = Permission::create(['name' => 'posts:edit']);
        $policy = Policy::create(['name' => 'share', 'document' => ['statements' => []]]);

        self::assertTrue(OperationGrantee::isSubject(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, $edit, GrantScope::platform())));
        self::assertTrue(OperationGrantee::isSubject(OperationResource::revoke(PackagePermissions::BOUNDARY_REMOVE, new Reference('user', '9'), $policy, GrantScope::platform())));
        self::assertTrue(OperationGrantee::isSubject(OperationResource::unchanged(PackagePermissions::ROLE_REVOKE, $user, null, GrantScope::platform())));
        self::assertFalse(OperationGrantee::isSubject(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $role, $edit, GrantScope::platform())));
        $platform = GrantScope::platform();

        self::assertFalse(OperationGrantee::isSubject(OperationResource::grant(PackagePermissions::RESOURCE_POLICY_ATTACH, new Reference('posts', '7'), $policy, $platform)));
        self::assertFalse(OperationGrantee::isSubject(OperationResource::revoke(PackagePermissions::RESOURCE_POLICY_DETACH, new Reference('posts', '*'), $policy, $platform)));
        self::assertFalse(OperationGrantee::isSubject(OperationResource::definition(PackagePermissions::ROLE_RENAME, $role)));
    }

    /**
     * A role is told by the configured role model's morph type.
     *
     * @return void
     */
    public function testARoleIsToldByTheConfiguredModel(): void
    {
        self::assertTrue(OperationGrantee::isRole(Reference::of(Role::create(['name' => 'editor']))));
        self::assertFalse(OperationGrantee::isRole(new Reference('user', '1')));

        config(['authorization.models.role' => CustomRole::class]);

        self::assertTrue(OperationGrantee::isRole(new Reference((new CustomRole)->getMorphClass(), '1')));
    }

    /**
     * The grantee is the actor when it is the actor's principal or the identity
     * behind it, by type and key; a principal or identity that is not a model
     * is never the grantee.
     *
     * @return void
     */
    public function testTheGranteeIsTheActorWhenItIsItsPrincipalOrIdentity(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $other = StubIdentity::create(['id' => 'user-2']);
        $edit  = Permission::create(['name' => 'posts:edit']);
        $grant = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, $edit, GrantScope::platform());

        self::assertTrue(OperationGrantee::isSelf($grant, new Subject($user, $user)));
        self::assertTrue(OperationGrantee::isSelf($grant, new Subject($other, $user)));
        self::assertTrue(OperationGrantee::isSelf($grant, new Subject($user, new \stdClass)));
        self::assertFalse(OperationGrantee::isSelf($grant, new Subject($other, $other)));
        self::assertFalse(OperationGrantee::isSelf($grant, new Subject(new \stdClass)));
        $named = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, new Reference($user->getMorphClass(), 'user-2'), $edit, GrantScope::platform());

        self::assertFalse(OperationGrantee::isSelf($named, new Subject($user, $user)));
        self::assertFalse(OperationGrantee::isSelf(OperationResource::definition(PackagePermissions::ROLE_RENAME, Role::create(['name' => 'editor'])), new Subject($user, $user)));
        self::assertTrue(OperationGrantee::isActor(Reference::of($user), new Subject($other, $user)));
        self::assertTrue(OperationGrantee::isActor(Reference::of($user), new Subject($user, new \stdClass)));
        self::assertFalse(OperationGrantee::isActor(Reference::of($other), new Subject($user, $user)));
        self::assertFalse(OperationGrantee::isActor(new Reference($user->getMorphClass(), 'USER-1'), new Subject($user, $user)));
        self::assertFalse(OperationGrantee::isActor(Reference::of($user), new Subject(new \stdClass)));
    }

    /**
     * The grantee's model is read by its morph type, through the morph map when
     * it names one, past the model's global scopes; a type that names no model,
     * and a record that does not exist, give none.
     *
     * @return void
     */
    public function testTheGranteesModelIsReadByItsMorphType(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::assertTrue($user->is(OperationGrantee::model(Reference::of($user))));
        self::assertNull(OperationGrantee::model(new Reference($user->getMorphClass(), 'missing')));
        self::assertNull(OperationGrantee::model(new Reference('external', '1')));
        self::assertNull(OperationGrantee::model(new Reference(\stdClass::class, '1')));

        Relation::morphMap(['identity' => StubIdentity::class]);

        try {
            self::assertTrue($user->is(OperationGrantee::model(new Reference('identity', 'user-1'))));
        } finally {
            Relation::morphMap([], false);
        }
    }
}
