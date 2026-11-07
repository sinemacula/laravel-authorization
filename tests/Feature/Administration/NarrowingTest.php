<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\Narrowing;
use SineMacula\Laravel\Authorization\Administration\OperationChange;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `Narrowing`, which tells whether removing a grant can only
 * narrow authority.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Narrowing::class)]
final class NarrowingTest extends TestCase
{
    use ActsAsTenant, UsesAnAuthorizationConnection;

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Revoking a permission always narrows; removing a boundary never does, nor
     * does any action that is not a removal, nor a removal of a target of
     * another kind.
     *
     * @return void
     */
    public function testAPermissionRevocationNarrowsAndABoundaryRemovalNever(): void
    {
        $permission = Permission::create(['name' => 'posts:edit']);
        $allowing   = self::policy('allowing', 'allow');

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::PERMISSION_REVOKE, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::BOUNDARY_REMOVE, $allowing));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::PERMISSION_GRANT, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::POLICY_DETACH, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::RESOURCE_POLICY_DETACH, $permission));
    }

    /**
     * Detaching a policy, from a grantee or a resource, narrows when the policy
     * as stored has no deny statement; one that denies, one whose document
     * cannot be read and one that is gone do not.
     *
     * @return void
     */
    public function testDetachingAnAllowOnlyPolicyNarrows(): void
    {
        $allowing = self::policy('allowing', 'allow');
        $denying  = self::policy('denying', 'deny');
        $broken   = self::policy('broken', 'allow');

        DB::table('policies')->where('id', $broken->id)->update(['document' => '{"statements": "not a list"}']);

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::POLICY_DETACH, $allowing));
        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::RESOURCE_POLICY_DETACH, $allowing));
        self::assertTrue(Narrowing::isAllowOnly($allowing));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::POLICY_DETACH, $denying));
        self::assertFalse(Narrowing::isAllowOnly($broken));
        self::assertFalse(Narrowing::isAllowOnly(new Policy(['name' => 'unsaved'])));
    }

    /**
     * The policy judged is the one stored, never the model as the caller holds
     * it.
     *
     * @return void
     */
    public function testThePolicyIsJudgedAsStored(): void
    {
        $policy = self::policy('allowing', 'allow');

        DB::table('policies')->where('id', $policy->id)->update(['document' => \json_encode(['statements' => [['effect' => 'deny', 'actions' => ['*']]]])]);

        self::assertFalse(Narrowing::isAllowOnly($policy));
    }

    /**
     * Revoking a role narrows when no policy attached to it or to any of its
     * ancestors denies anything, in any scope; an allow-only policy attached to
     * it keeps it narrowing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingARoleNarrowsUnlessADenyIsAttachedToItOrAnAncestor(): void
    {
        $parent = Role::create(['name' => 'staff']);
        $role   = Role::create(['name' => 'editor', 'parent_id' => $parent->id]);
        $other  = Role::create(['name' => 'author']);
        $grants = GrantService::instance();

        self::assertNotNull($grants);
        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));

        $grants->attachPolicy($role, self::policy('allowing', 'allow'));
        $grants->attachPolicy(StubIdentity::create(['id' => 'user-1']), self::policy('elsewhere', 'deny'));

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));

        $grants->attachPolicy($parent, self::policy('denying', 'deny'));

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $parent));
        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $other));
    }

    /**
     * The role's ancestors and their attachments are read outside every tenant
     * scope, so a deny attached to an ancestor owned by a tenant the check's
     * scope does not show, a tenant below the one active, or any tenant when
     * none is, still keeps the revocation from narrowing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAncestorTheTenantScopeHidesStillCounts(): void
    {
        [$parent, $child] = \array_map(self::createTenant(...), ['parent', 'child']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        $restricted = Role::query()->withoutGlobalScopes()->create(['name' => 'restricted', ...self::ownedBy($child)]);
        $editor     = Role::query()->withoutGlobalScopes()->create(['name' => 'editor', 'parent_id' => $restricted->id, ...self::ownedBy($child)]);

        GrantService::instance()?->attachPolicy($restricted, self::policy('denying', 'deny'), tenant: $child);

        $this->actAsTenant($parent);

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $editor));

        $this->actAsTenant(null);

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $editor));
    }

    /**
     * With the role hierarchy disabled, a role holds nothing of its ancestors,
     * so only a deny attached to the role itself keeps its revocation from
     * narrowing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheHierarchyDisabledOnlyTheRoleCounts(): void
    {
        $parent = Role::create(['name' => 'staff']);
        $role   = Role::create(['name' => 'editor', 'parent_id' => $parent->id]);

        GrantService::instance()?->attachPolicy($parent, self::policy('denying', 'deny'));
        config()->set('authorization.hierarchy.enabled', false);

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));

        GrantService::instance()?->attachPolicy($role, self::policy('own', 'deny'));

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));
    }

    /**
     * A chain that cannot be read whole is taken to deny: one that returns to a
     * role it has passed, and a role that is not stored.
     *
     * @return void
     */
    public function testAChainThatCannotBeReadWholeIsTakenToDeny(): void
    {
        $first  = Role::create(['name' => 'first']);
        $second = Role::create(['name' => 'second', 'parent_id' => $first->id]);

        DB::table('roles')->where('id', $first->id)->update(['parent_id' => $second->id]);

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $second));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, (new Role)->forceFill(['id' => '01a1b0c0-0000-7000-8000-00000000dead'])));
    }

    /**
     * The attachments are read on the write connection, as the decision reads
     * them, so a replica that has not caught up never hides a deny, and a
     * screen judges what the service judges.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAttachmentsAreReadOnTheWriteConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $config = config();

        $config->set('database.connections.split', [
            'driver' => 'sqlite',
            'prefix' => '',
            'read'   => ['database' => ':memory:'],
            'write'  => ['database' => ':memory:'],
        ]);

        DB::purge('split');
        DB::connection('split')->setPdo(self::authorizationConnection()->getPdo());
        $config->set('authorization.connection', 'split');

        $role = Role::create(['name' => 'editor']);

        GrantService::instance()?->attachPolicy($role, self::policy('denying', 'deny'));

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));
    }

    /**
     * A grant of what the grantee holds live in the same scope only shortens or
     * narrows it when it lasts no longer and reaches no further, and revoking
     * it would only narrow; an extension, a wider reach, a grant in another
     * scope, one of what is not held or has expired, and one of a role that a
     * deny is attached to may widen.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantShortensOnlyWhatTheGranteeHoldsLive(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-11-07 12:00:00', 'UTC'));

        $user     = StubIdentity::create(['id' => 'user-1']);
        $grantee  = Reference::of($user);
        $tenant   = new Reference('tenant', 'a');
        $edit     = Permission::create(['name' => 'posts:edit']);
        $read     = Permission::create(['name' => 'posts:read']);
        $denying  = Role::create(['name' => 'denying']);
        $inTenant = new GrantScope($tenant);
        $change   = static fn (Model $target, ?GrantScope $scope = null, ?Carbon $until = null): OperationChange => self::change($grantee, $target, $scope ?? $inTenant, $until);

        GrantService::instance()?->grantPermission($user, $edit, Carbon::now()->addDays(3), tenant: $tenant, includeSubtree: false);
        GrantService::instance()?->grantPermission($user, $read, tenant: $tenant);
        GrantService::instance()?->attachPolicy($denying, self::policy('denying', 'deny'));
        GrantService::instance()?->grantRole($user, $denying, tenant: $tenant);

        $grant = PackagePermissions::PERMISSION_GRANT;

        self::assertTrue(Narrowing::isShortening($grant, $change($edit, new GrantScope($tenant, null, false), Carbon::now()->addDay())));
        self::assertTrue(Narrowing::isShortening($grant, $change($edit, new GrantScope($tenant, null, false), Carbon::now()->addDays(3))));
        self::assertTrue(Narrowing::isShortening($grant, $change($read)));
        self::assertTrue(Narrowing::isShortening($grant, $change($read, new GrantScope($tenant, null, false), Carbon::now()->addDay())));
        self::assertFalse(Narrowing::isShortening($grant, $change($edit, new GrantScope($tenant, null, false), Carbon::now()->addDays(4))));
        self::assertFalse(Narrowing::isShortening($grant, $change($edit, new GrantScope($tenant, null, false))));
        self::assertFalse(Narrowing::isShortening($grant, $change($edit, new GrantScope($tenant), Carbon::now()->addDay())));
        self::assertFalse(Narrowing::isShortening($grant, $change($read, new GrantScope($tenant, 'admin'))));
        self::assertFalse(Narrowing::isShortening($grant, $change($read, GrantScope::platform())));
        self::assertFalse(Narrowing::isShortening(PackagePermissions::ROLE_GRANT, $change($denying)));

        Carbon::setTestNow(Carbon::now()->addDays(4));

        self::assertFalse(Narrowing::isShortening($grant, $change($edit, new GrantScope($tenant, null, false), Carbon::now()->addDay())));
    }

    /**
     * Setting a boundary narrows where the grantee has none in the scope, or
     * where it replaces one there with the same policy or one that can only
     * narrow it, reaching no fewer tenants; a wider document, a narrower reach,
     * or a boundary in another scope left alone, may widen.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryTightensOnlyWhereItCapsNoLess(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $grantee = Reference::of($user);
        $tenant  = new Reference('tenant', 'a');
        $read    = ['effect' => 'allow', 'actions' => ['posts:read']];
        $wide    = Policy::create(['name' => 'wide', 'document' => ['statements' => [$read, ['effect' => 'allow', 'actions' => ['posts:edit']]]]]);
        $narrow  = Policy::create(['name' => 'narrow', 'document' => ['statements' => [$read]]]);
        $other   = Policy::create(['name' => 'other', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]]);
        $set     = static fn (Policy $policy, ?GrantScope $scope = null): bool => Narrowing::isShortening(
            PackagePermissions::BOUNDARY_SET,
            self::change($grantee, $policy, $scope ?? new GrantScope($tenant), null),
        );

        self::assertTrue($set($other));

        BoundaryService::instance()?->set($user, $wide, $tenant);

        self::assertTrue($set($wide));
        self::assertTrue($set($narrow));
        self::assertFalse($set($other));
        self::assertFalse($set($narrow, new GrantScope($tenant, null, false)));
        self::assertTrue($set($other, GrantScope::platform()));
        self::assertFalse(Narrowing::isShortening(PackagePermissions::BOUNDARY_SET, new OperationChange($grantee, null, new GrantScope($tenant))));

        BoundaryService::instance()?->set($user, $narrow, $tenant, false);

        self::assertTrue($set($narrow, new GrantScope($tenant, null, false)));
        self::assertTrue($set($narrow));
        self::assertFalse($set($wide));
    }

    /**
     * A grant to a role, and a grant that names no target, never shorten one
     * the grantee holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantToARoleOrOfNothingNeverShortens(): void
    {
        $role = Role::create(['name' => 'editor']);
        $edit = Permission::create(['name' => 'posts:edit']);

        GrantService::instance()?->grantPermission(Reference::of($role), $edit);

        self::assertFalse(Narrowing::isShortening(PackagePermissions::PERMISSION_GRANT, new OperationChange(Reference::of($role), $edit, GrantScope::platform())));
        self::assertFalse(Narrowing::isShortening(PackagePermissions::PERMISSION_GRANT, new OperationChange(new Reference('user', '1'), null, GrantScope::platform())));
    }

    /**
     * Return the change of a grant of the target to the grantee in the scope,
     * until the expiry or forever.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \Illuminate\Support\Carbon|null  $expiresAt
     * @return \SineMacula\Laravel\Authorization\Administration\OperationChange
     */
    private static function change(Reference $grantee, Model $target, GrantScope $scope, ?Carbon $expiresAt): OperationChange
    {
        return new OperationChange($grantee, $target, $scope, $expiresAt);
    }

    /**
     * Create a policy of one statement with the effect.
     *
     * @param  string  $name
     * @param  string  $effect
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, string $effect): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => $effect, 'actions' => ['posts:*']]]]]);
    }
}
