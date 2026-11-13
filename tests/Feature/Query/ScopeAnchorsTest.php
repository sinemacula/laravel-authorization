<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Preview\PreviewAdmission;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Preview\PreviewResource;
use SineMacula\Laravel\Authorization\Query\ScopeAnchors;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for the tenants a decision's sources may sit at, which the
 * scope's classes of rows are cut at.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ScopeAnchors::class)]
final class ScopeAnchorsTest extends TestCase
{
    use ActivatesBreakGlass, ScopesQueries;

    /**
     * Every tenant a source of the subject or its identity sits at is read,
     * whatever its expiry or application: their grants, policies and
     * boundaries, the policies of the roles they hold and every role above, the
     * owners of those roles and of the permissions granted to them or through
     * the roles, the guardrails and the policies attached to the type; never
     * another's grant or another type's attachment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryTenantASourceSitsAtIsRead(): void
    {
        $user     = StubIdentity::create(['id' => 'u1']);
        $identity = StubIdentity::create(['id' => 'u2']);
        $other    = StubIdentity::create(['id' => 'u3']);
        $parent   = Role::create(['name' => 'parent', 'tenant_type' => 'teams', 'tenant_id' => 'owner']);
        $child    = Role::create(['name' => 'child', 'parent_id' => $parent->getKey(), 'tenant_type' => 'teams', 'tenant_id' => 'owner']);
        $owned    = Permission::create(['name' => 'posts:owned', 'tenant_type' => 'teams', 'tenant_id' => 'permission']);

        $user->givePermission(Permission::create(['name' => 'posts:view']), now()->subDay(), new Reference('teams', 'expired'), true, 'other');
        $identity->assignRole($child, null, new Reference('teams', 'owner'));
        $user->givePermission($owned, null, new Reference('teams', 'permission'));
        $parent->attachPolicy(self::storedPolicy('role-policy', []), null, new Reference('teams', 'role-policy'));
        $other->givePermission(Permission::create(['name' => 'posts:edit']), null, new Reference('teams', 'stranger'));

        // Owners apart from where they are granted, and a role carrying a
        // permission another tenant owns, which no grant made here allows but
        // the tables can hold.
        DB::table('roles')->update(['tenant_id' => 'role-owner']);
        DB::table('permissions')->where('id', $owned->getKey())->update(['tenant_id' => 'owned-permission']);
        $inherited = Permission::create(['name' => 'posts:inherited', 'tenant_type' => 'teams', 'tenant_id' => 'inherited']);

        DB::table('role_permissions')->insert(['role_id' => $child->getKey(), 'permission_id' => $inherited->getKey()]);

        app(ResourcePolicyService::class)->attach(self::storedPolicy('typed', []), ScopedPost::class, new Reference('teams', 'attached'));
        app(ResourcePolicyService::class)->attach(self::storedPolicy('other-type', []), 'comments', new Reference('teams', 'other-type'));
        DB::table('guardrails')->insert(['policy_id' => self::storedPolicy('railed', [])->getKey(), 'tenant_type' => 'teams', 'tenant_id' => 'railed']);

        [$sources, $admitted] = ScopeAnchors::read(new Subject($user, $identity), (new ScopedPost)->getMorphClass(), true);

        $ids = static fn (array $tenants): array => \array_map(static fn (Reference $tenant): string => $tenant->id, $tenants);

        self::assertEqualsCanonicalizing(['expired', 'owner', 'role-owner', 'role-policy', 'permission', 'owned-permission', 'inherited', 'attached', 'railed'], $ids($sources));
        self::assertEqualsCanonicalizing(['attached', 'railed'], $ids($admitted));
        self::assertSame($ids($admitted), $ids(ScopeAnchors::read(new Subject($user, $identity), (new ScopedPost)->getMorphClass(), false)[0]));
    }

    /**
     * Tenants of different types with the same id are told apart, among the
     * sources and among those a row admitted from outside reads.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTenantsOfTheSameIdAndAnotherTypeAreToldApart(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']), null, new Reference('teams', '5'));
        DB::table('guardrails')->insert(['policy_id' => self::storedPolicy('railed', [])->getKey(), 'tenant_type' => 'orgs', 'tenant_id' => '5']);
        app(ResourcePolicyService::class)->attach(self::storedPolicy('typed', []), ScopedPost::class, new Reference('teams', '5'));

        [$sources, $admitted] = ScopeAnchors::read(new Subject($user, $user), (new ScopedPost)->getMorphClass(), true);

        $pairs = static fn (array $tenants): array => \array_map(static fn (Reference $tenant): string => $tenant->type . ':' . $tenant->id, $tenants);

        self::assertEqualsCanonicalizing(['teams:5', 'orgs:5'], $pairs($sources));
        self::assertEqualsCanonicalizing(['teams:5', 'orgs:5'], $pairs($admitted));
    }

    /**
     * A subject that is not a model holds no grant, so none of another model's
     * grant tenants is read: only the tenants a row admitted from outside
     * reads, and those of an identity behind it that is a model.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectThatIsNotAModelReadsNoGrantTenant(): void
    {
        $other = StubIdentity::create(['id' => 'u3']);

        $other->givePermission(Permission::create(['name' => 'posts:view']), null, new Reference('teams', 'stranger'));
        $other->assignRole(Role::create(['name' => 'held']), null, new Reference('teams', 'held'));
        DB::table('guardrails')->insert(['policy_id' => self::storedPolicy('railed', [])->getKey(), 'tenant_type' => 'teams', 'tenant_id' => 'railed']);

        [$sources, $admitted] = ScopeAnchors::read(new Subject(new \stdClass), (new ScopedPost)->getMorphClass(), true);

        $ids = static fn (array $tenants): array => \array_map(static fn (Reference $tenant): string => $tenant->id, $tenants);

        self::assertSame(['railed'], $ids($sources));
        self::assertSame(['railed'], $ids($admitted));

        $identity = StubIdentity::create(['id' => 'u4']);

        $identity->givePermission(Permission::create(['name' => 'posts:list']), null, new Reference('teams', 'identity'));

        self::assertSame(['identity', 'railed'], $ids(ScopeAnchors::read(new Subject(new \stdClass, $identity), (new ScopedPost)->getMorphClass(), true)[0]));
    }

    /**
     * For the subject of a running use of a preview, the previewer's grant
     * tenants are read too, with the tenants of the policies attached to
     * preview resources; for any other subject, the same principal named apart
     * included, and once the use has ended, they are not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewsSubjectReadsItsPreviewersTenantsToo(): void
    {
        $target = StubIdentity::create(['id' => 'target']);
        $caller = StubIdentity::create(['id' => 'caller']);

        $target->givePermission(Permission::create(['name' => 'posts:view']), null, new Reference('teams', 'theirs'));
        $caller->givePermission(Permission::create(['name' => PackagePermissions::SUBJECT_PREVIEW]), null, new Reference('teams', 'callers'));
        app(ResourcePolicyService::class)->attach(self::storedPolicy('previews', []), PreviewResource::TYPE, new Reference('teams', 'previews'));

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($caller, $caller)));
        $this->app?->forgetInstance(AuthorizationManager::class);

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager   = $this->app?->make(AuthorizationManager::class);
        $about     = new Subject($target, $target);
        $type      = (new ScopedPost)->getMorphClass();
        $admission = new PreviewAdmission($manager, new PreviewResource(Reference::of($target), null, null, null));
        $ids       = static fn (array $tenants): array => \array_map(static fn (Reference $tenant): string => $tenant->id, $tenants);

        [$during, $apart] = Previewing::current()->evaluating($about, $admission, static fn (): array => [
            ScopeAnchors::read($about, $type, true)[0],
            ScopeAnchors::read(new Subject($target, $target), $type, true)[0],
        ]);

        self::assertEqualsCanonicalizing(['theirs', 'callers', 'previews'], $ids($during));
        self::assertSame(['theirs'], $ids($apart));
        self::assertSame(['theirs'], $ids(ScopeAnchors::read($about, $type, true)[0]));
    }

    /**
     * The tenant of every break-glass activation of the subject or its identity
     * is read, whatever its expiry, with the owners of the role it activates
     * and of the roles above, and the tenants of their policies and
     * permissions; another's activation is not, and none while break-glass is
     * disabled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryActivationsTenantAndItsRolesAreRead(): void
    {
        $user   = StubIdentity::create(['id' => 'u1']);
        $other  = StubIdentity::create(['id' => 'u3']);
        $parent = Role::create(['name' => 'parent']);
        $role   = Role::create(['name' => 'responder', 'parent_id' => $parent->getKey()]);
        $owned  = Permission::create(['name' => 'posts:owned', 'tenant_type' => 'teams', 'tenant_id' => 'permission']);

        DB::table('role_permissions')->insert(['role_id' => $parent->getKey(), 'permission_id' => $owned->getKey()]);
        $parent->attachPolicy(self::storedPolicy('role-policy', []), null, new Reference('teams', 'role-policy'));
        DB::table('roles')->where('id', $role->getKey())->update(['tenant_type' => 'teams', 'tenant_id' => 'role-owner']);

        self::activate($user, $role, ['tenant_type' => 'teams', 'tenant_id' => 'activated', 'expires_at' => now()->subDay()]);
        self::activate($other, Role::create(['name' => 'other']), ['tenant_type' => 'teams', 'tenant_id' => 'stranger']);

        [$sources] = ScopeAnchors::read(new Subject($user, $user), (new ScopedPost)->getMorphClass(), true);

        self::assertEqualsCanonicalizing(['activated', 'role-owner', 'role-policy', 'permission'], \array_map(static fn (Reference $tenant): string => $tenant->id, $sources));

        self::switchBreakGlass(false);

        self::assertSame([], ScopeAnchors::read(new Subject($user, $user), (new ScopedPost)->getMorphClass(), true)[0]);
    }
}
