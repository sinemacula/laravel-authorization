<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Query\ScopeAnchors;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ScopesQueries;
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
    use ScopesQueries;

    /**
     * Every tenant a source of the subject or its identity sits at is read,
     * whatever its expiry or application: their grants, policies and
     * boundaries, the policies of the roles they hold and every role above, the
     * owners of those roles and of the permissions granted, the guardrails and
     * the policies attached to the type; never another's grant or another
     * type's attachment.
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

        app(ResourcePolicyService::class)->attach(self::storedPolicy('typed', []), ScopedPost::class, new Reference('teams', 'attached'));
        app(ResourcePolicyService::class)->attach(self::storedPolicy('other-type', []), 'comments', new Reference('teams', 'other-type'));
        DB::table('guardrails')->insert(['policy_id' => self::storedPolicy('railed', [])->getKey(), 'tenant_type' => 'teams', 'tenant_id' => 'railed']);

        [$sources, $admitted] = ScopeAnchors::read(new Subject($user, $identity), (new ScopedPost)->getMorphClass(), true);

        $ids = static fn (array $tenants): array => \array_map(static fn (Reference $tenant): string => $tenant->id, $tenants);

        self::assertEqualsCanonicalizing(['expired', 'owner', 'role-policy', 'permission', 'attached', 'railed'], $ids($sources));
        self::assertEqualsCanonicalizing(['attached', 'railed'], $ids($admitted));
        self::assertSame($ids($admitted), $ids(ScopeAnchors::read(new Subject($user, $identity), (new ScopedPost)->getMorphClass(), false)[0]));
    }
}
