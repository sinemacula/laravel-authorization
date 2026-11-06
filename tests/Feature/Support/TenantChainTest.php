<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for a tenant and its ancestors, and the queries limited to what
 * they see and the grants that reach them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantChain::class)]
final class TenantChainTest extends TestCase
{
    use ActsAsTenant;

    /**
     * A tenant's chain is the tenant, then its ancestors nearest first; the
     * platform's is empty.
     *
     * @return void
     */
    public function testTheChainIsTheTenantThenItsAncestors(): void
    {
        [$account, $org, $group] = self::tenants();
        $tree                    = self::tree($account, $org, $group);

        $chain = TenantChain::of($account, $tree);

        self::assertEquals([$account, $org, $group], $chain->tenants);
        self::assertEquals($account, $chain->tenant());
        self::assertSame([], TenantChain::of(null, $tree)->tenants);
        self::assertNull(TenantChain::of(null, $tree)->tenant());
        self::assertNull((new TenantChain)->tenant());
    }

    /**
     * Whether a tenant is within another is asked of the bound tree; the
     * platform is within no tenant.
     *
     * @return void
     */
    public function testIsWithinAsksTheBoundTree(): void
    {
        [$account, $org, $group] = self::tenants();
        $tree                    = self::tree($account, $org, $group);

        $this->app?->instance(TenantTree::class, $tree);

        self::assertSame($tree, TenantChain::tree());
        self::assertTrue(TenantChain::isWithin($account, $group));
        self::assertTrue(TenantChain::isWithin($account, $account));
        self::assertFalse(TenantChain::isWithin($org, $account));
        self::assertFalse(TenantChain::isWithin(null, $org));
    }

    /**
     * A tenant sees the platform's records and those of every tenant on its
     * chain, grouped so the limit narrows the query; the platform sees its own
     * only.
     *
     * @return void
     */
    public function testOwnersAreThePlatformAndTheChain(): void
    {
        [$account, $org, $group, $sibling] = self::tenants();

        foreach ([null, $account, $org, $group, $sibling] as $owner) {
            Role::query()->withoutGlobalScope(TenantScope::class)->create(['name' => $owner === null ? 'platform' : $owner->id, ...self::owner($owner)]);
        }

        $chain = TenantChain::of($account, self::tree($account, $org, $group));

        $seen = $chain->owners(self::roles()->where('name', '!=', 'group'), 'roles.tenant_type', 'roles.tenant_id');

        self::assertEqualsCanonicalizing(['platform', 'account', 'org'], self::names($seen));
        self::assertSame(['platform'], self::names((new TenantChain)->owners(self::roles(), 'roles.tenant_type', 'roles.tenant_id')));
    }

    /**
     * Platform-wide grants and the tenant's own hold in it, whether they reach
     * below or not; an ancestor's hold only when they reach the tenants below
     * it, and another tenant's never.
     *
     * @return void
     */
    public function testGrantsReachFromAncestorsThatIncludeTheirSubtree(): void
    {
        [$account, $org, $group, $sibling] = self::tenants();
        $role                              = Role::query()->create(['name' => 'editor']);

        foreach ([[null, true], [$account, false], [$org, true], [$group, false], [$sibling, true]] as $index => [$tenant, $subtree]) {
            DB::table('authorizable_roles')->insert([
                'role_id'           => $role->id,
                'authorizable_type' => 'stub_identity',
                'authorizable_id'   => (string) $index,
                'tenant_type'       => $tenant?->type,
                'tenant_id'         => $tenant?->id,
                'include_subtree'   => $subtree,
            ]);
        }

        $chain = TenantChain::of($account, self::tree($account, $org, $group));
        $query = DB::table('authorizable_roles')->where('authorizable_id', '!=', '2');

        self::assertSame($query, $chain->grants($query, 'authorizable_roles'));
        self::assertEqualsCanonicalizing(['0', '1'], $query->pluck('authorizable_id')->all());
        $every = $chain->grants(DB::table('authorizable_roles'), 'authorizable_roles');

        self::assertEqualsCanonicalizing(['0', '1', '2'], $every->pluck('authorizable_id')->all());
        self::assertSame(['0'], (new TenantChain)->grants(DB::table('authorizable_roles'), 'authorizable_roles')->pluck('authorizable_id')->all());
    }

    /**
     * Records are ordered nearest owner first: the tenant's, each ancestor's in
     * turn, then the platform's; the platform's chain leaves the order alone.
     *
     * @return void
     */
    public function testNearestOwnerComesFirst(): void
    {
        [$account, $org, $group] = self::tenants();

        foreach ([$group, null, $account, $org] as $owner) {
            Role::query()->withoutGlobalScope(TenantScope::class)->create(['name' => 'editor', ...self::owner($owner)]);
        }

        $grammar = DB::connection()->getQueryGrammar();
        $chain   = TenantChain::of($account, self::tree($account, $org, $group));
        $query   = self::roles();

        self::assertSame($query, $chain->nearestFirst($query, $grammar->wrap('roles.tenant_type'), $grammar->wrap('roles.tenant_id')));
        self::assertSame(['account', 'org', 'group', null], $query->pluck('tenant_id')->all());

        $unordered = self::roles();

        (new TenantChain)->nearestFirst($unordered, 'tenant_type', 'tenant_id');

        self::assertNull($unordered->getQuery()->orders);
    }

    /**
     * Return four tenants: an account, the organisation above it, the group
     * above that, and a sibling of the account.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function tenants(): array
    {
        return \array_map(static fn (string $id): Reference => Reference::of(StubTenant::query()->create(['id' => $id, 'name' => $id])), ['account', 'org', 'group', 'sibling']);
    }

    /**
     * Return a tree with the account under the organisation under the group,
     * and a sibling of the account under the group.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $account
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $org
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $group
     * @return \Tests\Feature\Stubs\StubTenantTree
     */
    private static function tree(Reference $account, Reference $org, Reference $group): StubTenantTree
    {
        return (new StubTenantTree)->put($account, $org)->put($org, $group);
    }

    /**
     * Return the owner columns for the tenant, or the platform's for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return array{tenant_type: string|null, tenant_id: string|null}
     */
    private static function owner(?Reference $tenant): array
    {
        return ['tenant_type' => $tenant?->type, 'tenant_id' => $tenant?->id];
    }

    /**
     * Query every role, outside the tenant scope.
     *
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function roles(): Builder
    {
        return Role::query()->withoutGlobalScope(TenantScope::class);
    }

    /**
     * Return the names the role query reads.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Role>  $query
     * @return list<string>
     */
    private static function names(Builder $query): array
    {
        /** @var list<string> */
        return $query->pluck('name')->all();
    }
}
