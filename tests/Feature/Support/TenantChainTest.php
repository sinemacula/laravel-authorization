<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
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
     * platform's is empty. Two chains are the same when they list the same
     * tenants in the same order.
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
        self::assertTrue($chain->isSameAs(new TenantChain([$account, $org, $group])));
        self::assertFalse($chain->isSameAs(new TenantChain([$account, $group, $org])));
        self::assertFalse($chain->isSameAs(new TenantChain([$account, $org])));
        self::assertFalse($chain->isSameAs(new TenantChain([$account, $org, new Reference('stub_tenant', 'other')])));
        self::assertFalse($chain->isBelow);
        self::assertFalse($chain->isSameAs(TenantChain::of($account, $tree, true)));
        self::assertTrue(TenantChain::of($account, $tree, true)->isBelow);
        self::assertTrue(TenantChain::of($account, $tree, true)->isSameAs(new TenantChain([$account, $org, $group], true)));
        self::assertFalse(TenantChain::of(null, $tree, true)->isBelow);
    }

    /**
     * A chain starts at its tenant alone: not at an ancestor, another tenant of
     * the same type, or the same key of another type; the platform's starts at
     * none.
     *
     * @return void
     */
    public function testAChainIsAtItsOwnTenant(): void
    {
        [$account, $org, $group] = self::tenants();

        $chain = TenantChain::of($account, self::tree($account, $org, $group));

        self::assertTrue($chain->isAt(new Reference($account->type, $account->id)));
        self::assertFalse($chain->isAt($org));
        self::assertFalse($chain->isAt(new Reference('other_tenant', $account->id)));
        self::assertFalse((new TenantChain)->isAt($account));
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

        // Just below a tenant, its own grants hold only when they reach below,
        // as an ancestor's do.
        $belowAccount = TenantChain::of($account, self::tree($account, $org, $group), true);
        $belowGroup   = TenantChain::of($group, self::tree($account, $org, $group), true);

        self::assertEqualsCanonicalizing(['0', '2'], $belowAccount->grants(DB::table('authorizable_roles'), 'authorizable_roles')->pluck('authorizable_id')->all());
        self::assertSame(['0'], $belowGroup->grants(DB::table('authorizable_roles'), 'authorizable_roles')->pluck('authorizable_id')->all());
        $atGroup = TenantChain::of($group, self::tree($account, $org, $group));

        self::assertEqualsCanonicalizing(['0', '3'], $atGroup->grants(DB::table('authorizable_roles'), 'authorizable_roles')->pluck('authorizable_id')->all());
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
     * Within a batch of checks, the tree is asked for a tenant's ancestors, and
     * whether a tenant is within another, once for each tenant or pair, unless
     * the ancestors are read afresh; outside one, and with no resolution cache,
     * it is asked every time.
     *
     * @return void
     */
    public function testWithinABatchTheTreeIsAskedEachQuestionOnce(): void
    {
        $account = new Reference('stub_tenant', 'account');
        $org     = new Reference('stub_tenant', 'org');
        $other   = new Reference('stub_tenant', 'other');
        $tree    = (new StubTenantTree)->put($account, $org);
        $cache   = new ResolutionCache;

        $this->app?->instance(TenantTree::class, $tree);
        $this->app?->instance(ResolutionCache::class, $cache);

        $answers = $cache->batch(static fn (): array => [
            TenantChain::of($account, $tree)->tenants,
            TenantChain::of($account, $tree, true)->tenants,
            TenantChain::isWithin($account, $org),
            TenantChain::isWithin($account, $org),
            TenantChain::isWithin($account, $other),
            TenantChain::of($org, $tree)->tenants,
            TenantChain::of($account, $tree, false, true)->tenants,
        ]);

        self::assertEquals([[$account, $org], [$account, $org], true, true, false, [$org]], \array_slice($answers, 0, 6));
        self::assertSame(5, $tree->reads);

        TenantChain::of($account, $tree);
        TenantChain::isWithin($account, $org);

        self::assertSame(7, $tree->reads);

        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertTrue(TenantChain::isWithin($account, $org));
        self::assertEquals([$account, $org], TenantChain::of($account, $tree)->tenants);
        self::assertFalse(TenantChain::isWithin(null, $org));
        self::assertSame(9, $tree->reads);
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
