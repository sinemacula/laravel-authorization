<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the version tokens a resolution pins as it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionPins::class)]
final class ResolutionPinsTest extends TestCase
{
    use ActsAsTenant;

    /**
     * The grantee, roles, policies, the versions role policies, resource
     * policies, boundaries and guardrails share and the tenants are pinned
     * under their own keys, in the order they were pinned.
     *
     * @return void
     */
    public function testPinsRecordEachKindUnderItsKey(): void
    {
        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $pins  = new ResolutionPins($store);

        $pins->grantee(new Reference('user', 'user-1'));
        $pins->roles(['role-1', 'role-2']);
        $pins->policies(['policy-1']);
        $pins->rolePolicies();
        $pins->resourcePolicies('posts');
        $pins->boundaries();
        $pins->guardrails();
        $pins->tenants(new TenantChain([new Reference('stub_tenant', 'account'), new Reference('stub_tenant', 'org')]));
        $pins->roles([]);

        self::assertSame([
            'authz:version:grantee:user:user-1',
            'authz:version:role:role-1',
            'authz:version:role:role-2',
            'authz:version:policy:policy-1',
            'authz:version:role-policies',
            'authz:version:resource-policies',
            'authz:version:resource-policies:posts',
            'authz:version:boundaries',
            'authz:version:guardrails',
            'authz:version:tenant:stub_tenant:account',
            'authz:version:tenant:stub_tenant:org',
        ], \array_keys($pins->tokens()));
        self::assertSame($store->tokens(\array_keys($pins->tokens())), $pins->tokens());
        self::assertTrue($pins->isComplete());
    }

    /**
     * Without a store nothing is pinned, and the pins stay complete.
     *
     * @return void
     */
    public function testWithoutAStoreNothingIsPinned(): void
    {
        $pins = new ResolutionPins;

        $pins->grantee(new Reference('user', 'user-1'));
        $pins->roles(['role-1']);
        $pins->policies(['policy-1']);
        $pins->rolePolicies();
        $pins->resourcePolicies('posts');
        $pins->boundaries();
        $pins->guardrails();
        $pins->tenants(new TenantChain([new Reference('stub_tenant', 'account')]));

        self::assertSame([], $pins->tokens());
        self::assertTrue($pins->isComplete());
    }

    /**
     * Pinning no roles asks the store nothing.
     *
     * @return void
     */
    public function testPinningNothingAsksTheStoreNothing(): void
    {
        $driver = new FailingCacheStore;
        $pins   = new ResolutionPins(new VersionedStore(new Repository($driver), 'authz'));

        $pins->roles([]);
        $pins->policies([]);
        $pins->tenants(new TenantChain);

        self::assertSame(0, $driver->calls);
        self::assertTrue($pins->isComplete());
    }

    /**
     * A pin the store cannot read leaves the pins incomplete, so the resolution
     * is not stored.
     *
     * @return void
     */
    public function testAFailedPinLeavesThePinsIncomplete(): void
    {
        $this->app?->instance('log', new RecordingLogger);

        $pins = new ResolutionPins(new VersionedStore(new Repository(new FailingCacheStore), 'authz'));

        $pins->roles(['role-1']);

        self::assertSame([], $pins->tokens());
        self::assertFalse($pins->isComplete());
    }

    /**
     * The current tenant's chain is pinned, and read again once pinned: with no
     * store it holds as read and pins nothing; with one it holds while the tree
     * is unchanged, and when the tenant moved meanwhile the new chain is pinned
     * too and it does not hold.
     *
     * @return void
     */
    public function testTheCurrentChainIsPinnedAndReadAgain(): void
    {
        [$account, $org, $sibling] = \array_map(self::createTenant(...), ['account', 'org', 'sibling']);
        $tree                      = (new StubTenantTree)->put(Reference::of($account), Reference::of($org));

        $this->app?->instance(TenantTree::class, $tree);
        $this->actAsTenant($account);

        $none = new ResolutionPins;

        self::assertTrue($none->isChainHeldOncePinned());
        self::assertSame([], $none->tokens());
        self::assertSame(1, $tree->reads);

        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $held  = new ResolutionPins($store);

        self::assertTrue($held->isChainHeldOncePinned());
        $key = static fn (StubTenant $tenant, string $id): string => 'authz:version:tenant:' . $tenant->getMorphClass() . ':' . $id;

        self::assertSame([$key($account, 'account'), $key($org, 'org')], \array_keys($held->tokens()));
        self::assertSame(2, $tree->reads);

        $tree->put(Reference::of($account), Reference::of($sibling));

        $moved = new ResolutionPins($store);

        self::assertFalse($moved->isChainHeldOncePinned());
        self::assertSame([$key($account, 'account'), $key($org, 'org'), $key($sibling, 'sibling')], \array_keys($moved->tokens()));
        self::assertEquals([Reference::of($account), Reference::of($sibling)], TenantScope::currentChain()->tenants);
    }

    /**
     * Pins keep no routes unless the cache tracks grant usage for the
     * resolution.
     *
     * @return void
     */
    public function testPinsRouteOnlyWhenAsked(): void
    {
        self::assertFalse((new ResolutionPins)->isRouting());
        self::assertTrue((new ResolutionPins(null, true))->isRouting());
    }
}
