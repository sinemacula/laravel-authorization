<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantScopes;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\CatchesRefusals;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for where a grant is written: the owner's tenant, else the
 * tenant named, else platform-wide.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantScopes::class)]
final class GrantScopesTest extends TestCase
{
    use CatchesRefusals;

    /**
     * A tenant named as a model or a reference becomes its reference, and none
     * stays none.
     *
     * @return void
     */
    public function testATenantNamedBecomesItsReference(): void
    {
        $tenant    = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $reference = new Reference('organisation', 'org-a');

        self::assertEquals(new Reference($tenant->getMorphClass(), 'tenant-a'), GrantScopes::named($tenant));
        self::assertSame($reference, GrantScopes::named($reference));
        self::assertNull(GrantScopes::named(null));
    }

    /**
     * A call names its tenant as a reference, with its reach and application,
     * the reach kept as given even with no tenant.
     *
     * @return void
     */
    public function testACallNamesItsScope(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);

        self::assertEquals(new GrantScope(new Reference($tenant->getMorphClass(), 'tenant-a'), 'admin', false), GrantScopes::ofCall($tenant, false, 'admin'));
        self::assertEquals(new GrantScope(null, null, false), GrantScopes::ofCall(null, false, null));
        self::assertEquals(new GrantScope, GrantScopes::ofCall(null, true, null));
    }

    /**
     * A grant in a tenant is written with the reach given, and a platform-wide
     * grant always reaches below.
     *
     * @return void
     */
    public function testAPlatformGrantIsWrittenReachingBelow(): void
    {
        $tenant = new Reference('stub_tenant', 'tenant-a');

        self::assertEquals(new GrantScope($tenant, 'admin', false), GrantScopes::written($tenant, false, 'admin'));
        self::assertEquals(new GrantScope($tenant), GrantScopes::written($tenant, true, null));
        self::assertEquals(new GrantScope(null, 'admin'), GrantScopes::written(null, false, 'admin'));
    }

    /**
     * Each key takes the scope it is listed with, once however often it is
     * listed with the same reach, and a key listed with both reaches is
     * refused, naming the kind and the key.
     *
     * @return void
     */
    public function testAKeyListedWithBothReachesIsRefused(): void
    {
        $narrow = new GrantScope(new Reference('stub_tenant', 'tenant-a'), null, false);
        $wide   = new GrantScope(new Reference('stub_tenant', 'tenant-a'));

        self::assertSame(['a' => $narrow, 'b' => $wide], GrantScopes::byKey(GrantTarget::ROLE, [['a', $narrow], ['b', $wide], ['a', $narrow]]));
        self::assertSame([], GrantScopes::byKey(GrantTarget::ROLE, []));

        foreach ([[['a', $wide], ['a', $narrow]], [['a', $narrow], ['b', $wide], ['a', $wide]]] as $listed) {
            $refusal = self::refusalOf(static fn (): array => GrantScopes::byKey(GrantTarget::PERMISSION, $listed));

            self::assertInstanceOf(\InvalidArgumentException::class, $refusal);
            self::assertSame('The permission [a] is listed with both reaches.', $refusal->getMessage());
        }
    }

    /**
     * The owner's tenant fixes the scope, a platform target takes the tenant
     * named or none, and naming another tenant for an owned target is refused.
     *
     * @return void
     */
    public function testTheOwnerFixesTheScope(): void
    {
        $owner    = new Reference('stub_tenant', 'tenant-a');
        $owned    = self::role('editor', $owner);
        $platform = self::role('viewer');

        self::assertEquals($owner, GrantScopes::of(GrantTarget::ROLE, $owned, null));
        self::assertEquals($owner, GrantScopes::of(GrantTarget::ROLE, $owned, $owner));
        self::assertNull(GrantScopes::of(GrantTarget::ROLE, $platform, null));
        self::assertSame($owner, GrantScopes::of(GrantTarget::ROLE, $platform, $owner));

        $this->expectException(GrantScopeMismatchException::class);

        GrantScopes::of(GrantTarget::ROLE, $owned, new Reference('stub_tenant', 'tenant-b'));
    }

    /**
     * A sync's scope is the tenant that owns every target, else the platform:
     * when any target is the platform's, the owners differ, or there is none.
     *
     * @return void
     */
    public function testASyncTakesTheTenantEveryTargetShares(): void
    {
        $tenantA = new Reference('stub_tenant', 'tenant-a');
        $first   = self::role('first', $tenantA);
        $second  = self::role('second', $tenantA);

        self::assertEquals($tenantA, GrantScopes::commonOwner(GrantTarget::ROLE, null, [$first, $second]));
        self::assertNull(GrantScopes::commonOwner(GrantTarget::ROLE, null, [$first, self::role('platform')]));
        self::assertNull(GrantScopes::commonOwner(GrantTarget::ROLE, null, [self::role('platform-2'), $first]));
        self::assertNull(GrantScopes::commonOwner(GrantTarget::ROLE, null, [$first, self::role('other', new Reference('stub_tenant', 'tenant-b'))]));
        self::assertNull(GrantScopes::commonOwner(GrantTarget::ROLE, null, [$first, self::role('same-id', new Reference('other_type', 'tenant-a'))]));
        self::assertNull(GrantScopes::commonOwner(GrantTarget::ROLE, null, []));
    }

    /**
     * An owned target is grantable only in its own tenant; a platform one in
     * any scope.
     *
     * @return void
     */
    public function testAnOwnedTargetIsGrantableOnlyInItsTenant(): void
    {
        $owner = new Reference('stub_tenant', 'tenant-a');

        GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('platform'), null);
        GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('platform-2'), $owner);
        GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('owned', $owner), new Reference('stub_tenant', 'tenant-a'));

        try {
            GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('owned-2', $owner), null);
            self::fail('An owned role was grantable platform-wide.');
        } catch (GrantScopeMismatchException $exception) {
            self::assertNull($exception->getScope());
            self::assertSame('owned-2', $exception->getName());
        }
    }

    /**
     * A target naming half a tenant, a key without a type or a type without a
     * key, is grantable nowhere, at the platform or in any tenant, nor its
     * owner's scope taken as the platform, naming the column it lacks.
     *
     * @return void
     */
    public function testATargetNamingHalfATenantIsGrantableNowhere(): void
    {
        $tenant = new Reference('stub_tenant', 'tenant-a');
        $halves = [
            'tenant_type' => new Policy(['name' => 'no-type', 'tenant_id' => 'tenant-a']),
            'tenant_id'   => new Policy(['name' => 'no-key', 'tenant_type' => 'stub_tenant']),
        ];

        foreach ($halves as $missing => $policy) {
            $refusals = [
                self::refusalOf(static fn () => GrantScopes::assertGrantableIn(GrantTarget::POLICY, $policy, null)),
                self::refusalOf(static fn () => GrantScopes::assertGrantableIn(GrantTarget::POLICY, $policy, $tenant)),
                self::refusalOf(static fn (): ?Reference => GrantScopes::of(GrantTarget::POLICY, $policy, null)),
            ];

            foreach ($refusals as $refusal) {
                self::assertInstanceOf(InvalidTenantColumnsException::class, $refusal);
                self::assertSame((new InvalidTenantColumnsException('policy', $missing, 'grant'))->getMessage(), $refusal->getMessage());
                self::assertStringStartsWith("Cannot grant policy with inconsistent tenant columns — '{$missing}' is required", $refusal->getMessage());
            }
        }
    }

    /**
     * An owned target is grantable in the tenants below its owner in the bound
     * tree, and not in a tenant beside it.
     *
     * @return void
     */
    public function testAnOwnedTargetIsGrantableBelowItsTenant(): void
    {
        $org     = new Reference('stub_tenant', 'org');
        $account = new Reference('stub_tenant', 'account');
        $sibling = new Reference('stub_tenant', 'sibling');

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($account, $org));

        GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('owned', $org), $account);

        try {
            GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('owned-2', $account), $org);
            self::fail('A role was grantable above its tenant.');
        } catch (GrantScopeMismatchException $exception) {
            self::assertEquals($org, $exception->getScope());
        }

        $this->expectException(GrantScopeMismatchException::class);

        GrantScopes::assertGrantableIn(GrantTarget::ROLE, self::role('owned-3', $org), $sibling);
    }

    /**
     * Create a saved role, owned by the tenant given or the platform.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $owner
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name, ?Reference $owner = null): Role
    {
        return Role::query()->create(['name' => $name, 'tenant_type' => $owner?->type, 'tenant_id' => $owner?->id]);
    }
}
