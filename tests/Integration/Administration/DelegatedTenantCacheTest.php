<?php

declare(strict_types = 1);

namespace Tests\Integration\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Cache\Invalidation;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Integration tests for delegated administration over a tenant tree with a
 * persistent resolution cache: a parent tenant's administrator granting or
 * revoking in its tenant changes the next request's checks in the parent and
 * every tenant below it, however warm their entries were.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Invalidation::class)]
final class DelegatedTenantCacheTest extends TestCase
{
    use ActsAsTenant;

    /**
     * Keep entries in the array store across requests.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config(['authorization.cache.store' => 'array']);
    }

    /**
     * A delegated grant in the parent tenant, and its revocation, each take
     * effect on the next request in the parent and in its child, over entries
     * each tenant had already stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentAdministratorsChangeReachesWarmChecksBelow(): void
    {
        [$parent, $child] = $this->tree();

        $user  = StubGrantee::query()->create(['id' => 'user']);
        $admin = $this->administrator($parent);

        self::assertSame([false, false], $this->checks($user, $parent, $child));
        self::assertSame([[false, false], 0], $this->warmChecks($user, $parent, $child));

        $this->actAsTenant($parent);
        self::grants()->grantPermission($user, 'posts:edit', actor: $admin, tenant: $parent);

        self::assertSame([true, true], $this->checks($user, $parent, $child));
        self::assertSame([[true, true], 0], $this->warmChecks($user, $parent, $child));

        $this->actAsTenant($parent);
        self::grants()->revokePermission($user, 'posts:edit', $admin, $parent);

        self::assertSame([false, false], $this->checks($user, $parent, $child));
    }

    /**
     * Return the checks in each tenant, as `checks()` makes them, with how many
     * queries they made of the grant tables.
     *
     * @param  \Tests\Feature\Stubs\StubGrantee  $user
     * @param  \Tests\Feature\Stubs\StubTenant  ...$tenants
     * @return array{list<bool>, int}
     */
    private function warmChecks(StubGrantee $user, StubTenant ...$tenants): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $allowed = $this->checks($user, ...$tenants);
        $reads   = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'authorizable_'));

        DB::disableQueryLog();

        return [$allowed, \count($reads)];
    }

    /**
     * Return whether the user may edit posts in each tenant, each checked on a
     * request of its own.
     *
     * @param  \Tests\Feature\Stubs\StubGrantee  $user
     * @param  \Tests\Feature\Stubs\StubTenant  ...$tenants
     * @return list<bool>
     */
    private function checks(StubGrantee $user, StubTenant ...$tenants): array
    {
        $allowed = [];

        foreach ($tenants as $tenant) {
            $this->actAsTenant($tenant);
            $this->app?->forgetInstance(ResolutionCache::class);

            $allowed[] = StubGrantee::query()->whereKey($user->getKey())->firstOrFail()->hasPermission('posts:edit');
        }

        return $allowed;
    }

    /**
     * Return the acting context of the most senior administrator, holding every
     * administration action and `posts:edit` in the tenant and below.
     *
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \Throwable
     */
    private function administrator(StubTenant $tenant): ActingContext
    {
        $admin = StubGrantee::query()->create(['id' => 'admin']);

        self::grants()->grantRole($admin, Role::query()->create(['name' => 'chief', 'rank' => 0]));

        foreach (['authorization:*', 'posts:edit'] as $name) {
            self::grants()->grantPermission($admin, Permission::query()->create(['name' => $name]), tenant: $tenant);
        }

        return ActingContext::for($admin);
    }

    /**
     * Bind a tenant tree of a parent and its child, and return both.
     *
     * @return array{\Tests\Feature\Stubs\StubTenant, \Tests\Feature\Stubs\StubTenant}
     */
    private function tree(): array
    {
        [$parent, $child] = \array_map(self::createTenant(...), ['parent', 'child']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        return [$parent, $child];
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }
}
