<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\GrantReach;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `GrantReach`, the tenants a delegated grant reaches, put
 * into the query that reads what applies there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantReach::class)]
final class GrantReachTest extends TestCase
{
    /**
     * A platform-wide grant reaches every tenant, so the query is left alone.
     *
     * @return void
     */
    public function testAPlatformWideGrantReachesEveryTenant(): void
    {
        $this->rows(['tenant' => ['parent', 'child', 'other'], 'team' => ['parent']]);

        self::assertSame(['', 'team:parent', 'tenant:child', 'tenant:other', 'tenant:parent'], self::reached(GrantScope::platform()));
    }

    /**
     * A grant in a tenant reaches the platform, the tenant and its ancestors,
     * and, when it reaches below its tenant, every tenant the tree's subtree
     * query selects below it; never another tenant, nor one of another type
     * with the same key.
     *
     * @return void
     */
    public function testATenantGrantReachesItsChainAndItsSubtree(): void
    {
        [$top, $parent, $child] = [new Reference('tenant', 'top'), new Reference('tenant', 'parent'), new Reference('tenant', 'child')];

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($parent, $top)->put($child, $parent));
        $this->rows(['tenant' => ['top', 'parent', 'child', 'other'], 'team' => ['parent']]);

        self::assertSame(['', 'tenant:parent', 'tenant:top'], self::reached(new GrantScope($parent, null, false)));
        self::assertSame(['', 'tenant:child', 'tenant:parent', 'tenant:top'], self::reached(new GrantScope($parent)));
        self::assertSame(['', 'team:parent'], self::reached(new GrantScope(new Reference('team', 'parent'))));
    }

    /**
     * With a flat tree, a grant reaching below its tenant reaches the tenant
     * alone, and the subtree query is never run.
     *
     * @return void
     */
    public function testAFlatTreeReachesTheTenantAlone(): void
    {
        $this->app?->instance(TenantTree::class, new FlatTenantTree);
        $this->rows(['tenant' => ['parent', 'child']]);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $reach = GrantReach::of(new GrantScope(new Reference('tenant', 'parent')));

        self::assertSame([], DB::getQueryLog());
        self::assertSame(['', 'tenant:parent'], self::through($reach));
    }

    /**
     * A subtree given as an Eloquent query is read through its base query.
     *
     * @return void
     */
    public function testAnEloquentSubtreeIsRead(): void
    {
        $subtree = static fn (): Builder => StubTenant::query()->selectRaw('\'tenant\' as tenant_type, id as tenant_id')->where('id', '!=', 'other');

        $this->app?->instance(TenantTree::class, self::tree($subtree));

        StubTenant::query()->create(['id' => 'child', 'name' => 'child']);
        StubTenant::query()->create(['id' => 'other', 'name' => 'other']);

        $this->rows(['tenant' => ['parent', 'child', 'other']]);

        self::assertSame(['', 'tenant:child', 'tenant:parent'], self::reached(new GrantScope(new Reference('tenant', 'parent'))));
    }

    /**
     * A subtree that is no query cannot be read, so the reach throws rather
     * than guess.
     *
     * @return void
     */
    public function testASubtreeThatIsNoQueryThrows(): void
    {
        $this->app?->instance(TenantTree::class, self::tree(static fn (): Builder => new class implements Builder {}));

        $this->expectException(\UnexpectedValueException::class);

        GrantReach::of(new GrantScope(new Reference('tenant', 'parent')));
    }

    /**
     * Return a tree with no ancestors whose subtree query the callback builds.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Reference): \Illuminate\Contracts\Database\Query\Builder  $subtree
     * @return \SineMacula\Laravel\Authorization\Contracts\TenantTree
     */
    private static function tree(\Closure $subtree): TenantTree
    {
        return new readonly class ($subtree) implements TenantTree {
            /**
             * Create the tree.
             *
             * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Reference): \Illuminate\Contracts\Database\Query\Builder  $subtree
             */
            public function __construct(

                /** Builds the subtree query of a tenant. */
                private \Closure $subtree,
            ) {}

            /**
             * Return no ancestors.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
             */
            #[\Override]
            public function ancestors(Reference $tenant): array
            {
                return [];
            }

            /**
             * Determine whether the tenant is the ancestor.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
             * @return bool
             */
            #[\Override]
            public function isWithin(Reference $tenant, Reference $ancestor): bool
            {
                return $tenant->id === $ancestor->id;
            }

            /**
             * Return the subtree query the callback builds.
             *
             * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
             * @return \Illuminate\Contracts\Database\Query\Builder
             */
            #[\Override]
            public function subtree(Reference $tenant): Builder
            {
                return ($this->subtree)($tenant);
            }
        };
    }

    /**
     * Store a guardrail row platform-wide and one in each tenant, keyed by its
     * type.
     *
     * @param  array<string, list<string>>  $tenants
     * @return void
     */
    private function rows(array $tenants): void
    {
        $rows = [[null, null]];

        foreach ($tenants as $type => $ids) {
            foreach ($ids as $id) {
                $rows[] = [$type, $id];
            }
        }

        foreach ($rows as [$type, $id]) {
            $policy = Policy::create(['name' => 'rail-' . $type . '-' . $id, 'document' => ['statements' => []]]);

            DB::table('guardrails')->insert(['policy_id' => $policy->id, 'tenant_type' => $type, 'tenant_id' => $id, 'created_at' => now(), 'updated_at' => now()]);
        }
    }

    /**
     * Return the tenants of the guardrail rows the reach of a grant in the
     * scope keeps, sorted, `''` for the platform's.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return list<string>
     */
    private static function reached(GrantScope $scope): array
    {
        return self::through(GrantReach::of($scope));
    }

    /**
     * Return the tenants of the guardrail rows the reach keeps, sorted, `''`
     * for the platform's.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\GrantReach  $reach
     * @return list<string>
     */
    private static function through(GrantReach $reach): array
    {
        $kept = [];

        foreach ($reach->constrain(DB::table('guardrails'), 'guardrails')->get(['tenant_type', 'tenant_id']) as $row) {
            /** @var array{tenant_type: string|null, tenant_id: string|null} $columns */
            $columns = (array) $row;
            $kept[]  = $columns['tenant_type'] === null ? '' : $columns['tenant_type'] . ':' . $columns['tenant_id'];
        }

        \sort($kept);

        return $kept;
    }
}
