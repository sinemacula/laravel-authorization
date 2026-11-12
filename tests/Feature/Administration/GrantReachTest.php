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
use SineMacula\Laravel\Authorization\Support\TenantColumns;
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
     * A row naming half a tenant, a key without a type or a type without a key,
     * is neither the platform's nor in any tenant of a reach, so a reach keeps
     * it only when it reaches every tenant and leaves the query alone.
     *
     * @return void
     */
    public function testARowNamingHalfATenantIsInNoReach(): void
    {
        [$top, $parent, $child] = [new Reference('tenant', 'top'), new Reference('tenant', 'parent'), new Reference('tenant', 'child')];

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($parent, $top)->put($child, $parent));
        $this->rows(['tenant' => ['top', 'parent', 'child']]);

        DB::table('guardrails')->where('tenant_id', 'parent')->update(['tenant_type' => null]);
        DB::table('guardrails')->where('tenant_id', 'child')->update(['tenant_id' => null]);

        self::assertSame(['', 'tenant:top'], self::reached(new GrantScope($parent)));
        self::assertSame(['', 'tenant:top'], self::reached(new GrantScope($child)));
        self::assertSame(['', '-:parent', 'tenant:-', 'tenant:top'], self::reached(GrantScope::platform()));
    }

    /**
     * The rows a callback says hold everywhere are kept in any reach besides
     * those it reaches, as what restricts naming half a tenant is; a reach of
     * every tenant leaves the query alone and never asks.
     *
     * @return void
     */
    public function testTheRowsHoldingEverywhereAreKeptInAnyReach(): void
    {
        [$top, $parent, $child] = [new Reference('tenant', 'top'), new Reference('tenant', 'parent'), new Reference('tenant', 'child')];

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($parent, $top)->put($child, $parent));
        $this->rows(['tenant' => ['top', 'parent', 'child', 'other']]);

        DB::table('guardrails')->where('tenant_id', 'parent')->update(['tenant_type' => null]);
        DB::table('guardrails')->where('tenant_id', 'child')->update(['tenant_id' => null]);

        $asked      = [];
        $everywhere = static function (Builder $query, string $table) use (&$asked): Builder {
            $asked[] = $table;

            return TenantColumns::whereHalf($query, $table . '.tenant_type', $table . '.tenant_id');
        };
        $kept = static fn (GrantScope $scope): array => self::through(GrantReach::of($scope), $everywhere);

        self::assertSame(['', '-:parent', 'tenant:-', 'tenant:top'], $kept(new GrantScope($top, null, false)));
        self::assertSame(['guardrails'], $asked);
        self::assertSame(['', '-:parent', 'tenant:-', 'tenant:other', 'tenant:top'], $kept(GrantScope::platform()));
        self::assertSame(['guardrails'], $asked);
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
     * A subtree row whose tenant's type and key are integers is read as their
     * string forms, as the grant tables store them.
     *
     * @return void
     */
    public function testAnIntegerTypeAndKeyInASubtreeRowAreReadAsTheirStrings(): void
    {
        $this->app?->instance(TenantTree::class, self::tree(static fn (): Builder => DB::query()->selectRaw('7 as tenant_type, 5 as tenant_id')));
        $this->rows(['7' => ['parent', '5', '6'], 'tenant' => ['5']]);

        self::assertSame(['', '7:5', '7:parent'], self::reached(new GrantScope(new Reference('7', 'parent'))));
    }

    /**
     * A subtree row without its tenant's type or key, or with either null, is
     * refused, naming the tree, rather than read as a tenant of a type guessed
     * or with no key.
     *
     * @return void
     */
    public function testASubtreeRowWithoutItsTypeOrKeyIsRefused(): void
    {
        $subtrees = [
            static fn (): Builder => DB::query()->selectRaw('\'child\' as tenant_id'),
            static fn (): Builder => DB::query()->selectRaw('\'tenant\' as tenant_type'),
            static fn (): Builder => DB::query()->selectRaw('null as tenant_type, \'child\' as tenant_id'),
            static fn (): Builder => DB::query()->selectRaw('\'tenant\' as tenant_type, null as tenant_id'),
        ];

        foreach ($subtrees as $subtree) {
            $tree = self::tree($subtree);

            $this->app?->instance(TenantTree::class, $tree);

            try {
                GrantReach::of(new GrantScope(new Reference('tenant', 'parent')));

                self::fail('A subtree row without its type or key was read.');
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('The subtree of the tenant tree ' . $tree::class . ' returned a row without both a tenant_type and a tenant_id: '
                    . 'a subtree must select both columns, typed, for every tenant.', $exception->getMessage());
            }
        }
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
     * @param  array<array-key, list<string>>  $tenants
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
     * Return the tenants of the guardrail rows the reach keeps, with those the
     * callback says hold everywhere, sorted, `''` for the platform's and `-`
     * for a missing half of a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\GrantReach  $reach
     * @param  (\Closure(\Illuminate\Contracts\Database\Query\Builder, string): mixed)|null  $everywhere
     * @return list<string>
     */
    private static function through(GrantReach $reach, ?\Closure $everywhere = null): array
    {
        $kept = [];

        foreach ($reach->constrain(DB::table('guardrails'), 'guardrails', $everywhere)->get(['tenant_type', 'tenant_id']) as $row) {
            /** @var array{tenant_type: string|null, tenant_id: string|null} $columns */
            $columns = (array) $row;
            $isNone  = $columns['tenant_type'] === null && $columns['tenant_id'] === null;
            $kept[]  = $isNone ? '' : ($columns['tenant_type'] ?? '-') . ':' . ($columns['tenant_id'] ?? '-');
        }

        \sort($kept);

        return $kept;
    }
}
