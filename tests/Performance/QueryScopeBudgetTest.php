<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\ScopeAnchors;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\MeasuresTime;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\QueryScoping\GuardedPost;
use Tests\TestCase;

/**
 * Performance budget for compiling an authorized scope, which runs on every
 * query of a model carrying `AuthorizedScope` and twice for `paginate()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(QueryAuthorizer::class)]
#[CoversClass(ScopeAnchors::class)]
final class QueryScopeBudgetTest extends TestCase
{
    use MeasuresTime, ScopesQueries;

    /** @var string The tenant type of every tenant in the tree. */
    private const string TEAMS = 'teams';

    /** @var \Tests\Feature\Stubs\StubTenantTree The tenant tree every test grants across. */
    private StubTenantTree $tree;

    /**
     * Bind a tenant tree the package reads without a query.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->tree = new StubTenantTree;

        $this->app?->instance(TenantTree::class, $this->tree);
    }

    /**
     * Compiling the scope runs as many queries, for the same classes of rows,
     * when each team within the active one holds four times the grants, roles,
     * policies, denied records and grantless teams below it, and twelve teams
     * elsewhere carry grants, as with one of each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompilingRunsAFixedNumberOfQueriesAsTheGrantsGrow(): void
    {
        $this->grantAcross('small', within: 3, each: 1, elsewhere: 1);

        $small = $this->compileQueries(6);

        $this->grantAcross('large', within: 3, each: 4, elsewhere: 12);

        $large = $this->compileQueries(24);

        self::assertCount(\count($small), $large, "Compiling the scope grew with the grants:\n" . \implode("\n", $large));
    }

    /**
     * A query of the guarded model compiled at the limits, 64 anchors and 15
     * classes, runs in under five seconds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompilingAtTheAnchorAndScopeLimitsStaysWithinBudget(): void
    {
        $this->grantAcross('limits', within: 6, each: 1, elsewhere: 57);

        self::assertSame(12, GuardedPost::query()->count());

        $elapsed = $this->fastestOf(3, static function (): void {
            GuardedPost::query()->count();
        });

        $this->assertWithinBudget(5.0, $elapsed, "Compiling at the scoping limits exceeded its budget ({$elapsed}s).");
    }

    /**
     * Grant the user `posts:view` across teams below a root of its own, with
     * the given number of further permissions, roles and policies at each team
     * within, each with a post at the team, a post in a grantless team below
     * and a post an attached policy denies the view of, and a post at each team
     * elsewhere, which the root's queries leave out, and resolve the user in
     * its root.
     *
     * @param  string  $root
     * @param  int  $within
     * @param  int  $each
     * @param  int  $elsewhere
     * @return void
     *
     * @throws \Throwable
     */
    private function grantAcross(string $root, int $within, int $each, int $elsewhere): void
    {
        $tree = $this->tree;
        $view = Permission::query()->firstOrCreate(['name' => GuardedPost::ACTION]);
        $user = StubGrantee::create(['id' => $root]);
        $top  = new Reference(self::TEAMS, $root);
        $away = new Reference(self::TEAMS, "{$root}-away");

        $tree->put($top, null)->put($away, null);

        for ($i = 0; $i < $within; $i++) {
            $team = new Reference(self::TEAMS, "{$root}-in-{$i}");

            $tree->put($team, $top);
            $user->givePermission($view, null, $team);

            for ($k = 0; $k < $each; $k++) {
                $name = "{$root}-{$i}-{$k}";
                $role = Role::create(['name' => $name]);

                $below = new Reference(self::TEAMS, "{$name}-below");

                $role->permissions()->attach(Permission::create(['name' => "{$name}:view"])->getKey());
                $tree->put($below, $team);

                $user->givePermission(Permission::create(['name' => "{$name}:edit"]), null, $team);
                $user->assignRole($role, null, $team);
                $user->attachPolicy(self::storedPolicy($name, [['effect' => 'allow', 'actions' => ["{$name}:edit"]]]), null, $team);

                foreach ([$team, $below] as $tenant) {
                    GuardedPost::query()->withoutGlobalScopes()->create(['tenant_type' => self::TEAMS, 'tenant_id' => $tenant->id]);
                }

                $denied = GuardedPost::query()->withoutGlobalScopes()->create(['tenant_type' => self::TEAMS, 'tenant_id' => $team->id]);

                self::attachToResource($denied, [['effect' => 'deny', 'actions' => [GuardedPost::ACTION]]]);
            }
        }

        for ($i = 0; $i < $elsewhere; $i++) {
            $team = new Reference(self::TEAMS, "{$root}-away-{$i}");

            $tree->put($team, $away);
            $user->givePermission($view, null, $team);

            GuardedPost::query()->withoutGlobalScopes()->create(['tenant_type' => self::TEAMS, 'tenant_id' => $team->id]);
        }

        $this->resolveRequest($user, $top);
    }

    /**
     * Return the queries one count of the guarded model runs, with the
     * resolution cache and the schema cold, asserting the posts it counts.
     *
     * @param  int  $visible
     * @return list<string>
     */
    private function compileQueries(int $visible): array
    {
        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->forgetInstance(SchemaInspector::class);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame($visible, GuardedPost::query()->count());

        /** @var list<string> $queries */
        $queries = \array_column(DB::getQueryLog(), 'query');

        DB::disableQueryLog();

        return $queries;
    }
}
