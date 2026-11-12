<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleExclusionService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Query budget of the conflict report of mutually exclusive roles (AUTHZ-11.8,
 * N135): the roles below the pair are read in a fixed number of queries, the
 * grants of all of them together, and the tree is asked about every pair of
 * tenants the holders' grants weigh together, a chunk at a time, so the count
 * is the same for two holders as for forty, wherever they are granted and
 * whatever the depth of the hierarchy, and the report of every pair costs no
 * more queries for one pair than for several.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleExclusionService::class)]
final class RoleExclusionQueryBudgetTest extends TestCase
{
    /**
     * The report of one pair costs the same queries for two holders as for
     * forty, each holding both roles, one through a chain of parent roles, in a
     * tenant and below its parent in the closure-table tree.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportCostIsIndependentOfItsHolders(): void
    {
        [$clerk, $auditor, $acting] = $this->roles();

        $this->holders(1, 2, $acting, $auditor);

        $few = self::queriesOf(static fn (): ConflictReport => self::service()->conflicts($clerk, $auditor));

        self::assertCount(2, $few['answer']->holders());

        $this->holders(3, 40, $acting, $auditor);

        $many = self::queriesOf(static fn (): ConflictReport => self::service()->conflicts($clerk, $auditor));

        self::assertCount(40, $many['answer']->holders());
        self::assertCount(\count($few['queries']), $many['queries'], "The report cost other queries:\n" . \implode("\n", $many['queries']));
        self::assertLessThanOrEqual(6, \count($many['queries']));
    }

    /**
     * The report of one pair costs the same queries for two holders as for
     * forty when each holder is granted in tenants of its own, one reaching
     * below its parent tenant and one in the child, the tree asked about every
     * pair of tenants together.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportCostIsIndependentOfItsHoldersTenants(): void
    {
        [$clerk, $auditor, $acting] = $this->roles();

        $this->spread(1, 2, $acting, $auditor);

        $few = self::queriesOf(static fn (): ConflictReport => self::service()->conflicts($clerk, $auditor));

        self::assertCount(2, $few['answer']->holders());

        $this->spread(3, 40, $acting, $auditor);

        $many = self::queriesOf(static fn (): ConflictReport => self::service()->conflicts($clerk, $auditor));

        self::assertCount(40, $many['answer']->holders());
        self::assertCount(\count($few['queries']), $many['queries'], "The report cost other queries:\n" . \implode("\n", $many['queries']));
    }

    /**
     * The report of every declared pair costs the same queries for one pair as
     * for three, the holdings of every role of every pair read together.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportOfEveryPairIsReadTogether(): void
    {
        [$clerk, $auditor, $acting] = $this->roles();

        self::service()->declare($clerk, $auditor);

        $this->holders(1, 5, $acting, $auditor);

        $one = self::queriesOf(static fn (): array => self::service()->conflictsForAll());

        $payer  = Role::query()->create(['name' => 'payer']);
        $keeper = Role::query()->create(['name' => 'keeper']);

        self::service()->declare($payer, $keeper);
        self::service()->declare($auditor, $payer);

        $this->holders(6, 10, $acting, $auditor);

        $three = self::queriesOf(static fn (): array => self::service()->conflictsForAll());

        self::assertCount(1, $one['answer']);
        self::assertCount(5, $one['answer'][0]->holders());
        self::assertCount(3, $three['answer']);
        self::assertCount(\count($one['queries']), $three['queries'], "The reports cost other queries:\n" . \implode("\n", $three['queries']));
    }

    /**
     * Bind the closure-table tree, with a tenant below its parent, and the
     * directory, then return the pair's roles, `clerk` and `auditor`, and
     * `acting`, below `clerk` through a chain of parent roles.
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role, 2: \SineMacula\Laravel\Authorization\Models\Role}
     */
    private function roles(): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);
        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory);

        ClosureTenantTree::add(new Reference('org', 'parent'));
        ClosureTenantTree::add(new Reference('org', 'child'), new Reference('org', 'parent'));

        $clerk  = Role::query()->create(['name' => 'clerk']);
        $parent = $clerk;

        foreach (\range(1, 5) as $depth) {
            $parent = Role::query()->create(['name' => 'deputy-' . $depth, 'parent_id' => $parent->id]);
        }

        return [$clerk, Role::query()->create(['name' => 'auditor']), $parent];
    }

    /**
     * Create the holders numbered from and to, each granted the first role at
     * the parent tenant, reaching below it, and the second in the child.
     *
     * @param  int  $from
     * @param  int  $to
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $first
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $second
     * @return void
     *
     * @throws \Throwable
     */
    private function holders(int $from, int $to, Role $first, Role $second): void
    {
        foreach (\range($from, $to) as $number) {
            $holder = StubIdentity::query()->create(['id' => 'holder-' . $number]);

            app(GrantService::class)->grantRole($holder, $first, tenant: new Reference('org', 'parent'));
            app(GrantService::class)->grantRole($holder, $second, tenant: new Reference('org', 'child'));
        }
    }

    /**
     * Create the holders numbered from and to, each granted the first role at a
     * parent tenant of its own, reaching below it, and the second in that
     * tenant's child.
     *
     * @param  int  $from
     * @param  int  $to
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $first
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $second
     * @return void
     *
     * @throws \Throwable
     */
    private function spread(int $from, int $to, Role $first, Role $second): void
    {
        foreach (\range($from, $to) as $number) {
            [$parent, $child] = [new Reference('org', 'parent-' . $number), new Reference('org', 'child-' . $number)];

            ClosureTenantTree::add($parent);
            ClosureTenantTree::add($child, $parent);

            $holder = StubIdentity::query()->create(['id' => 'holder-' . $number]);

            app(GrantService::class)->grantRole($holder, $first, tenant: $parent);
            app(GrantService::class)->grantRole($holder, $second, tenant: $child);
        }
    }

    /**
     * Return the answer of the read and the queries it ran.
     *
     * @template TAnswer
     *
     * @param  \Closure(): TAnswer  $read
     * @return array{answer: TAnswer, queries: list<string>}
     */
    private static function queriesOf(\Closure $read): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $answer = $read();

        return ['answer' => $answer, 'queries' => $queries];
    }

    /**
     * Return the role exclusion service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleExclusionService
     */
    private static function service(): RoleExclusionService
    {
        return app(RoleExclusionService::class);
    }
}
