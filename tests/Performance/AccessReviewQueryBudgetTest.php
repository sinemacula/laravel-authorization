<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewResult;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Query budget of the access reviews (AUTHZ-11.6): a review reads the roles it
 * involves in a fixed number of queries and the grants of all its holders
 * together, a page at a time, so its queries never grow with its holders, the
 * holders of a role through a deep hierarchy costing what one holder does; nor
 * with the tenants its grants are held in, nor with grants that reach no
 * attachment of the policy reviewed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AccessReview::class)]
final class AccessReviewQueryBudgetTest extends TestCase
{
    /** @var int How deep the role hierarchy goes. */
    private const int DEPTH = 6;

    /**
     * The holders of a permission, a role and a policy cost the same queries
     * for one holder as for forty, each holding through every role of a deep
     * hierarchy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHoldersCostTheSameWhateverTheHolders(): void
    {
        [$top, $permission, $policy] = $this->hierarchy();

        $scope = ReviewScope::appliesIn(new Reference('tenant', 'level-2'), ApplicationSelector::any());

        $queries = [ReviewQuery::holders($permission, $scope), ReviewQuery::holders($top, $scope), ReviewQuery::holders($policy, $scope)];

        $this->holders(1);

        $baselines = \array_map($this->queriesOf(...), $queries);

        $this->holders(40);

        foreach ($queries as $index => $query) {
            $measured = $this->queriesOf($query);

            self::assertSame([1, 40], [\count($baselines[$index]['rows']), \count($measured['rows'])]);
            self::assertCount(\count($baselines[$index]['queries']), $measured['queries'], "The review cost other queries:\n" . \implode("\n", $measured['queries']));
        }
    }

    /**
     * What a subject holds costs the same queries for one grant as for twenty,
     * and the expiring grants and an actor's grants the same for one row as for
     * forty.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHoldingsAndStoredRowsCostTheSameWhateverTheRows(): void
    {
        $this->hierarchy();

        $ann   = StubIdentity::query()->create(['id' => 'ann']);
        $query = ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere());

        self::grantsOf($ann, 1);

        $baseline = $this->queriesOf($query);

        self::grantsOf($ann, 20);

        self::assertCount(\count($baseline['queries']), $this->queriesOf($query)['queries']);

        $expiring = ReviewQuery::expiring(ReviewScope::rootedWithin(new Reference('tenant', 'level-1')), now()->subYear(), now()->addYears(2));

        $this->holders(1);

        $few = $this->queriesOf($expiring);

        $this->holders(40);

        self::assertCount(\count($few['queries']), $this->queriesOf($expiring)['queries']);
    }

    /**
     * The holders of a policy attached to a role at a tenant reaching below it
     * cost the same queries for one holder as for forty, each granted the role
     * in a tenant of its own below that tenant, in a review of everywhere and
     * one rooted within the tenant: the tree is asked once for the attachment,
     * never once for each tenant a grant is held in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPolicyHoldersCostTheSameWhateverTheTenantsTheyAreIn(): void
    {
        [$role, $policy] = $this->attachedAtTheRoot(true);

        $queries = [ReviewQuery::holders($policy, ReviewScope::everywhere()), ReviewQuery::holders($policy, ReviewScope::rootedWithin(new Reference('tenant', 'root')))];

        self::grantedInTenantsOfTheirOwn($role, 1, true);

        $baselines = \array_map($this->queriesOf(...), $queries);

        self::grantedInTenantsOfTheirOwn($role, 40, true);

        foreach ($queries as $index => $query) {
            $measured = $this->queriesOf($query);

            self::assertSame([1, 40], [\count($baselines[$index]['rows']), \count($measured['rows'])]);
            self::assertCount(\count($baselines[$index]['queries']), $measured['queries'], "The review cost other queries:\n" . \implode("\n", $measured['queries']));
        }
    }

    /**
     * Role grants that reach no attachment of a policy, held in another
     * application or in tenants the attachment does not meet, are never read:
     * the holders of the policy cost the same queries, and list no one, for two
     * such grants as for forty, however small the limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantsReachingNoAttachmentCostNothing(): void
    {
        [$role, $policy] = $this->attachedAtTheRoot(false);

        $elsewhere = Role::query()->create(['name' => 'elsewhere']);
        $web       = Policy::query()->create(['name' => 'web-only', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]);

        self::grants()->attachPolicy($elsewhere, $web, application: 'web');

        $queries = [
            ReviewQuery::holders($policy, ReviewScope::everywhere())->withLimit(1),
            ReviewQuery::holders($web, ReviewScope::appliesIn(null, ApplicationSelector::any()))->withLimit(1),
        ];

        self::grantedInTenantsOfTheirOwn($role, 2, false);
        self::grantedIn($elsewhere, 2, 'api');

        $baselines = \array_map($this->queriesOf(...), $queries);

        self::grantedInTenantsOfTheirOwn($role, 40, false);
        self::grantedIn($elsewhere, 40, 'api');

        foreach ($queries as $index => $query) {
            $measured = $this->queriesOf($query);

            self::assertSame([0, 0], [\count($baselines[$index]['rows']), \count($measured['rows'])]);
            self::assertCount(\count($baselines[$index]['queries']), $measured['queries'], "The review cost other queries:\n" . \implode("\n", $measured['queries']));
        }
    }

    /**
     * What a subject holds through a role whose policy is attached at a tenant
     * reaching below it costs the same queries for a grant of the role in one
     * tenant below it as in twenty.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHoldingsCostTheSameWhateverTheTenantsTheyAreIn(): void
    {
        [$role] = $this->attachedAtTheRoot(true);

        $ann     = StubIdentity::query()->create(['id' => 'ann']);
        $query   = ReviewQuery::holdings(new Subject($ann, $ann), ReviewScope::everywhere());
        $granted = 0;
        $grant   = static function (int $count) use ($ann, $role, &$granted): void {
            for (; $granted < $count; $granted++) {
                $tenant = new Reference('tenant', 'ann-' . $granted);

                ClosureTenantTree::add($tenant, new Reference('tenant', 'root'));

                self::grants()->grantRole($ann, $role, tenant: $tenant);
            }
        };

        $grant(1);

        $baseline = $this->queriesOf($query);

        $grant(20);

        $measured = $this->queriesOf($query);

        self::assertSame([2, 40], [\count($baseline['rows']), \count($measured['rows'])]);
        self::assertCount(\count($baseline['queries']), $measured['queries'], "The review cost other queries:\n" . \implode("\n", $measured['queries']));
    }

    /**
     * Put a root tenant in the closure-table tree, and a role with a deny-only
     * policy attached at the root, reaching below it when asked; return the
     * role and the policy.
     *
     * @param  bool  $isSubtree
     * @return array{\SineMacula\Laravel\Authorization\Models\Role, \SineMacula\Laravel\Authorization\Models\Policy}
     *
     * @throws \Throwable
     */
    private function attachedAtTheRoot(bool $isSubtree): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(new Reference('tenant', 'root'));

        $role   = Role::query()->create(['name' => 'carrier']);
        $policy = Policy::query()->create(['name' => 'deny-root', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]);

        self::grants()->attachPolicy($role, $policy, tenant: new Reference('tenant', 'root'), includeSubtree: $isSubtree);

        return [$role, $policy];
    }

    /**
     * Grant the role to more holders, until there are as many as given, each in
     * a tenant of its own below the root, reaching below it when asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  int  $count
     * @param  bool  $isSubtree
     * @return void
     *
     * @throws \Throwable
     */
    private static function grantedInTenantsOfTheirOwn(Role $role, int $count, bool $isSubtree): void
    {
        for ($index = StubIdentity::query()->where('id', 'like', 'tenanted-%')->count(); $index < $count; $index++) {
            $holder = StubIdentity::query()->create(['id' => 'tenanted-' . $index]);
            $tenant = new Reference('tenant', 'child-' . $index);

            ClosureTenantTree::add($tenant, new Reference('tenant', 'root'));

            self::grants()->grantRole($holder, $role, tenant: $tenant, includeSubtree: $isSubtree);
        }
    }

    /**
     * Grant the role to more holders, until there are as many as given, each at
     * the platform for the application.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  int  $count
     * @param  string  $application
     * @return void
     *
     * @throws \Throwable
     */
    private static function grantedIn(Role $role, int $count, string $application): void
    {
        for ($index = StubIdentity::query()->where('id', 'like', 'applied-%')->count(); $index < $count; $index++) {
            self::grants()->grantRole(StubIdentity::query()->create(['id' => 'applied-' . $index]), $role, application: $application);
        }
    }

    /**
     * Put a chain of tenants in the closure-table tree, and a chain of roles,
     * the top one carrying a permission and a deny-only policy; return the top
     * role, the permission and the policy.
     *
     * @return array{\SineMacula\Laravel\Authorization\Models\Role, \SineMacula\Laravel\Authorization\Models\Permission, \SineMacula\Laravel\Authorization\Models\Policy}
     *
     * @throws \Throwable
     */
    private function hierarchy(): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(new Reference('tenant', 'level-1'));
        ClosureTenantTree::add(new Reference('tenant', 'level-2'), new Reference('tenant', 'level-1'));

        $top        = Role::query()->create(['name' => 'level-0']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $policy     = Policy::query()->create(['name' => 'deny-delete', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]]);

        $top->givePermissionTo($permission);
        self::grants()->attachPolicy($top, $policy);

        $parent = $top;

        for ($level = 1; $level < self::DEPTH; $level++) {
            $role = new Role;

            $role->forceFill(['name' => 'level-' . $level, 'parent_id' => $parent->getKey()])->save();

            $parent = $role;
        }

        return [$top, $permission, $policy];
    }

    /**
     * Grant the bottom role to more holders, until there are as many as given,
     * each in the top tenant reaching below it, expiring in a year.
     *
     * @param  int  $count
     * @return void
     *
     * @throws \Throwable
     */
    private function holders(int $count): void
    {
        $bottom = Role::query()->where('name', 'level-' . (self::DEPTH - 1))->firstOrFail();

        for ($index = StubIdentity::query()->where('id', 'like', 'holder-%')->count(); $index < $count; $index++) {
            $holder = StubIdentity::query()->create(['id' => 'holder-' . $index]);

            self::grants()->grantRole($holder, $bottom, now()->addYear(), tenant: new Reference('tenant', 'level-1'));
        }
    }

    /**
     * Grant the grantee more roles and permissions, until it holds as many of
     * each as given.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @param  int  $count
     * @return void
     *
     * @throws \Throwable
     */
    private static function grantsOf(StubIdentity $grantee, int $count): void
    {
        for ($index = Role::query()->where('name', 'like', 'held-%')->count(); $index < $count; $index++) {
            $role = new Role;

            $role->forceFill(['name' => 'held-' . $index, 'parent_id' => Role::query()->where('name', 'level-0')->value('id')])->save();

            self::grants()->grantRole($grantee, $role);
            self::grants()->grantPermission($grantee, Permission::query()->create(['name' => 'held-' . $index . ':read']));
        }
    }

    /**
     * Run the review as trusted work, and return its rows with the queries it
     * ran.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return array{rows: list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>, queries: list<string>}
     */
    private function queriesOf(ReviewQuery $query): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $executed) use (&$queries): void {
            $queries[] = $executed->sql;
        });

        /** @var \SineMacula\Laravel\Authorization\Reviews\AccessReview $reviews */
        $reviews = app(AccessReview::class);
        $result  = $reviews->trusted($query);

        $this->app?->make('events')->forget(QueryExecuted::class);

        return ['rows' => self::rowsOf($result), 'queries' => $queries];
    }

    /**
     * Return the rows of the result.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewResult  $result
     * @return list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    private static function rowsOf(ReviewResult $result): array
    {
        return $result->rows;
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        $service = GrantService::instance();

        self::assertInstanceOf(GrantService::class, $service);

        return $service;
    }
}
