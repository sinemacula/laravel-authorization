<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Paging budget of access reviews over a large tenant (AUTHZ-11.6, N98): five
 * thousand holders granted roles of a deep hierarchy across fifty tenants, each
 * nested below the one before, are read a page at a time by keyset, each page
 * costing the same queries whatever its number, and streamed a chunk at a time
 * with the memory held bounded by the chunk, not by the tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AccessReview::class)]
final class AccessReviewPagingBudgetTest extends TestCase
{
    use ReviewsAccess;

    /** @var int How many holders the tenant has. */
    private const int HOLDERS = 5000;

    /** @var int How many tenants the holders are granted in. */
    private const int TENANTS = 50;

    /** @var int How deep the role hierarchy goes. */
    private const int DEPTH = 6;

    /** @var int How many rows a page or a chunk holds. */
    private const int PAGE = 250;

    /**
     * Every page of the holders of the top role and of the permission it
     * carries costs the same queries, from the first to the last, but for a
     * page whose rows begin in one source and end in the next, which reads
     * both; and the pages together list every holder once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryPageCostsTheSameQueries(): void
    {
        self::keyCursors();

        [$top, $permission] = $this->seedTheTenant();

        $scope = ReviewScope::rootedWithin(new Reference('tenant', 'root'), ApplicationSelector::any());

        foreach ([ReviewQuery::holders($top, $scope), ReviewQuery::holders($permission, $scope)] as $query) {
            $paged = self::pagedThrough($query, self::PAGE);
            $costs = \array_map(\count(...), $paged['queries']);

            self::assertCount(self::HOLDERS, $paged['rows']);
            self::assertCount(self::HOLDERS, \array_unique(\array_map(static fn ($row): string => $row->rowKey, $paged['rows'])));
            self::assertCount(\intdiv(self::HOLDERS, self::PAGE), $costs);
            self::assertLessThanOrEqual(1, \max($costs) - \min($costs), 'The pages cost other queries: ' . \implode(', ', $costs));
            self::assertSame($costs[1], \end($costs), 'The last page cost other queries than the second: ' . \implode(', ', $costs));
            self::assertFalse(self::readsByOffset($paged['queries']), 'A page was read at an offset.');
        }
    }

    /**
     * Streaming the holders a chunk at a time holds memory bounded by the
     * chunk: what is held after the last chunk is no more than after the first
     * few, whatever the tenant holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStreamHoldsMemoryBoundedByTheChunk(): void
    {
        [$top] = $this->seedTheTenant();

        DB::connection()->disableQueryLog();

        $query = ReviewQuery::holders($top, ReviewScope::everywhere());
        $read  = 0;
        $held  = [];

        foreach (self::reviews()->trustedStream($query, self::PAGE) as $row) {
            $read++;

            if ($read % self::PAGE === 0) {
                $held[] = \memory_get_usage();
            }

            unset($row);
        }

        self::assertSame(self::HOLDERS, $read);
        self::assertCount(\intdiv(self::HOLDERS, self::PAGE), $held);

        $settled = \array_slice($held, 2);

        self::assertLessThan(4 * 1024 * 1024, \max([0, ...$settled]) - \min([\PHP_INT_MAX, ...$settled]), 'The stream held more as it read more: ' . \implode(', ', $held));
    }

    /**
     * Seed fifty tenants below one root, each below the one before, a role
     * hierarchy six deep whose top role carries a permission, and five thousand
     * holders, each granted a role of the hierarchy in one of the tenants; and
     * return the top role and the permission.
     *
     * @return array{\SineMacula\Laravel\Authorization\Models\Role, \SineMacula\Laravel\Authorization\Models\Permission}
     *
     * @throws \Throwable
     */
    private function seedTheTenant(): array
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        $root = new Reference('tenant', 'root');

        ClosureTenantTree::add($root);

        $parent = $root;

        for ($tenant = 0; $tenant < self::TENANTS; $tenant++) {
            ClosureTenantTree::add($child = new Reference('tenant', 't' . $tenant), $parent);

            $parent = $child;
        }

        $roles = [Role::query()->create(['name' => 'level-0'])];

        for ($level = 1; $level < self::DEPTH; $level++) {
            $role = new Role;

            $role->forceFill(['name' => 'level-' . $level, 'parent_id' => $roles[$level - 1]->getKey()])->save();

            $roles[] = $role;
        }

        $permission = Permission::query()->create(['name' => 'posts:edit']);

        $roles[0]->givePermissionTo($permission);

        $now  = now()->utc()->format('Y-m-d H:i:s');
        $rows = [];

        for ($holder = 0; $holder < self::HOLDERS; $holder++) {
            $rows[] = [
                'role_id'           => $roles[$holder % self::DEPTH]->getKey(),
                'authorizable_type' => 'holder',
                'authorizable_id'   => \sprintf('h%05d', $holder),
                'tenant_type'       => 'tenant',
                'tenant_id'         => 't' . ($holder % self::TENANTS),
                'include_subtree'   => true,
                'created_at'        => $now,
                'updated_at'        => $now,
            ];
        }

        foreach (\array_chunk($rows, 500) as $chunk) {
            DB::table('authorizable_roles')->insert($chunk);
        }

        return [$roles[0], $permission];
    }

    /**
     * Determine whether any query of the pages reads at an offset.
     *
     * @param  list<list<string>>  $pages
     * @return bool
     */
    private static function readsByOffset(array $pages): bool
    {
        foreach ($pages as $page) {
            foreach ($page as $sql) {
                if (\preg_match('/\boffset\b/i', $sql) === 1) {
                    return true;
                }
            }
        }

        return false;
    }
}
