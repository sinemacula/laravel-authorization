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
 * costing the same queries whatever its number and seeking to where it starts,
 * as the database measures the rows it reads, and streamed a chunk at a time
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

    /** @var int How many rows a page may read beyond those after its keyset: the one beyond its last, and the index entries it seeks by. */
    private const int SEEK = 6;

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
     * Each page of a role's direct holders seeks to where it starts, through
     * the index leading with the target and the grantee: it reads the role's
     * grants from its keyset on, never one before it, nor any other role's, so
     * each page reads fewer rows than the one before and the last little more
     * than a page, whatever the tenant holds. The rows read are measured by the
     * database itself, so a page that scans from the start, or the whole table,
     * fails however few queries it runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachPageReadsFromWhereItStarts(): void
    {
        $driver = DB::connection()->getDriverName();

        if ($driver !== 'pgsql' && $driver !== 'mysql') {
            self::markTestSkipped('The rows a page reads are measured on PostgreSQL and MySQL.');
        }

        self::keyCursors();

        [$top] = $this->seedTheTenant();

        DB::statement($driver === 'pgsql' ? 'analyze authorizable_roles' : 'analyze table authorizable_roles');

        $query = ReviewQuery::holders($top, ReviewScope::everywhere(), true);
        $held  = \intdiv(self::HOLDERS + self::DEPTH - 1, self::DEPTH);
        $reads = [];
        $rows  = 0;

        foreach (self::directReadsOf($query) as [$sql, $bindings, $count]) {
            $reads[] = self::rowsRead($driver, $sql, $bindings);
            $rows += $count;
        }

        $read = \implode(', ', $reads);

        self::assertSame($held, $rows);
        self::assertCount((int) \ceil($held / self::PAGE), $reads);
        // A page reads the rows it returns, the one beyond to know whether more
        // are left, and a few index entries to seek to its keyset.
        self::assertLessThanOrEqual(2 * self::PAGE + self::SEEK, \end($reads), "The last page read from before where it starts: {$read}.");

        foreach ($reads as $page => $count) {
            self::assertLessThanOrEqual($held - $page * self::PAGE + self::SEEK, $count, "Page {$page} read rows before where it starts: {$read}.");
        }
    }

    /**
     * Streaming the holders a chunk at a time reads nothing until the rows are
     * taken, then a page of the chunk at a time, and holds memory bounded by
     * the chunk: the most it holds above what was held before the stream began
     * stays within a few chunks' worth, whatever the tenant holds, so a stream
     * that read the whole review at once would fail.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStreamHoldsMemoryBoundedByTheChunk(): void
    {
        [$top] = $this->seedTheTenant();

        DB::connection()->disableQueryLog();

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $query = ReviewQuery::holders($top, ReviewScope::everywhere());

        \gc_collect_cycles();

        $baseline = \memory_get_usage();

        \memory_reset_peak_usage();

        $stream = self::reviews()->trustedStream($query, self::PAGE);

        self::assertSame(0, $queries, 'The stream read before its rows were taken.');

        $read = 0;

        foreach ($stream as $row) {
            $read++;

            unset($row);
        }

        $held = \memory_get_peak_usage() - $baseline;

        self::assertSame(self::HOLDERS, $read);
        self::assertGreaterThanOrEqual(\intdiv(self::HOLDERS, self::PAGE), $queries, 'The stream was not read a chunk at a time.');
        self::assertLessThan(8 * 1024 * 1024, $held, 'The stream held more than a few chunks at once: ' . $held . ' bytes.');
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
     * Read every page of the review as trusted work, a page of the page size at
     * a time, and return, for each, the query that read its direct grants, with
     * its bindings, and how many rows the page returned.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return list<array{string, array<array-key, mixed>, int}>
     *
     * @throws \Throwable
     */
    private static function directReadsOf(ReviewQuery $query): array
    {
        $connection = DB::connection();
        $reads      = [];
        $cursor     = null;

        $connection->enableQueryLog();

        do {
            $connection->flushQueryLog();

            $page   = self::reviews()->trustedPage($query, $cursor, self::PAGE);
            $cursor = $page->nextCursor;
            $direct = \array_values(\array_filter(
                $connection->getQueryLog(),
                static fn (array $logged): bool => \str_contains(\str_replace(['"', '`'], '', $logged['query']), 'authorizable_roles.role_id = ?'),
            ));

            self::assertCount(1, $direct, 'A page read its direct grants other than once.');

            $reads[] = [$direct[0]['query'], $direct[0]['bindings'], \count($page->rows)];
        } while ($cursor !== null);

        $connection->disableQueryLog();

        return $reads;
    }

    /**
     * Return how many rows the database reads to run the query with the
     * bindings: on PostgreSQL, the rows every scan of its plan read, those its
     * filters removed included; on MySQL, the index entries its handler read.
     *
     * @param  string  $driver
     * @param  string  $sql
     * @param  array<array-key, mixed>  $bindings
     * @return int
     *
     * @throws \JsonException
     */
    private static function rowsRead(string $driver, string $sql, array $bindings): int
    {
        if ($driver === 'pgsql') {
            $plan = ((array) DB::selectOne('explain (analyze, format json) ' . $sql, $bindings))['QUERY PLAN'] ?? null;

            /** @var list<array{Plan: array<string, mixed>}> $explained */
            $explained = \json_decode(\is_string($plan) ? $plan : '[]', true, 512, \JSON_THROW_ON_ERROR);

            return self::scanned($explained[0]['Plan']);
        }

        DB::statement('flush status');
        DB::select($sql, $bindings);

        $read     = 0;
        $handlers = '\'Handler_read_key\', \'Handler_read_next\', \'Handler_read_first\', \'Handler_read_rnd_next\'';

        foreach (DB::select("show session status where Variable_name in ({$handlers})") as $status) {
            $read += self::wholeNumber((array) $status, 'Value');
        }

        return $read;
    }

    /**
     * Return the rows the plan node and those below it read from the table, the
     * rows each filter or recheck removed included; a bitmap's index scan reads
     * no row itself, its heap scan reading them.
     *
     * @param  array<string, mixed>  $node
     * @return int
     */
    private static function scanned(array $node): int
    {
        $type  = \is_string($node['Node Type'] ?? null) ? $node['Node Type'] : '';
        $rows  = self::wholeNumber($node, 'Actual Rows') + self::wholeNumber($node, 'Rows Removed by Filter') + self::wholeNumber($node, 'Rows Removed by Index Recheck');
        $read  = \str_contains($type, 'Scan') && $type !== 'Bitmap Index Scan' ? $rows * \max(1, self::wholeNumber($node, 'Actual Loops')) : 0;
        $plans = \is_array($node['Plans'] ?? null) ? $node['Plans'] : [];

        foreach ($plans as $child) {
            $read += \is_array($child) ? self::scanned($child) : 0;
        }

        return $read;
    }

    /**
     * Return the whole number the field holds, or none for anything else.
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $name
     * @return int
     */
    private static function wholeNumber(array $fields, string $name): int
    {
        $value = $fields[$name] ?? null;

        return \is_int($value) || (\is_string($value) && \ctype_digit($value)) ? (int) $value : 0;
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
