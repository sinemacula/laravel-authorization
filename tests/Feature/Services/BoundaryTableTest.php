<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\BoundaryTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\InterleavesWrites;
use Tests\TestCase;

/**
 * Feature tests for the writer of one grantee's permission boundary within one
 * scope, and the table's null-folding unique key and foreign key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BoundaryTable::class)]
final class BoundaryTableTest extends TestCase
{
    use InterleavesWrites;

    /**
     * A boundary is written once in its scope with its reach and its actor;
     * setting it again changes nothing, with another reach changes the reach
     * alone, and with another policy replaces it, naming the policy replaced.
     *
     * @return void
     */
    public function testSetsOnceThenChangesTheReachOrReplaces(): void
    {
        [$first, $second] = [self::policy('first'), self::policy('second')];

        $tenant = new Reference('stub_tenant', 'tenant-a');
        $set    = self::table($tenant, true, new Reference('admin', '1'))->set($first);

        self::assertSame(['admin', '1'], [DB::table('authorizable_boundaries')->value('granted_by_type'), DB::table('authorizable_boundaries')->value('granted_by_id')]);

        $outcomes = [
            $set,
            self::table($tenant, true)->set($first),
            self::table($tenant, false)->set($first),
            self::table($tenant, false)->set($second),
            self::table($tenant, false)->set($second),
        ];

        self::assertSame([
            [GrantOutcome::GRANTED, null],
            [GrantOutcome::UNCHANGED, null],
            [GrantOutcome::REACH_CHANGED, null],
            [GrantOutcome::REPLACED, $first],
            [GrantOutcome::UNCHANGED, null],
        ], $outcomes);

        $row = (array) DB::table('authorizable_boundaries')->sole();

        self::assertSame(['user', 'user-1', 'stub_tenant', 'tenant-a'], [$row['authorizable_type'], $row['authorizable_id'], $row['tenant_type'], $row['tenant_id']]);
        self::assertSame($second, (string) $row['policy_id']);
        self::assertFalse((bool) $row['include_subtree']);
        self::assertNull($row['granted_by_type']);
        self::assertNotNull($row['created_at']);
    }

    /**
     * The platform-wide boundary and a tenant's are apart, as are two
     * grantees'.
     *
     * @return void
     */
    public function testKeepsOneBoundaryPerGranteeAndScope(): void
    {
        $policy = self::policy('cap');

        self::table(null)->set($policy);
        self::table(new Reference('stub_tenant', 'tenant-a'))->set($policy);
        (new BoundaryTable(AuthorizationConnection::connection(), 'authorizable_boundaries', new Reference('user', 'user-2')))->set($policy);

        self::assertSame(3, DB::table('authorizable_boundaries')->count());
    }

    /**
     * A row a concurrent call removed between the ignored insert and the read
     * back is set afresh, once more, with the writer's policy, reach and actor.
     *
     * @return void
     */
    public function testSetsAfreshARowRemovedConcurrently(): void
    {
        [$first, $second] = [self::policy('first'), self::policy('second')];

        self::table(null)->set($first);

        $inserts = self::interleaveWrites('authorizable_boundaries', static function (): void {
            DB::table('authorizable_boundaries')->where('authorizable_id', 'user-1')->delete();
        }, static function (): void {});

        self::assertSame([GrantOutcome::GRANTED, null], self::table(null, false, new Reference('admin', '1'))->set($second));
        self::assertCount(2, $inserts);

        $row = (array) DB::table('authorizable_boundaries')->sole();

        self::assertSame([$second, false, 'admin', '1'], [(string) $row['policy_id'], (bool) $row['include_subtree'], $row['granted_by_type'], $row['granted_by_id']]);
    }

    /**
     * A write that leaves no row, even once tried again, reports nothing set,
     * as on MySQL a policy deleted at the same moment does when `INSERT IGNORE`
     * turns its foreign key failure into a warning.
     *
     * @return void
     */
    public function testReportsNothingWhenNoRowIsWritten(): void
    {
        [$first, $second] = [self::policy('first'), self::policy('second')];

        self::table(null)->set($first);

        $row     = (array) DB::table('authorizable_boundaries')->sole();
        $inserts = self::interleaveWrites('authorizable_boundaries', static function (): void {
            DB::table('authorizable_boundaries')->where('authorizable_id', 'user-1')->delete();
        }, static function () use ($row): void {
            DB::table('authorizable_boundaries')->insert($row);
        }, 2, 1);

        self::assertNull(self::table(null)->set($second));
        self::assertCount(2, $inserts);
        self::assertSame(0, DB::table('authorizable_boundaries')->where('policy_id', $second)->count());
    }

    /**
     * A removal reports the policy and the scope with the reach the boundary
     * had, and removes only the scope's; a platform-wide boundary always
     * reaches below; nothing there removes nothing.
     *
     * @return void
     */
    public function testRemoveReportsThePolicyAndTheReach(): void
    {
        $policy = self::policy('cap');
        $tenant = new Reference('stub_tenant', 'tenant-a');

        self::table($tenant, false)->set($policy);
        self::table(null, false)->set($policy);

        self::assertNull(self::table(new Reference('stub_tenant', 'tenant-b'))->remove());
        self::assertEquals([$policy, new GrantScope($tenant, null, false)], self::table($tenant)->remove());
        self::assertEquals([$policy, new GrantScope(null, null, true)], self::table(null)->remove());
        self::assertNull(self::table(null)->remove());
        self::assertSame(0, DB::table('authorizable_boundaries')->count());
    }

    /**
     * A boundary naming half a tenant, a key without a type or a type without a
     * key, is not the platform's: setting one at the platform writes a row
     * beside it, and removing it there leaves it as it is.
     *
     * @return void
     */
    public function testABoundaryNamingHalfATenantIsNotThePlatforms(): void
    {
        $policy = self::policy('cap');
        $row    = ['policy_id' => $policy, 'authorizable_type' => 'user', 'authorizable_id' => 'user-1', 'include_subtree' => true];

        DB::table('authorizable_boundaries')->insert([[...$row, 'tenant_type' => null, 'tenant_id' => 'tenant-a'], [...$row, 'tenant_type' => 'stub_tenant', 'tenant_id' => null]]);

        self::assertNull(self::table(null)->remove());
        self::assertSame([GrantOutcome::GRANTED, null], self::table(null)->set($policy));
        self::assertEquals([$policy, new GrantScope(null, null, true)], self::table(null)->remove());
        self::assertSame(2, DB::table('authorizable_boundaries')->count());
    }

    /**
     * A boundary naming half a tenant holds in no scope, so it is left out of
     * the boundaries read everywhere and read apart, by the same query, with
     * its tenant columns as stored; removing one removes it alone, as stored,
     * once, and removing everywhere removes them first, returning them apart.
     *
     * @return void
     */
    public function testBoundariesNamingHalfATenantAreReadAndRemovedApart(): void
    {
        $policy = self::policy('cap');
        $other  = self::policy('other');
        $row    = ['policy_id' => $policy, 'authorizable_type' => 'user', 'authorizable_id' => 'user-1', 'include_subtree' => true];
        $half   = [[...$row, 'tenant_type' => null, 'tenant_id' => 'tenant-a'], [...$row, 'tenant_type' => 'stub_tenant', 'tenant_id' => null]];

        DB::table('authorizable_boundaries')->insert($half);
        DB::table('authorizable_boundaries')->insert([...$row, 'authorizable_id' => 'user-2', 'tenant_type' => null, 'tenant_id' => 'tenant-a']);
        DB::table('authorizable_boundaries')->insert([...$row, 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        self::table(null)->set($policy);

        $malformed = [['policy_id' => $policy, 'tenant_type' => null, 'tenant_id' => 'tenant-a'], ['policy_id' => $policy, 'tenant_type' => 'stub_tenant', 'tenant_id' => null]];

        [$boundaries, $read] = self::table(null)->everywhere();

        $whole = [[$policy, new GrantScope(null, null, true)], [$policy, new GrantScope(new Reference('stub_tenant', 'tenant-a'), null, true)]];

        self::assertEqualsCanonicalizing($whole, $boundaries);
        self::assertEqualsCanonicalizing($malformed, $read);
        self::assertSame(0, self::table(null)->removeMalformed(['policy_id' => $other, 'tenant_type' => null, 'tenant_id' => 'tenant-a']));

        foreach ($malformed as $boundary) {
            self::assertSame(1, self::table(null)->removeMalformed($boundary));
            self::assertSame(0, self::table(null)->removeMalformed($boundary));
        }

        self::assertSame([], self::table(null)->everywhere()[1]);
        self::assertSame(3, DB::table('authorizable_boundaries')->count());

        DB::table('authorizable_boundaries')->insert($half);

        [$removed, $removedHalf] = self::table(null)->removeEverywhere();

        self::assertEqualsCanonicalizing($whole, $removed);
        self::assertEqualsCanonicalizing($malformed, $removedHalf);
        self::assertSame(['user-2'], DB::table('authorizable_boundaries')->pluck('authorizable_id')->all());
    }

    /**
     * Removing everywhere removes every scope's boundary of the grantee alone,
     * reporting each with its scope and its reach.
     *
     * @return void
     */
    public function testRemovesEverywhere(): void
    {
        $policy = self::policy('cap');
        $tenant = new Reference('stub_tenant', 'tenant-a');

        $reaching = new Reference('stub_tenant', 'tenant-b');

        self::table($tenant, false)->set($policy);
        self::table($reaching, true)->set($policy);
        self::table(null)->set($policy);
        (new BoundaryTable(AuthorizationConnection::connection(), 'authorizable_boundaries', new Reference('user', 'user-2')))->set($policy);

        [$removed, $malformed] = self::table(null)->removeEverywhere();

        self::assertSame([], $malformed);

        \usort($removed, static fn (array $left, array $right): int => \strcmp((string) $left[1]->tenant?->id, (string) $right[1]->tenant?->id));

        self::assertEquals([
            [$policy, new GrantScope(null, null, true)],
            [$policy, new GrantScope($tenant, null, false)],
            [$policy, new GrantScope($reaching, null, true)],
        ], $removed);
        self::assertSame(['user-2'], DB::table('authorizable_boundaries')->pluck('authorizable_id')->all());
        self::assertSame([[], []], self::table(null)->removeEverywhere());
    }

    /**
     * The unique key folds nulls, so a second platform-wide boundary for the
     * same grantee is refused even though its tenant columns are null.
     *
     * @return void
     */
    public function testTheUniqueKeyFoldsNulls(): void
    {
        $row = ['authorizable_type' => 'user', 'authorizable_id' => 'user-1', 'tenant_type' => null, 'tenant_id' => null];

        DB::table('authorizable_boundaries')->insert(['policy_id' => self::policy('first'), ...$row]);

        $this->expectException(QueryException::class);

        DB::table('authorizable_boundaries')->insert(['policy_id' => self::policy('second'), ...$row]);
    }

    /**
     * The foreign key refuses to delete a policy in use as a boundary from
     * under it, even past the model.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheForeignKeyKeepsABoundarysPolicy(): void
    {
        $policy = self::policy('cap');

        self::table(null)->set($policy);

        try {
            // Within a savepoint, so the refused statement leaves the test's
            // transaction usable on PostgreSQL.
            DB::transaction(static fn (): int => DB::table('policies')->where('id', $policy)->delete());
            self::fail('The policy was deleted from under its boundary.');
        } catch (QueryException) {
            // Expected.
        }

        self::assertSame(1, DB::table('policies')->where('id', $policy)->count());
    }

    /**
     * The boundary held in the scope, and those held in every scope, are read
     * without removing anything, so a removal can be decided first.
     *
     * @return void
     */
    public function testReadsTheBoundariesWithoutRemovingThem(): void
    {
        $policy = self::policy('cap');
        $tenant = new Reference('stub_tenant', 'tenant-a');

        self::assertNull(self::table($tenant)->held());
        self::assertSame([[], []], self::table(null)->everywhere());

        self::table($tenant, false)->set($policy);
        self::table(null)->set($policy);

        [$everywhere] = self::table(null)->everywhere();

        \usort($everywhere, static fn (array $left, array $right): int => \strcmp((string) $left[1]->tenant?->id, (string) $right[1]->tenant?->id));

        self::assertSame([$policy, false], self::table($tenant)->held());
        self::assertEquals([[$policy, new GrantScope(null, null, true)], [$policy, new GrantScope($tenant, null, false)]], $everywhere);
        self::assertSame(2, DB::table('authorizable_boundaries')->count());
    }

    /**
     * Return the writer of `user:user-1`'s boundary in the scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\Support\BoundaryTable
     */
    private static function table(?Reference $tenant, bool $includeSubtree = true, ?Reference $actor = null): BoundaryTable
    {
        return new BoundaryTable(AuthorizationConnection::connection(), 'authorizable_boundaries', new Reference('user', 'user-1'), $tenant, $includeSubtree, $actor);
    }

    /**
     * Create a policy and return its key.
     *
     * @param  string  $name
     * @return string
     */
    private static function policy(string $name): string
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => []]])->id;
    }
}
