<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\ResourcePolicyTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\InterleavesWrites;
use Tests\TestCase;

/**
 * Feature tests for the writer of one resource's policy attachments within one
 * scope, and the table's null-folding unique key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourcePolicyTable::class)]
final class ResourcePolicyTableTest extends TestCase
{
    use InterleavesWrites;

    /**
     * An attachment is written once in its scope with its reach; attaching it
     * again changes nothing, and with another reach changes the reach alone.
     *
     * @return void
     */
    public function testAttachesOnceAndChangesOnlyTheReach(): void
    {
        $policy = self::policy();
        $scope  = new GrantScope(new Reference('stub_tenant', 'tenant-a'), 'admin');

        $narrow   = new GrantScope($scope->tenant, 'admin', false);
        $outcomes = [
            self::table('7', $scope)->attach($policy),
            self::table('7', $scope)->attach($policy),
            self::table('7', $narrow)->attach($policy),
            self::table('7', $narrow)->attach($policy),
        ];

        self::assertSame([GrantOutcome::GRANTED, GrantOutcome::UNCHANGED, GrantOutcome::REACH_CHANGED, GrantOutcome::UNCHANGED], $outcomes);

        $row = DB::table('resource_policies')->sole();

        self::assertSame(['posts', '7', 'stub_tenant', 'tenant-a', 'admin'], [$row->resource_type, $row->resource_id, $row->tenant_type, $row->tenant_id, $row->application]);
        self::assertFalse((bool) $row->include_subtree);
        self::assertNotNull($row->created_at);
    }

    /**
     * The record and the type, the platform and a tenant, and every application
     * and one, are separate scopes.
     *
     * @return void
     */
    public function testEachScopeHoldsItsOwnAttachment(): void
    {
        $policy = self::policy();
        $tenant = new Reference('stub_tenant', 'tenant-a');

        $scopes = [
            ['7', GrantScope::platform()],
            [null, GrantScope::platform()],
            ['7', new GrantScope($tenant)],
            ['7', new GrantScope(null, 'admin')],
            [null, new GrantScope($tenant, 'admin')],
        ];

        foreach ($scopes as [$id, $scope]) {
            self::assertSame(GrantOutcome::GRANTED, self::table($id, $scope)->attach($policy));
        }

        self::assertSame(5, DB::table('resource_policies')->count());

        self::assertEquals(new GrantScope($tenant, 'admin'), self::table(null, new GrantScope($tenant, 'admin'))->detach($policy));
        self::assertNull(self::table(null, new GrantScope($tenant, 'admin'))->detach($policy));
        self::assertEquals(new GrantScope(null, 'admin'), self::table('7', new GrantScope(null, 'admin'))->detach($policy));
        self::assertEquals(GrantScope::platform(), self::table(null, GrantScope::platform())->detach($policy));
        self::assertSame(2, DB::table('resource_policies')->count());
    }

    /**
     * A detachment reports the reach the attachment had, and detaches only in
     * its scope.
     *
     * @return void
     */
    public function testDetachReportsTheReach(): void
    {
        $policy = self::policy();
        $tenant = new Reference('stub_tenant', 'tenant-a');

        self::table('7', new GrantScope($tenant, null, false))->attach($policy);

        self::assertNull(self::table('8', new GrantScope($tenant))->detach($policy));
        self::assertNull(self::table('7', GrantScope::platform())->detach($policy));
        self::assertEquals(new GrantScope($tenant, null, false), self::table('7', new GrantScope($tenant))->detach($policy));
        self::assertSame(0, DB::table('resource_policies')->count());
    }

    /**
     * The unique key folds nulls, so a second row for the same policy and
     * resource in the same scope is refused even when the resource id, tenant
     * and application are null.
     *
     * @return void
     */
    public function testTheUniqueKeyFoldsNulls(): void
    {
        $row = ['policy_id' => self::policy(), 'resource_type' => 'posts', 'resource_id' => null, 'tenant_type' => null, 'tenant_id' => null, 'application' => null];

        DB::table('resource_policies')->insert($row);

        $this->expectException(QueryException::class);

        DB::table('resource_policies')->insert($row);
    }

    /**
     * An attachment a concurrent call detached between the ignored insert and
     * the read back is attached afresh, once more, with the scope's reach.
     *
     * @return void
     */
    public function testAttachesAfreshARowDetachedConcurrently(): void
    {
        $policy = self::policy();
        $scope  = new GrantScope(null, null, false);

        self::table('7', GrantScope::platform())->attach($policy);

        $inserts = self::interleaveWrites('resource_policies', static function (): void {
            DB::table('resource_policies')->delete();
        }, static function (): void {});

        self::assertSame(GrantOutcome::GRANTED, self::table('7', $scope)->attach($policy));
        self::assertCount(2, $inserts);
        self::assertFalse((bool) DB::table('resource_policies')->sole()->include_subtree);
    }

    /**
     * An attachment that leaves no row, even once tried again, reports nothing
     * attached, as on MySQL a policy deleted at the same moment does when
     * `INSERT IGNORE` turns its foreign key failure into a warning.
     *
     * @return void
     */
    public function testReportsNothingWhenNoRowIsWritten(): void
    {
        $policy = self::policy();

        self::table('7', GrantScope::platform())->attach($policy);

        $row     = (array) DB::table('resource_policies')->sole();
        $inserts = self::interleaveWrites('resource_policies', static function (): void {
            DB::table('resource_policies')->delete();
        }, static function () use ($row): void {
            DB::table('resource_policies')->insert($row);
        }, 2, 1);

        self::assertNull(self::table('7', GrantScope::platform())->attach($policy));
        self::assertCount(2, $inserts);
        self::assertSame(0, DB::table('resource_policies')->count());
    }

    /**
     * Return the writer of the posts resource's attachments.
     *
     * @param  string|null  $id
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return \SineMacula\Laravel\Authorization\Services\Support\ResourcePolicyTable
     */
    private static function table(?string $id, GrantScope $scope): ResourcePolicyTable
    {
        return new ResourcePolicyTable(AuthorizationConnection::connection(), 'resource_policies', 'posts', $id, $scope);
    }

    /**
     * Create a policy and return its key.
     *
     * @return string
     */
    private static function policy(): string
    {
        return Policy::create(['name' => 'sharing', 'document' => ['statements' => []]])->id;
    }
}
