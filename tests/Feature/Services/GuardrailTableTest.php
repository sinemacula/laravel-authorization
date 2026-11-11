<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\Support\GuardrailTable;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\InterleavesWrites;
use Tests\TestCase;

/**
 * Feature tests for the writer of the guardrails of one scope, and the table's
 * null-folding unique key and foreign key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GuardrailTable::class)]
final class GuardrailTableTest extends TestCase
{
    use InterleavesWrites;

    /**
     * A guardrail is written once in its scope with its actor; setting it again
     * changes nothing.
     *
     * @return void
     */
    public function testSetsOnceInTheScope(): void
    {
        $policy = self::policy('cap');
        $tenant = new Reference('stub_tenant', 'tenant-a');

        self::assertSame(GrantOutcome::GRANTED, self::table($tenant, new Reference('admin', '1'))->set($policy));
        self::assertSame(GrantOutcome::UNCHANGED, self::table($tenant, new Reference('admin', '2'))->set($policy));

        $row = (array) DB::table('guardrails')->sole();

        self::assertSame([$policy, 'stub_tenant', 'tenant-a'], [(string) $row['policy_id'], $row['tenant_type'], $row['tenant_id']]);
        self::assertSame(['admin', '1'], [$row['granted_by_type'], $row['granted_by_id']]);
        self::assertNotNull($row['created_at']);
        self::assertNotNull($row['updated_at']);
    }

    /**
     * The platform's guardrails and each tenant's are apart, and a scope holds
     * any number of policies.
     *
     * @return void
     */
    public function testKeepsAPolicyOncePerScope(): void
    {
        [$first, $second] = [self::policy('first'), self::policy('second')];

        self::assertSame(GrantOutcome::GRANTED, self::table(null)->set($first));
        self::assertSame(GrantOutcome::GRANTED, self::table(null)->set($second));
        self::assertSame(GrantOutcome::GRANTED, self::table(new Reference('stub_tenant', 'tenant-a'))->set($first));
        self::assertSame(GrantOutcome::GRANTED, self::table(new Reference('stub_tenant', 'tenant-b'))->set($first));
        self::assertSame(GrantOutcome::UNCHANGED, self::table(null)->set($first));
        self::assertSame(4, DB::table('guardrails')->count());
        self::assertNull(DB::table('guardrails')->where('policy_id', $second)->value('granted_by_type'));
    }

    /**
     * A row a concurrent call removed between the ignored insert and the read
     * back is set afresh, once more.
     *
     * @return void
     */
    public function testSetsAfreshARowRemovedConcurrently(): void
    {
        $policy = self::policy('cap');

        self::table(null)->set($policy);

        $inserts = self::interleaveWrites('guardrails', static function (): void {
            DB::table('guardrails')->delete();
        }, static function (): void {});

        self::assertSame(GrantOutcome::GRANTED, self::table(null, new Reference('admin', '1'))->set($policy));
        self::assertCount(2, $inserts);
        self::assertSame('1', DB::table('guardrails')->value('granted_by_id'));
    }

    /**
     * A write that leaves no row, even once tried again, reports nothing set.
     *
     * @return void
     */
    public function testReportsNothingWhenNoRowIsWritten(): void
    {
        $policy = self::policy('cap');

        self::table(null)->set($policy);

        $row     = (array) DB::table('guardrails')->sole();
        $inserts = self::interleaveWrites('guardrails', static function (): void {
            DB::table('guardrails')->delete();
        }, static function () use ($row): void {
            DB::table('guardrails')->insert($row);
        }, 2, 1);

        self::assertNull(self::table(null)->set($policy));
        self::assertCount(2, $inserts);
        self::assertSame(0, DB::table('guardrails')->count());
    }

    /**
     * A removal removes only the scope's guardrail of the policy and reports
     * whether there was one.
     *
     * @return void
     */
    public function testRemovesOnlyTheScopesGuardrail(): void
    {
        [$first, $second] = [self::policy('first'), self::policy('second')];
        $tenant           = new Reference('stub_tenant', 'tenant-a');

        self::table($tenant)->set($first);
        self::table(null)->set($first);
        self::table(null)->set($second);

        self::assertFalse(self::table(new Reference('stub_tenant', 'tenant-b'))->remove($first));
        self::assertFalse(self::table(new Reference('other_tenant', 'tenant-a'))->remove($first));
        self::assertTrue(self::table($tenant)->remove($first));
        self::assertTrue(self::table(null)->remove($first));
        self::assertFalse(self::table(null)->remove($first));
        self::assertEquals([$second], DB::table('guardrails')->pluck('policy_id')->all());
    }

    /**
     * A guardrail naming half a tenant, a key without a type or a type without
     * a key, is not the platform's: setting the policy at the platform writes a
     * row beside it, and removing it there leaves it as it is.
     *
     * @return void
     */
    public function testAGuardrailNamingHalfATenantIsNotThePlatforms(): void
    {
        $policy = self::policy('cap');

        DB::table('guardrails')->insert([
            ['policy_id' => $policy, 'tenant_type' => null, 'tenant_id' => 'tenant-a'],
            ['policy_id' => $policy, 'tenant_type' => 'stub_tenant', 'tenant_id' => null],
        ]);

        self::assertFalse(self::table(null)->remove($policy));
        self::assertSame(GrantOutcome::GRANTED, self::table(null)->set($policy));
        self::assertTrue(self::table(null)->remove($policy));
        self::assertSame(2, DB::table('guardrails')->count());
    }

    /**
     * The policy's guardrail rows naming half a tenant are removed on their
     * own, as stored, each returned with its tenant columns; the platform's, a
     * tenant's and another policy's are left.
     *
     * @return void
     */
    public function testRemovesThePolicysRowsNamingHalfATenant(): void
    {
        $policy = self::policy('cap');
        $other  = self::policy('other');

        DB::table('guardrails')->insert([
            ['policy_id' => $policy, 'tenant_type' => null, 'tenant_id' => 'tenant-a'],
            ['policy_id' => $policy, 'tenant_type' => 'stub_tenant', 'tenant_id' => null],
            ['policy_id' => $policy, 'tenant_type' => null, 'tenant_id' => null],
            ['policy_id' => $policy, 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a'],
            ['policy_id' => $other, 'tenant_type' => null, 'tenant_id' => 'tenant-a'],
        ]);

        self::assertEqualsCanonicalizing(
            [['tenant_type' => null, 'tenant_id' => 'tenant-a'], ['tenant_type' => 'stub_tenant', 'tenant_id' => null]],
            self::table(new Reference('stub_tenant', 'tenant-b'))->removeMalformed($policy),
        );
        self::assertSame([], self::table(null)->removeMalformed($policy));
        self::assertSame(3, DB::table('guardrails')->count());
        self::assertSame(1, DB::table('guardrails')->where('policy_id', $other)->count());
    }

    /**
     * The unique key folds nulls, so the same policy is refused a second
     * platform-wide row even though its tenant columns are null.
     *
     * @return void
     */
    public function testTheUniqueKeyFoldsNulls(): void
    {
        $row = ['policy_id' => self::policy('cap'), 'tenant_type' => null, 'tenant_id' => null];

        DB::table('guardrails')->insert($row);

        $this->expectException(QueryException::class);

        DB::table('guardrails')->insert($row);
    }

    /**
     * The foreign key refuses to delete a policy in use as a guardrail from
     * under it, even past the model.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheForeignKeyKeepsAGuardrailsPolicy(): void
    {
        $policy = self::policy('cap');

        self::table(null)->set($policy);

        try {
            // Within a savepoint, so the refused statement leaves the test's
            // transaction usable on PostgreSQL.
            DB::transaction(static fn (): int => DB::table('policies')->where('id', $policy)->delete());
            self::fail('The policy was deleted from under its guardrail.');
        } catch (QueryException) {
            // Expected.
        }

        self::assertSame(1, DB::table('policies')->where('id', $policy)->count());
    }

    /**
     * Return the writer of the guardrails of the scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Services\Support\GuardrailTable
     */
    private static function table(?Reference $tenant, ?Reference $actor = null): GuardrailTable
    {
        return new GuardrailTable(AuthorizationConnection::connection(), 'guardrails', $tenant, $actor);
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
