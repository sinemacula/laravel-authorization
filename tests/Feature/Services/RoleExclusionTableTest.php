<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Exclusions\RoleExclusion;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\RoleExclusionTable;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\RecordsRowLocks;
use Tests\TestCase;

/**
 * Feature tests for `RoleExclusionTable`, which reads and writes the pairs of
 * mutually exclusive roles.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RoleExclusionTable::class)]
final class RoleExclusionTableTest extends TestCase
{
    use RecordsRowLocks;

    /**
     * Declaring a pair writes its row once, with its owner, who declared it and
     * when, in UTC; declaring it again changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeclaresAPairOnce(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        [$first, $second] = self::pair();

        $table = RoleExclusionTable::of(new Reference('admin', '1'));

        self::assertFalse($table->isDeclared($first, $second));
        self::assertSame(GrantOutcome::GRANTED, $table->declare($first, $second, new Reference('stub_tenant', 'a')));
        self::assertSame(GrantOutcome::UNCHANGED, $table->declare($first, $second, null));
        self::assertTrue($table->isDeclared($first, $second));
        self::assertFalse($table->isDeclared($second, $first));

        $row = (array) DB::table('role_exclusions')->sole();

        Carbon::setTestNow();

        self::assertSame(['stub_tenant', 'a', 'admin', '1'], [$row['tenant_type'], $row['tenant_id'], $row['granted_by_type'], $row['granted_by_id']]);
        self::assertSame('2026-07-01 12:00:00', $row['created_at']);
        self::assertSame('2026-07-01 12:00:00', $row['updated_at']);
    }

    /**
     * A pair whose row is ignored by the insert and gone by the read after it
     * is not reported declared at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPairNeitherWrittenNorFoundIsNotReported(): void
    {
        [$first, $second] = self::pair();

        DB::table('role_exclusions')->insert(['role_id' => $first, 'excluded_role_id' => $second]);

        DB::listen(static function (QueryExecuted $query): void {
            $sql = \strtolower($query->sql);

            if (!\str_starts_with($sql, 'insert') || (!\str_contains($sql, 'ignore') && !\str_contains($sql, 'on conflict'))) {
                return;
            }

            DB::table('role_exclusions')->delete();
        });

        self::assertNull(RoleExclusionTable::of()->declare($first, $second, null));
    }

    /**
     * A pair is found as stored, its roles of the type given, with its owner,
     * under a row lock; a pair not declared is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFindsAPairAsStored(): void
    {
        [$first, $second] = self::pair();

        $table = RoleExclusionTable::of();

        $table->declare($first, $second, new Reference('stub_tenant', 'a'));

        $locks = $this->recordRowLocks();
        $found = $table->find('role', $first, $second);

        self::assertSame([['role_exclusions', [$first, $second]]], $locks->getArrayCopy());

        self::assertNotNull($found);
        self::assertSame(['role', $first, 'role', $second], [$found->role->type, $found->role->id, $found->excludedRole->type, $found->excludedRole->id]);
        self::assertSame(['stub_tenant', 'a'], [$found->tenant?->type, $found->tenant?->id]);
        self::assertNull($table->find('role', $second, $first));
    }

    /**
     * Removing a pair reports whether it was declared, and leaves every other
     * pair as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesAPair(): void
    {
        [$first, $second] = self::pair();

        $third = Role::query()->create(['name' => 'third'])->id;
        $table = RoleExclusionTable::of();

        $table->declare($first, $second, null);
        $table->declare($first, $third, null);

        self::assertFalse($table->remove($second, $first));
        self::assertTrue($table->remove($first, $second));
        self::assertFalse($table->remove($first, $second));
        self::assertTrue($table->isDeclared($first, $third));
    }

    /**
     * Every pair is listed in key order, or those naming a role on either side,
     * each its roles of the type given, with its owner and who declared it,
     * null for none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListsThePairs(): void
    {
        $keys = [
            Role::query()->create(['name' => 'one'])->id,
            Role::query()->create(['name' => 'two'])->id,
            Role::query()->create(['name' => 'three'])->id,
        ];

        \sort($keys);

        [$low, $middle, $high] = $keys;

        $table = RoleExclusionTable::of(new Reference('admin', '1'));

        $table->declare($middle, $high, null);
        $table->declare($low, $high, new Reference('stub_tenant', 'a'));
        RoleExclusionTable::of()->declare($low, $middle, null);

        $pairs = $table->pairs('role');
        $names = static fn (array $listed): array => \array_map(static fn (RoleExclusion $pair): array => [$pair->role->id, $pair->excludedRole->id], $listed);

        self::assertSame([[$low, $middle], [$low, $high], [$middle, $high]], $names($pairs));
        self::assertSame([[$low, $middle], [$middle, $high]], $names($table->pairs('role', $middle)));
        self::assertSame('role', $pairs[0]->role->type);
        self::assertSame('role', $pairs[0]->excludedRole->type);
        self::assertNull($pairs[0]->tenant);
        self::assertNull($pairs[0]->grantedBy);
        self::assertEquals(new Reference('stub_tenant', 'a'), $pairs[1]->tenant);
        self::assertEquals(new Reference('admin', '1'), $pairs[1]->grantedBy);
        self::assertNotNull($pairs[1]->createdAt);
        self::assertSame('UTC', $pairs[1]->createdAt->getTimezone()->getName());

        DB::table('role_exclusions')->update(['created_at' => null, 'granted_by_type' => 'admin', 'granted_by_id' => null]);

        self::assertNull($table->pairs('role')[0]->createdAt);
        self::assertNull($table->pairs('role')[0]->grantedBy);
    }

    /**
     * The writer reads and writes the table the configuration names, on the
     * package's connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUsesTheConfiguredTable(): void
    {
        [$first, $second] = self::pair();

        $this->container()->make(ConfigRepository::class)->set('authorization.tables.role_exclusions', 'renamed_exclusions');

        $queries = DB::pretend(static fn (): bool => RoleExclusionTable::of()->remove($first, $second));

        self::assertCount(1, $queries);
        self::assertStringContainsString('renamed_exclusions', $queries[0]['query']);
    }

    /**
     * Return the keys of two new roles.
     *
     * @return array{0: string, 1: string}
     */
    private static function pair(): array
    {
        return [Role::query()->create(['name' => 'clerk'])->id, Role::query()->create(['name' => 'auditor'])->id];
    }
}
