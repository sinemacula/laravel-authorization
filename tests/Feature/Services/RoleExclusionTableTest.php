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
use Tests\Fixtures\LockModeRecordingGrammar;
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
     * The pairs touching roles are those naming one of them or, while the
     * hierarchy is enabled, a role above one, read under a shared lock in the
     * pairs' order; a pair naming only roles below or beside them is left out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListsThePairsTouchingRolesOrTheRolesAboveThem(): void
    {
        $top    = Role::query()->create(['name' => 'top']);
        $middle = Role::query()->create(['name' => 'middle', 'parent_id' => $top->id]);
        $bottom = Role::query()->create(['name' => 'bottom', 'parent_id' => $middle->id]);
        $aside  = Role::query()->create(['name' => 'aside']);
        $other  = Role::query()->create(['name' => 'other']);
        $table  = RoleExclusionTable::of();
        $pairs  = [[$top->id, $aside->id], [$bottom->id, $other->id], [$aside->id, $other->id], [$middle->id, $other->id]];

        foreach ($pairs as $pair) {
            \sort($pair);

            $table->declare($pair[0], $pair[1], null);
        }

        $named = static fn (array $listed): array => \array_map(static fn (RoleExclusion $pair): array => [$pair->role->id, $pair->excludedRole->id], $listed);
        $sort  = static function (array $pairs): array {
            $pairs = \array_map(static function (array $pair): array {
                \sort($pair);

                return $pair;
            }, $pairs);

            \sort($pairs);

            return $pairs;
        };

        self::assertSame($sort([[$top->id, $aside->id], [$middle->id, $other->id]]), $named($table->touching('role', [$middle->id])));
        self::assertSame('role', $table->touching('role', [$middle->id])[0]->role->type);
        self::assertSame(['role_exclusions', 'roles'], $this->lockedTables(static fn (): array => $table->touching('role', [$middle->id])));
        self::assertSame([], $table->touching('role', []));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame($sort([[$middle->id, $other->id]]), $named($table->touching('role', [$middle->id])));
        self::assertSame([], $table->touching('role', [Role::query()->create(['name' => 'idle'])->id]));
    }

    /**
     * The roles are walked up one level a query, the roles under a shared lock
     * and the first pair naming each, in key order, for update, past a role
     * with no parent beside them, and the pairs are read for update only when
     * the walk finds one; a stored cycle ends the walk.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWalksUpALevelAQueryAndReadsThePairsOnlyWhenOneIsFound(): void
    {
        $lone = (new Role)->forceFill(['id' => '00000000-0000-4000-8000-000000000001', 'name' => 'lone']);

        $lone->save();

        $top    = Role::query()->create(['name' => 'top']);
        $middle = Role::query()->create(['name' => 'middle', 'parent_id' => $top->id]);
        $bottom = Role::query()->create(['name' => 'bottom', 'parent_id' => $middle->id]);
        $table  = RoleExclusionTable::of();
        $walk   = static fn (): array => self::queriesOf(static fn (): array => $table->touching('role', [$bottom->id]));

        self::assertSame([[$bottom->id], [$middle->id], [$top->id]], \array_column($walk(), 1));

        $table->declare(...self::sorted($top->id, Role::query()->create(['name' => 'aside'])->id));

        $queries = $walk();

        self::assertCount(4, $queries);
        self::assertCount(1, $table->touching('role', [$lone->id, $bottom->id]));
        self::assertMatchesRegularExpression('/order by \S+\.\S+role_id\S* asc, \S+\.\S+excluded_role_id\S* asc limit 1/', $queries[0][0]);
        self::assertMatchesRegularExpression('/^select \* from [`"]role_exclusions[`"]/', $queries[3][0]);
        self::assertSame([[true, 'role_exclusions'], [false, 'roles'], [true, 'role_exclusions']], self::lockModesOf(static fn (): array => $table->touching('role', [$top->id])));

        DB::table('roles')->where('id', $top->id)->update(['parent_id' => $bottom->id]);

        self::assertCount(1, $table->touching('role', [$bottom->id]));
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
     * Return the queries the call ran, each its SQL and bindings.
     *
     * @param  \Closure(): mixed  $call
     * @return list<array{0: string, 1: list<mixed>}>
     */
    private static function queriesOf(\Closure $call): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $call();

        $queries = \array_map(static fn (array $query): array => [$query['query'], \array_values($query['bindings'])], DB::getQueryLog());

        DB::disableQueryLog();

        return $queries;
    }

    /**
     * Return each lock the call took, in order: whether it was for update, and
     * the table it locked, the one each lock clause's query reads from.
     *
     * @param  \Closure(): mixed  $call
     * @return list<array{0: bool, 1: string}>
     */
    private static function lockModesOf(\Closure $call): array
    {
        $connection = DB::connection();
        $locks      = new \ArrayObject;

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockModeRecordingGrammar($connection, $locks));
        } else {
            DB::listen(static function (QueryExecuted $query) use ($locks): void {
                \preg_match_all('/ (for update|for share|lock in share mode)/i', $query->sql, $clauses, \PREG_OFFSET_CAPTURE);

                foreach ($clauses[1] as [$clause, $offset]) {
                    \preg_match_all('/\bfrom\s+[`"]?(\w+)/i', \substr($query->sql, 0, $offset), $tables);

                    $locks->append([(string) \end($tables[1]), \strtolower($clause) === 'for update', []]);
                }
            });
        }

        try {
            $call();
        } finally {
            $connection->useDefaultQueryGrammar();
        }

        /** @var list<array{0: string, 1: bool, 2: list<mixed>}> $taken */
        $taken = $locks->getArrayCopy();

        return \array_map(static fn (array $lock): array => [$lock[1], $lock[0]], $taken);
    }

    /**
     * Return the two keys in the pair's order, the lower first.
     *
     * @param  string  $one
     * @param  string  $other
     * @return array{0: string, 1: string, 2: null}
     */
    private static function sorted(string $one, string $other): array
    {
        return \strcmp($one, $other) < 0 ? [$one, $other, null] : [$other, $one, null];
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
